use actix_http::cookie::Cookie;
use actix_web::{web, App, HttpMessage, HttpRequest, HttpResponse, HttpServer};
use async_std::sync::Mutex;
use graphql_client::GraphQLQuery;
use juniper::http::GraphQLRequest;
use juniper::RootNode;
use juniper::{graphql_value, FieldError, FieldResult};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const COOKIE_LIFE: u64 = 7_000_000;
const COOKIE_NAME: &str = "refresh_cookie";

const HASURA_JWT_LIFE: u64 = 7000;

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    let env = envy::from_env::<Env>().expect("Missing environment variables!");

    let jwt: JwtSecret = serde_json::from_str(&env.jwt_secret).expect("JWT_SECRET is invalid!");

    let jwt_header = jsonwebtoken::Header::new(jwt.type_);

    let config = Config {
        hasura_endpoint: env.hasura_endpoint,
        hasura_admin_secret: env.admin_secret,
        jwt_enc_key: jsonwebtoken::EncodingKey::from_secret(&jwt.key.as_bytes()),
        jwt_dec_key: jsonwebtoken::DecodingKey::from_secret(&jwt.key.as_bytes()).into_static(),
        jwt_header,
        client: reqwest::Client::new(),
    };

    let schema_ = Schema::new(Query {}, Mutation {}, juniper::EmptySubscription::new());
    let schema = std::sync::Arc::new(schema_);

    HttpServer::new(move || {
        App::new()
            .app_data(config.clone())
            .data(schema.clone())
            .route("/graphql", web::post().to(graphql_handler))
    })
    .bind(("0.0.0.0", env.port))?
    .run()
    .await
}

async fn graphql_handler(
    schema: web::Data<Arc<Schema>>,
    req: HttpRequest,
    gql_req: web::Json<GraphQLRequest>,
) -> actix_web::Result<HttpResponse> {
    let config = req.app_data::<Config>().expect("config fail").to_owned();

    let maybe_cookie = req.cookie(COOKIE_NAME);

    let user_id = if let Some(cookie) = &maybe_cookie {
        handle_cookie(&config, cookie).await.ok()
    } else {
        None
    };

    let context = Context {
        hasura_endpoint: config.hasura_endpoint,
        hasura_admin_secret: config.hasura_admin_secret,
        jwt_enc_key: config.jwt_enc_key,
        jwt_dec_key: config.jwt_dec_key,
        jwt_header: config.jwt_header,
        client: config.client,
        cookie_user_id: user_id,
        cookie_out: Arc::new(Mutex::new(CookieChange::NoChange)),
    };

    let res = gql_req.execute(&schema, &context).await;

    match serde_json::to_string(&res) {
        Err(e) => Err(actix_web::Error::from(e)),
        Ok(out) => {
            let arc = context.cookie_out.clone();

            let cookie_change = arc.lock().await;

            match &*cookie_change {
                CookieChange::Add(id) => {
                    let cookie = make_cookie(id, &context.jwt_header, &context.jwt_enc_key);

                    Ok(HttpResponse::Ok()
                        .cookie(cookie)
                        .content_type("application/json")
                        .body(out))
                }
                CookieChange::NoChange => Ok(HttpResponse::Ok()
                    .content_type("application/json")
                    .body(out)),
                CookieChange::Remove => match maybe_cookie {
                    None => Ok(HttpResponse::Ok()
                        .content_type("application/json")
                        .body(out)),
                    Some(ck) => Ok(HttpResponse::Ok()
                        .del_cookie(&ck)
                        .content_type("application/json")
                        .body(out)),
                },
            }
        }
    }
}

//// Juniper GraphQL Resolvers ////

struct Query;

#[juniper::graphql_object(Context = Context)]
impl Query {
    async fn login(context: &Context, username: String) -> FieldResult<Auth> {
        let variables = user_by_username::Variables { username };
        let request_body = UserByUsername::build_query(variables);

        let res: user_by_username::ResponseData = post(&context, &request_body).await?;

        match res.user.get(0) {
            None => Err(field_error("Name not in use")),
            Some(user) => {
                let arc = context.cookie_out.clone();
                *arc.lock().await = CookieChange::Add(user.id.to_owned());
                authenticate(&context, &user.id)
            }
        }
    }
    async fn refresh(context: &Context) -> FieldResult<Option<Auth>> {
        match context.cookie_user_id {
            Some(id) => authenticate(&context, &id).map(Some),
            None => Ok(None),
        }
    }
}

struct Mutation;

#[juniper::graphql_object(Context = Context)]
impl Mutation {
    async fn signup(context: &Context, username: String) -> FieldResult<Auth> {
        let variables = user_create::Variables { username };
        let request_body = UserCreate::build_query(variables);

        let res: user_create::ResponseData = post(&context, &request_body).await?;

        match res.insert_user_one {
            None => Err(field_error("Failed to create user")),
            Some(user) => {
                let arc = context.cookie_out.clone();
                *arc.lock().await = CookieChange::Add(user.id.to_owned());
                authenticate(&context, &user.id)
            }
        }
    }
    async fn logout(context: &Context) -> FieldResult<bool> {
        let arc = context.cookie_out.clone();
        *arc.lock().await = CookieChange::Remove;
        Ok(true)
    }
}

//// graphql_client codegen ////

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "schema.json",
    query_path = "graphql/user-by-username.graphql"
)]
struct UserByUsername;

#[derive(GraphQLQuery)]
#[graphql(schema_path = "schema.json", query_path = "graphql/user-by-id.graphql")]
struct UserById;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "schema.json",
    query_path = "graphql/user-create.graphql"
)]
struct UserCreate;

//// Types ////

type Schema = RootNode<'static, Query, Mutation, juniper::EmptySubscription<Context>>;

// Required in order for graphql_client
// to utilise Hasura introspection.
#[allow(non_camel_case_types)]
type uuid = uuid_foo::Uuid;

enum CookieChange {
    NoChange,
    Add(uuid),
    Remove,
}

#[derive(serde::Deserialize)]
struct Env {
    port: u16,
    hasura_endpoint: String,
    admin_secret: String,
    jwt_secret: String,
}

#[derive(Clone)]
struct Config {
    hasura_endpoint: String,
    hasura_admin_secret: String,
    jwt_enc_key: jsonwebtoken::EncodingKey,
    jwt_dec_key: jsonwebtoken::DecodingKey<'static>,
    jwt_header: jsonwebtoken::Header,
    client: reqwest::Client,
}

#[derive(Clone)]
struct Context {
    hasura_endpoint: String,
    hasura_admin_secret: String,
    jwt_enc_key: jsonwebtoken::EncodingKey,
    jwt_dec_key: jsonwebtoken::DecodingKey<'static>,
    jwt_header: jsonwebtoken::Header,
    client: reqwest::Client,
    cookie_user_id: Option<uuid>,
    cookie_out: Arc<Mutex<CookieChange>>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct CookieJwt {
    sub: uuid,
    exp: u64,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct HasuraJwt {
    exp: u64,
    sub: uuid,
    #[serde(rename = "https://hasura.io/jwt/claims")]
    hasura: HasuraClaims,
}

#[derive(juniper::GraphQLObject)]
struct Auth {
    token: String,
    id: uuid,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct HasuraClaims {
    #[serde(rename = "x-hasura-default-role")]
    role: String,
    #[serde(rename = "x-hasura-allowed-roles")]
    allowed_roles: Vec<String>,
    #[serde(rename = "x-hasura-user-id")]
    user_id: uuid,
}

#[derive(serde::Deserialize)]
struct JwtSecret {
    #[serde(rename = "type")]
    type_: jsonwebtoken::Algorithm,
    key: String,
}

//// Helpers ////

async fn post<T: serde::Serialize, D: serde::de::DeserializeOwned>(
    context: &Context,
    body: T,
) -> Result<D, juniper::FieldError> {
    let res = context
        .client
        .post(&context.hasura_endpoint)
        .header(
            "x-hasura-admin-secret",
            context.hasura_admin_secret.as_bytes(),
        )
        .json(&body)
        .send()
        .await;

    match res {
        Err(_) => Err(field_error("Request failure")),
        Ok(data) => {
            let decode: Result<graphql_client::Response<D>, reqwest::Error> = data.json().await;

            decode
                .map_err(|_| field_error("JSON decode failure"))
                .and_then(|gql| {
                    gql.data
                        .ok_or_else(|| field_error("Empty data was returned"))
                })
        }
    }
}

fn authenticate(context: &Context, user_id: &uuid) -> Result<Auth, juniper::FieldError> {
    let claims = HasuraJwt {
        exp: seconds_from_now(HASURA_JWT_LIFE),
        sub: *user_id,
        hasura: HasuraClaims {
            role: "user".to_string(),
            allowed_roles: vec!["user".to_string()],
            user_id: user_id.to_owned(),
        },
    };

    jsonwebtoken::encode(&context.jwt_header, &claims, &context.jwt_enc_key)
        .map_err(|_| field_error("JWT problem"))
        .map(|token| Auth {
            id: user_id.to_owned(),
            token,
        })
}

fn field_error(msg: &str) -> juniper::FieldError {
    FieldError::new(msg, graphql_value!({ "code": 123 }))
}

fn make_cookie(
    id: &uuid,
    jwt_header: &jsonwebtoken::Header,
    jwt_enc_key: &jsonwebtoken::EncodingKey,
) -> Cookie<'static> {
    let claims = CookieJwt {
        exp: seconds_from_now(COOKIE_LIFE),
        sub: *id,
    };

    let jwt = jsonwebtoken::encode(jwt_header, &claims, jwt_enc_key).expect("bad token");

    Cookie::build(COOKIE_NAME, jwt)
        .http_only(true)
        .permanent()
        .finish()
}

fn seconds_from_now(n: u64) -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("time error")
        .as_secs();

    since_the_epoch + n
}

async fn handle_cookie(config: &Config, cookie: &Cookie<'static>) -> Result<uuid, String> {
    let cookie_decode = jsonwebtoken::decode::<CookieJwt>(
        cookie.value(),
        &config.jwt_dec_key,
        &jsonwebtoken::Validation::default(),
    );

    if let Ok(ck) = cookie_decode {
        let variables = user_by_id::Variables { id: ck.claims.sub };
        let request_body = UserById::build_query(variables);

        let user = config
            .client
            .post(&config.hasura_endpoint)
            .header(
                "x-hasura-admin-secret",
                config.hasura_admin_secret.as_bytes(),
            )
            .json(&request_body)
            .send()
            .await
            .map_err(|_| "User fetch failure")?
            .json::<graphql_client::Response<user_by_id::ResponseData>>()
            .await
            .map_err(|_| "User decode failure")?
            .data
            .ok_or("Data not returned")?
            .user_by_pk
            .ok_or("User not found")?;

        Ok(user.id)
    } else {
        Err("Bad Cookie".to_owned())
    }
}
