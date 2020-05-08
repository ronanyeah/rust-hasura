use actix_web::{web, App, Error, HttpResponse, HttpServer};
use graphql_client::GraphQLQuery;
use juniper::http::GraphQLRequest;
use juniper::RootNode;
use juniper::{graphql_value, FieldError, FieldResult};
use std::sync::Arc;

const BCRYPT_COST: u32 = 10;

#[derive(GraphQLQuery)]
#[graphql(schema_path = "schema.json", query_path = "user-read.graphql")]
struct UserRead;

#[derive(GraphQLQuery)]
#[graphql(schema_path = "schema.json", query_path = "user-create.graphql")]
struct UserCreate;

#[allow(non_camel_case_types)]
#[derive(serde::Deserialize, serde::Serialize, Clone, PartialEq, Copy)]
pub struct uuid(uuid_foo::Uuid);

type Schema = RootNode<'static, Query, Mutation, juniper::EmptySubscription<Context>>;

#[juniper::graphql_scalar(description = "uuid")]
impl<S> GraphQLScalar for uuid
where
    S: ScalarValue,
{
    fn resolve(&self) -> juniper::Value {
        juniper::Value::scalar(self.0.to_string())
    }

    fn from_input_value(v: &InputValue) -> Option<uuid> {
        v.as_scalar_value()
            .and_then(|t| t.as_str())
            .and_then(|str| uuid_foo::Uuid::parse_str(str).ok())
            .map(uuid)
    }

    fn from_str<'a>(value: ScalarToken<'a>) -> juniper::ParseScalarResult<'a, S> {
        <String as juniper::ParseScalarValue<S>>::from_str(value)
    }
}

#[derive(juniper::GraphQLObject)]
struct Auth {
    token: String,
    id: uuid,
}

#[derive(Clone)]
struct Context {
    hasura_endpoint: String,
    hasura_admin_secret: String,
    jwt_key: jsonwebtoken::EncodingKey,
    jwt_header: jsonwebtoken::Header,
    client: reqwest::Client,
}

#[derive(serde::Deserialize)]
struct Config {
    port: u16,
    hasura_endpoint: String,
    admin_secret: String,
    jwt_secret: String,
}

#[derive(serde::Deserialize)]
struct JwtSecret {
    #[serde(rename = "type")]
    type_: jsonwebtoken::Algorithm,
    key: String,
}

#[derive(serde::Deserialize, serde::Serialize, Clone)]
struct Claims {
    sub: String,
    #[serde(rename = "https://hasura.io/jwt/claims")]
    hasura: HasuraClaims,
}

#[derive(serde::Deserialize, serde::Serialize, Clone)]
struct HasuraClaims {
    #[serde(rename = "x-hasura-default-role")]
    role: String,
    #[serde(rename = "x-hasura-allowed-roles")]
    allowed_roles: Vec<String>,
    #[serde(rename = "x-hasura-user-id")]
    user_id: uuid,
}

struct Mutation;

struct Query;

fn make_jwt(context: &Context, user_id: &uuid) -> Result<String, juniper::FieldError> {
    let claims = Claims {
        sub: user_id.0.to_string(),
        hasura: HasuraClaims {
            role: "user".to_string(),
            allowed_roles: vec!["user".to_string()],
            user_id: user_id.to_owned(),
        },
    };

    jsonwebtoken::encode(&context.jwt_header, &claims, &context.jwt_key)
        .map_err(|_| field_error("JWT problem"))
}

fn field_error(msg: &str) -> juniper::FieldError {
    FieldError::new(msg, graphql_value!({ "code": 123 }))
}

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

#[juniper::graphql_object(Context = Context)]
impl Mutation {
    async fn signup(context: &Context, email: String, password: String) -> FieldResult<Auth> {
        match bcrypt::hash(password, BCRYPT_COST) {
            Err(_) => Err(field_error("Bcrypt problem")),
            Ok(password) => {
                let variables = user_create::Variables { email, password };
                let request_body = UserCreate::build_query(variables);

                let res: Result<user_create::ResponseData, juniper::FieldError> =
                    post(&context, &request_body).await;

                res.and_then(|data| {
                    data.insert_user
                        .as_ref()
                        .and_then(|xs| xs.returning.get(0))
                        .map_or(Err(field_error("Failed to create user")), |user| {
                            make_jwt(&context, &user.id).map(|token| Auth { id: user.id, token })
                        })
                })
            }
        }
    }
}

#[juniper::graphql_object(Context = Context)]
impl Query {
    async fn login(context: &Context, email: String, password: String) -> FieldResult<Auth> {
        let variables = user_read::Variables { email };
        let request_body = UserRead::build_query(variables);

        let res: Result<user_read::ResponseData, juniper::FieldError> =
            post(&context, &request_body).await;

        res.and_then(|data| {
            data.user
                .get(0)
                .map_or(
                    Err(field_error("Email not in use")),
                    |user| match bcrypt::verify(&password, &user.password) {
                        Err(_) => Err(field_error("Bcrypt problem")),
                        Ok(correct) => {
                            if correct {
                                make_jwt(&context, &user.id)
                                    .map(|token| Auth { id: user.id, token })
                            } else {
                                Err(field_error("Incorrect password"))
                            }
                        }
                    },
                )
        })
    }
}

async fn graphql(
    st: web::Data<Arc<Schema>>,
    ctx: web::Data<Context>,
    data: web::Json<GraphQLRequest>,
) -> Result<HttpResponse, Error> {
    let res = data.execute(&st, &ctx).await;

    let out = serde_json::to_string(&res).map_err(Error::from)?;

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(out))
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    let config = envy::from_env::<Config>().expect("missing environment variables");

    let jwt: JwtSecret = serde_json::from_str(&config.jwt_secret).expect("JWT_SECRET is invalid!");

    let jwt_header = jsonwebtoken::Header::new(jwt.type_);

    let context = Context {
        hasura_endpoint: config.hasura_endpoint,
        hasura_admin_secret: config.admin_secret,
        jwt_key: jsonwebtoken::EncodingKey::from_secret(&jwt.key.as_bytes()),
        jwt_header,
        client: reqwest::Client::new(),
    };

    let sch = Schema::new(Query {}, Mutation {}, juniper::EmptySubscription::new());
    let schema = std::sync::Arc::new(sch);
    HttpServer::new(move || {
        App::new()
            .data(context.clone())
            .data(schema.clone())
            .route("/graphql", web::post().to(graphql))
    })
    .bind(format!("{}{}", "0.0.0.0:", &config.port.to_string()))?
    .run()
    .await
}
