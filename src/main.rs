use actix_web::{web, App, Error, HttpResponse, HttpServer};
use futures::future::TryFutureExt;
use graphql_client::{GraphQLQuery, Response};
use juniper::http::GraphQLRequest;
use juniper::RootNode;
use juniper::{graphql_value, FieldError, FieldResult};
use std::str::FromStr;
use std::sync::Arc;

const BCRYPT_COST: u32 = 10;

#[derive(GraphQLQuery)]
#[graphql(schema_path = "schema.json", query_path = "user-read.graphql")]
pub struct UserRead;

#[derive(GraphQLQuery)]
#[graphql(schema_path = "schema.json", query_path = "user-create.graphql")]
pub struct UserCreate;

#[allow(non_camel_case_types)]
#[derive(serde::Deserialize, serde::Serialize, Clone, PartialEq)]
pub struct uuid(uuid_foo::Uuid);

pub type Schema = RootNode<'static, Query, Mutation>;

juniper::graphql_scalar!(uuid where Scalar = <S> {
    resolve(&self) -> juniper::Value {
        juniper::Value::scalar(self.0.to_string())
    }

    from_input_value(v: &InputValue) -> Option<uuid> {
        v.as_scalar_value::<String>()
            .and_then(|str| uuid_foo::Uuid::parse_str(str).ok())
            .map(uuid)
    }

    from_str<'a>(value: ScalarToken<'a>) -> juniper::ParseScalarResult<'a, S> {
        <String as juniper::ParseScalarValue<S>>::from_str(value)
    }
});

#[derive(juniper::GraphQLObject)]
struct Auth {
    token: String,
    id: uuid,
}

#[derive(Clone)]
pub struct Context {
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
pub struct JwtSecret {
    #[serde(rename = "type")]
    type_: String,
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

pub struct Mutation;

pub struct Query;

fn post<T: serde::ser::Serialize>(
    context: &Context,
    body: T,
) -> reqwest::Result<reqwest::Response> {
    context
        .client
        .post(&context.hasura_endpoint)
        .header(
            "x-hasura-admin-secret",
            context.hasura_admin_secret.as_bytes(),
        )
        .json(&body)
        .send()
}

fn make_jwt(context: &Context, user_id: &uuid) -> jsonwebtoken::errors::Result<String> {
    let claims = Claims {
        sub: user_id.0.to_string(),
        hasura: HasuraClaims {
            role: "user".to_string(),
            allowed_roles: vec!["user".to_string()],
            user_id: user_id.to_owned(),
        },
    };

    jsonwebtoken::encode(&context.jwt_header, &claims, &context.jwt_key)
}

#[juniper::object(Context = Context)]
impl Mutation {
    fn login(context: &Context, email: String, password: String) -> FieldResult<Auth> {
        let variables = user_read::Variables { email };
        let request_body = UserRead::build_query(variables);

        let mut res = post(&context, &request_body).expect("http failure");

        let response_body: Response<user_read::ResponseData> =
            res.json().expect("json decode failure");

        let data = &response_body.data.expect("missing data");

        data.user.get(0).map_or(
            Err(FieldError::new(
                "Email not in use.",
                graphql_value!({ "code": "user-not-found" }),
            )),
            |user| {
                if bcrypt::verify(&password, &user.password).expect("bcrypt failure") {
                    Ok(Auth {
                        id: uuid(user.id.0),
                        token: make_jwt(&context, &user.id).expect("jwt create failure"),
                    })
                } else {
                    Err(FieldError::new(
                        "Incorrect password.",
                        graphql_value!({ "code": "incorrect-password" }),
                    ))
                }
            },
        )
    }
    fn signup(context: &Context, email: String, password: String) -> FieldResult<Auth> {
        let variables = user_create::Variables {
            email,
            password: bcrypt::hash(password, BCRYPT_COST).expect("bcrypt failure"),
        };
        let request_body = UserCreate::build_query(variables);

        let mut res = post(&context, &request_body).expect("http failure");

        let response_body: Response<user_create::ResponseData> =
            res.json().expect("json decode failure");

        let users = response_body
            .data
            .and_then(|data| data.insert_user.map(|insert_user| insert_user.returning));

        users.as_ref().and_then(|xs| xs.get(0)).map_or(
            Err(FieldError::new(
                "Could not create user.",
                juniper::Value::null(),
            )),
            |user| {
                Ok(Auth {
                    id: uuid(user.id.0),
                    token: make_jwt(&context, &user.id).expect("token creation failure"),
                })
            },
        )
    }
}

#[juniper::object(Context = Context)]
impl Query {
    // The  GraphQL spec requires a Query field to be defined.
    fn echo(txt: String) -> FieldResult<String> {
        Ok(txt)
    }
}

async fn graphql(
    st: web::Data<Arc<Schema>>,
    ctx: web::Data<Context>,
    data: web::Json<GraphQLRequest>,
) -> Result<HttpResponse, Error> {
    let res = web::block(move || {
        let res = data.execute(&st, &ctx);
        Ok::<_, serde_json::error::Error>(serde_json::to_string(&res)?)
    })
    .map_err(Error::from)
    .await?;

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(res))
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    let config = envy::from_env::<Config>().expect("missing environment variables");

    let jwt: JwtSecret = serde_json::from_str(&config.jwt_secret).expect("JWT_SECRET is invalid!");

    let algo: jsonwebtoken::Algorithm =
        jsonwebtoken::Algorithm::from_str(&jwt.type_).expect("Invalid JWT algorithm!");

    let jwt_header = jsonwebtoken::Header::new(algo);

    let context = Context {
        hasura_endpoint: config.hasura_endpoint,
        hasura_admin_secret: config.admin_secret,
        jwt_key: jsonwebtoken::EncodingKey::from_secret(&jwt.key.as_bytes()),
        jwt_header,
        client: reqwest::Client::new(),
    };

    let sch = Schema::new(Query {}, Mutation {});
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
