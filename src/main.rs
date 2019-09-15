use graphql_client::{GraphQLQuery, Response};
use iron_cors::CorsMiddleware;
use juniper::{graphql_value, FieldError, FieldResult};
use juniper_iron::GraphQLHandler;
use mount::Mount;
use std::str::FromStr;

const BCRYPT_COST: u32 = 10;

#[derive(GraphQLQuery)]
#[graphql(schema_path = "schema.json", query_path = "query.graphql")]
pub struct UserGet;

#[derive(GraphQLQuery)]
#[graphql(schema_path = "schema.json", query_path = "query.graphql")]
pub struct UserCreate;

#[allow(non_camel_case_types)]
#[derive(serde::Deserialize, serde::Serialize, Clone, PartialEq)]
pub struct uuid(uuid_foo::Uuid);

juniper::graphql_scalar!(uuid where Scalar = <S> {
    resolve(&self) -> juniper::Value {
        juniper::Value::scalar(self.0.to_string().clone())
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
    jwt_key: String,
    jwt_header: jsonwebtoken::Header,
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

fn post<T: serde::ser::Serialize>(context: &Context, body: T) -> reqwest::Response {
    let client = reqwest::Client::new();
    client
        .post(&context.hasura_endpoint)
        .header(
            "x-hasura-admin-secret",
            context.hasura_admin_secret.as_bytes(),
        )
        .json(&body)
        .send()
        .unwrap()
}

fn make_jwt(context: &Context, user_id: &uuid) -> jsonwebtoken::errors::Result<String> {
    let claims = Claims {
        sub: user_id.0.to_string().to_owned(),
        hasura: HasuraClaims {
            role: "user".to_string(),
            allowed_roles: vec!["user".to_string()],
            user_id: user_id.to_owned(),
        },
    };

    jsonwebtoken::encode(&context.jwt_header, &claims, &context.jwt_key.as_ref())
}

#[juniper::object(Context = Context)]
impl Mutation {
    fn login(context: &Context, email: String, password: String) -> FieldResult<Auth> {
        let variables = user_get::Variables { email };
        let request_body = UserGet::build_query(variables);

        let mut res = post(&context, &request_body);

        let response_body: Response<user_get::ResponseData> = res.json().unwrap();

        let data = &response_body.data.unwrap();

        data.user.get(0).map_or(
            Err(FieldError::new(
                "Email not in use.",
                graphql_value!({ "code": "user-not-found" }),
            )),
            |user| {
                if bcrypt::verify(&password, &user.password).unwrap() {
                    Ok(Auth {
                        id: uuid(user.id.0),
                        token: make_jwt(&context, &user.id).unwrap(),
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
            password: bcrypt::hash(password, BCRYPT_COST).unwrap(),
        };
        let request_body = UserCreate::build_query(variables);

        let mut res = post(&context, &request_body);

        let response_body: Response<user_create::ResponseData> = res.json().unwrap();

        let err = response_body
            .errors
            .as_ref()
            .and_then(|errs| errs.get(0))
            .map_or(
                FieldError::new("Could not create user.", juniper::Value::null()),
                |e| {
                    let val = e
                        .extensions
                        .as_ref()
                        .and_then(|es| es.get("code"))
                        .and_then(serde_json::value::Value::as_str)
                        .map_or(juniper::Value::null(), |c| graphql_value!({ "code": c }));
                    FieldError::new(&e.message, val)
                },
            );

        let users = response_body
            .data
            .and_then(|data| data.insert_user.map(|insert_user| insert_user.returning));

        users
            .as_ref()
            .and_then(|xs| xs.get(0))
            .map_or(Err(err), |user| {
                Ok(Auth {
                    id: uuid(user.id.0),
                    token: make_jwt(&context, &user.id).unwrap(),
                })
            })
    }
}

#[juniper::object(Context = Context)]
impl Query {
    fn echo(txt: String) -> FieldResult<String> {
        Ok(txt)
    }
}

fn main() {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap();

    let hasura_endpoint = std::env::var("HASURA_ENDPOINT").unwrap();
    let hasura_admin_secret = std::env::var("ADMIN_SECRET").unwrap();

    let jwt_str = std::env::var("JWT_SECRET").unwrap();
    let jwt: JwtSecret = serde_json::from_str(&jwt_str).unwrap();

    let algo: jsonwebtoken::Algorithm = jsonwebtoken::Algorithm::from_str(&jwt.type_).unwrap();

    let jwt_header = jsonwebtoken::Header::new(algo);

    let context = Context {
        hasura_endpoint,
        hasura_admin_secret,
        jwt_key: jwt.key,
        jwt_header,
    };

    let graphql_endpoint = GraphQLHandler::new(move |_| Ok(context.clone()), Query, Mutation);

    let mut mount = Mount::new();

    mount.mount("/graphql", graphql_endpoint);

    let mut chain = iron::Chain::new(mount);

    let cors_middleware = CorsMiddleware::with_allow_any();

    chain.link_around(cors_middleware);

    println!("Server listening on port {}!", port);

    iron::Iron::new(chain).http(("0.0.0.0", port)).unwrap();
}
