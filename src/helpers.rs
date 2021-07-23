use cookie::Cookie;
use juniper::{graphql_value, FieldError};
use std::time::{SystemTime, UNIX_EPOCH};

pub const COOKIE_NAME: &str = "cookie";

const HASURA_JWT_LIFE: u64 = 7000;

pub async fn hasura_request<T: serde::Serialize, D: serde::de::DeserializeOwned>(
    context: &crate::types::Context,
    body: T,
) -> Result<D, juniper::FieldError> {
    let res = context
        .config
        .client
        .post(&context.config.hasura_endpoint)
        .header(
            "x-hasura-admin-secret",
            context.config.hasura_admin_secret.as_bytes(),
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

pub fn authenticate(
    context: &crate::types::Context,
    user_id: &crate::graphql::uuid,
) -> Result<crate::types::Auth, juniper::FieldError> {
    let claims = crate::types::HasuraJwt {
        exp: seconds_from_now(HASURA_JWT_LIFE),
        sub: *user_id,
        hasura: crate::types::HasuraClaims {
            role: "user".to_string(),
            allowed_roles: vec!["user".to_string()],
            user_id: *user_id,
        },
    };

    jsonwebtoken::encode(
        &context.config.jwt_header,
        &claims,
        &context.config.jwt_enc_key,
    )
    .map_err(|_| field_error("JWT problem"))
    .map(|token| crate::types::Auth {
        id: *user_id,
        token,
    })
}

pub fn field_error(msg: &str) -> juniper::FieldError {
    FieldError::new(msg, graphql_value!({ "code": 123 }))
}

pub fn new_cookie(id: &crate::graphql::uuid) -> String {
    Cookie::build(COOKIE_NAME, id.to_string())
        .secure(true)
        .http_only(true)
        .max_age(time::Duration::days(7))
        .finish()
        .to_string()
}

pub fn remove_cookie() -> String {
    Cookie::build(COOKIE_NAME, "foo")
        .max_age(time::Duration::seconds(0))
        .expires(time::OffsetDateTime::unix_epoch())
        .finish()
        .to_string()
}

pub fn seconds_from_now(n: u64) -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("time error")
        .as_secs();

    since_the_epoch + n
}

pub fn parse_cookie(cookie: &str) -> Option<crate::graphql::uuid> {
    let cookie = Cookie::parse(cookie).ok()?;
    serde_json::from_str(&cookie.value()).ok()
}
