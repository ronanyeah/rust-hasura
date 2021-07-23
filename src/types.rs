use async_std::sync::Mutex;
use std::sync::Arc;

#[derive(serde::Deserialize)]
pub struct Env {
    pub port: u16,
    pub hasura_endpoint: String,
    pub admin_secret: String,
    pub jwt_secret: String,
}

#[derive(Clone)]
pub struct Config {
    pub hasura_endpoint: String,
    pub hasura_admin_secret: String,
    pub jwt_enc_key: jsonwebtoken::EncodingKey,
    pub jwt_dec_key: jsonwebtoken::DecodingKey<'static>,
    pub jwt_header: jsonwebtoken::Header,
    pub client: reqwest::Client,
}

#[derive(Clone)]
pub struct Context {
    pub cookie_user_id: Option<crate::graphql::uuid>,
    pub cookie_out: Arc<Mutex<CookieChange>>,
    pub config: Config,
}

pub enum CookieChange {
    NoChange,
    Add(crate::graphql::uuid),
    Remove,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct CookieJwt {
    pub sub: crate::graphql::uuid,
    pub exp: u64,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct HasuraJwt {
    pub exp: u64,
    pub sub: crate::graphql::uuid,
    #[serde(rename = "https://hasura.io/jwt/claims")]
    pub hasura: HasuraClaims,
}

#[derive(juniper::GraphQLObject)]
pub struct Auth {
    pub token: String,
    pub id: crate::graphql::uuid,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct HasuraClaims {
    #[serde(rename = "x-hasura-default-role")]
    pub role: String,
    #[serde(rename = "x-hasura-allowed-roles")]
    pub allowed_roles: Vec<String>,
    #[serde(rename = "x-hasura-user-id")]
    pub user_id: crate::graphql::uuid,
}

#[derive(serde::Deserialize)]
pub struct JwtSecret {
    #[serde(rename = "type")]
    pub type_: jsonwebtoken::Algorithm,
    pub key: String,
}
