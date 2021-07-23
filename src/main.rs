use async_std::sync::Mutex;
use graphql_client::GraphQLQuery;
use juniper::http::GraphQLRequest;
use juniper::FieldResult;
use std::convert::Infallible;
use std::sync::Arc;
use warp::Filter;
use warp::Reply;
mod graphql;
mod helpers;
mod types;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let env = envy::from_env::<types::Env>().expect("Missing environment variables!");

    let jwt: types::JwtSecret =
        serde_json::from_str(&env.jwt_secret).expect("JWT_SECRET is invalid!");

    let jwt_header = jsonwebtoken::Header::new(jwt.type_);

    let client = reqwest::Client::new();

    let config = types::Config {
        hasura_endpoint: env.hasura_endpoint,
        hasura_admin_secret: env.admin_secret,
        jwt_enc_key: jsonwebtoken::EncodingKey::from_secret(&jwt.key.as_bytes()),
        jwt_dec_key: jsonwebtoken::DecodingKey::from_secret(&jwt.key.as_bytes()).into_static(),
        jwt_header,
        client: client.clone(),
    };

    let schema = graphql::Schema::new(
        graphql::Query {},
        graphql::Mutation {},
        juniper::EmptySubscription::new(),
    );
    let schema_arc = std::sync::Arc::new(schema);

    let ping_route = warp::get().and(warp::path("ping")).map(ping);

    let gql = warp::post()
        .and(warp::path("graphql"))
        .and(with_config(config))
        .and(with_schema(schema_arc))
        .and(warp::filters::cookie::optional(helpers::COOKIE_NAME))
        .and(warp::body::json())
        .and_then(graphql_handler);

    let routes = ping_route.or(gql);

    warp::serve(routes).run(([0, 0, 0, 0], env.port)).await;

    Ok(())
}

fn with_schema(
    val: Arc<graphql::Schema>,
) -> impl Filter<Extract = (Arc<graphql::Schema>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || val.clone())
}

fn with_config(
    val: types::Config,
) -> impl Filter<Extract = (types::Config,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || val.clone())
}

fn ping() -> impl warp::Reply {
    let response = serde_json::json!({ "message": "OK" });
    warp::reply::json(&response)
}

async fn graphql_handler(
    config: types::Config,
    schema: Arc<graphql::Schema>,
    cookie: Option<String>,
    gql_req: GraphQLRequest,
) -> Result<impl warp::Reply, Infallible> {
    let user_id = cookie.clone().and_then(|val| helpers::parse_cookie(&val));

    let context = types::Context {
        cookie_user_id: user_id,
        cookie_out: Arc::new(Mutex::new(types::CookieChange::NoChange)),
        config,
    };

    let res = gql_req.execute(&schema, &context).await;

    let response = match serde_json::to_string(&res) {
        Err(e) => warp::reply::json(&e.to_string()).into_response(),
        Ok(out) => {
            let arc = context.cookie_out.clone();

            let cookie_change = arc.lock().await;

            let default_response = warp::reply::json(&out);

            match &*cookie_change {
                types::CookieChange::NoChange => default_response.into_response(),
                types::CookieChange::Add(id) => warp::reply::with_header(
                    default_response,
                    warp::http::header::SET_COOKIE,
                    helpers::new_cookie(&id),
                )
                .into_response(),
                types::CookieChange::Remove => warp::reply::with_header(
                    default_response,
                    warp::http::header::SET_COOKIE,
                    helpers::remove_cookie(),
                )
                .into_response(),
            }
        }
    };

    Ok(response)
}

//// Juniper GraphQL Resolvers ////

#[juniper::graphql_object(Context = types::Context)]
impl graphql::Query {
    async fn login(context: &types::Context, username: String) -> FieldResult<types::Auth> {
        let variables = graphql::user_by_username::Variables { username };
        let request_body = graphql::UserByUsername::build_query(variables);

        let res: graphql::user_by_username::ResponseData =
            helpers::hasura_request(&context, &request_body).await?;

        match res.user.get(0) {
            None => Err(helpers::field_error("Username not found")),
            Some(user) => {
                let arc = context.cookie_out.clone();
                *arc.lock().await = types::CookieChange::Add(user.id);
                helpers::authenticate(&context, &user.id)
            }
        }
    }
    async fn refresh(context: &types::Context) -> FieldResult<Option<types::Auth>> {
        match context.cookie_user_id {
            Some(id) => helpers::authenticate(&context, &id).map(Some),
            None => Ok(None),
        }
    }
}

#[juniper::graphql_object(Context = types::Context)]
impl graphql::Mutation {
    async fn signup(context: &types::Context, username: String) -> FieldResult<types::Auth> {
        let variables = graphql::user_create::Variables { username };
        let request_body = graphql::UserCreate::build_query(variables);

        let res: graphql::user_create::ResponseData =
            helpers::hasura_request(&context, &request_body).await?;

        match res.insert_user_one {
            None => Err(helpers::field_error("Failed to create user")),
            Some(user) => {
                let arc = context.cookie_out.clone();
                *arc.lock().await = types::CookieChange::Add(user.id);
                helpers::authenticate(&context, &user.id)
            }
        }
    }
    async fn logout(context: &types::Context) -> FieldResult<bool> {
        let arc = context.cookie_out.clone();
        *arc.lock().await = types::CookieChange::Remove;
        Ok(true)
    }
}
