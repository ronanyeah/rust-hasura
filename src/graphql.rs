//// graphql_client codegen ////

use graphql_client::GraphQLQuery;
use juniper::RootNode;

// Required for graphql_client to match
// Hasura uuid type in schema.json.
#[allow(non_camel_case_types)]
pub type uuid = uuid_::Uuid;

pub struct Query;

pub struct Mutation;

pub type Schema =
    RootNode<'static, Query, Mutation, juniper::EmptySubscription<crate::types::Context>>;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "graphql/schema.json",
    query_path = "graphql/user-by-username.graphql"
)]
pub struct UserByUsername;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "graphql/schema.json",
    query_path = "graphql/user-create.graphql"
)]
pub struct UserCreate;
