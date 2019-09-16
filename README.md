## Rust + Hasura

This is an example of a [Rust](https://www.rust-lang.org) server that functions as a [remote schema](https://docs.hasura.io/1.0/graphql/manual/remote-schemas/index.html) for [Hasura](https://hasura.io).

It features login, signup, JWT creation, [hashed](https://docs.rs/bcrypt) passwords and [typesafe](https://docs.rs/graphql_client) requests to Hasura (including integration of Rust's [uuid](https://docs.rs/uuid) package).


## Package Manager

[Cargo](https://doc.rust-lang.org/cargo/guide)


## Setup

-  Your Hasura schema must have a table `user`, with a column `id` of type `uuid`, and also a column `password` of type `text`.
- You must also set an [`ADMIN_SECRET`](https://docs.hasura.io/1.0/graphql/manual/deployment/graphql-engine-flags/reference.html) and a [`JWT_SECRET`](https://docs.hasura.io/1.0/graphql/manual/auth/authentication/jwt.html) on the graphql engine, and share these with the Rust server.
- Use [graphqurl](https://www.npmjs.com/package/graphqurl) to generate `./schema.json`
- `gq $HASURA_ENDPOINT -H "x-hasura-admin-secret: $ADMIN_SECRET" --introspect --format json > ./schema.json`
- `cargo run`


## Environment Variables

Key | Example
--- | ---
`PORT` | `8000`
`HASURA_ENDPOINT` | `http://127.0.0.1:8080/v1/graphql`
`ADMIN_SECRET` | `foo`
`JWT_SECRET` | `{"type":"HS256","key":"3QQ6FD+o0+c7tzQQVfjpMkNDi2yARAAKzQQk8O2IKoxQQ4nF7EdAh8s3TwpHwrdQQ6R"}`
