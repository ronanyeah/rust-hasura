## Rust + Hasura ![Rust](https://github.com/ronanyeah/rust-hasura/workflows/Rust/badge.svg)

This is an example of a [Rust](https://www.rust-lang.org) server that functions as a [remote schema](https://hasura.io/docs/1.0/graphql/manual/remote-schemas/index.html) for [Hasura](https://hasura.io).

It demonstrates:
- user login + signup
- [JWT authorization w/ refresh cookie](https://hasura.io/blog/best-practices-of-using-jwt-with-graphql/)
- [typesafe GraphQL requests](https://docs.rs/graphql_client)
- [uuid](https://docs.rs/uuid) package integration

You can learn more about this stack from [this talk](https://www.youtube.com/watch?v=ly05IV5isf4).


## Package Manager

[Cargo](https://doc.rust-lang.org/cargo/guide)


## Setup

-  Your Hasura schema must have a table `user`, with a `id` column of type `uuid`, and also a `username` column of type `text`.
- Set an [`ADMIN_SECRET`](https://hasura.io/docs/1.0/graphql/manual/deployment/graphql-engine-flags/reference.html) and a [`JWT_SECRET`](https://hasura.io/docs/1.0/graphql/manual/auth/authentication/jwt.html) on the graphql engine, and share these with the Rust server as environment variables.
- Use [graphqurl](https://www.npmjs.com/package/graphqurl) to generate `schema.json`
- `gq $HASURA_ENDPOINT -H "x-hasura-admin-secret: $ADMIN_SECRET" --introspect --format json > ./graphql/schema.json`

## Start
- `cargo run`


## Environment Variables

Key | Example
--- | ---
`PORT` | `8000`
`HASURA_ENDPOINT` | `http://127.0.0.1:8080/v1/graphql`
`ADMIN_SECRET` | `foo`
`JWT_SECRET` | `{"type":"HS256","key":"3QQ6FD+o0+c7tzQQVfjpMkNDi2yARAAKzQQk8O2IKoxQQ4nF7EdAh8s3TwpHwrdQQ6R"}`
