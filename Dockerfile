FROM rust:1.73.0-buster as builder
WORKDIR /app
RUN cargo new hello_world --lib
COPY Cargo.toml hello_world/Cargo.toml

WORKDIR /app/hello_world
# for cache
RUN cargo build 
WORKDIR /app/hello_world
RUN cargo build
COPY . .
ENTRYPOINT [ "cargo","test" ]