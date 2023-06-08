FROM rust as builder
WORKDIR /app
RUN cargo new hello_world --lib
COPY Cargo.toml hello_world/Cargo.toml
WORKDIR /app/hello_world
RUN cargo build
COPY . .
ENTRYPOINT [ "cargo","test" ]