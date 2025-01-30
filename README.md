# Simple LDAP client library for Ldap3

A ldap client library that wraps [ldap3](https://github.com/inejge/ldap3) to make it easy to use.

![CI](https://github.com/keaz/simple-ldap/actions/workflows/ci.yml/badge.svg)
[![Crates.io](https://img.shields.io/crates/v/simple-ldap)](https://crates.io/crates/simple-ldap)
[![Documentation](https://docs.rs/simple-ldap/badge.svg)](https://docs.rs/simple-ldap)

## Usage

Adding `simple_ldap` as a dependency to your project:

```commandline
cargo add simple-ldap
```

Other useful pieces you'll likely need:

```commandline
cargo add url serde --features serde/derive
```


### Example

There are plenty more examples in the [documentation](https://docs.rs/simple-ldap)!


#### Search records

```rust,no_run
use simple_ldap::{
    LdapClient, LdapConfig,
    filter::EqFilter,
    ldap3::Scope
};
use url::Url;
use serde::Deserialize;

// A type for deserializing the search result into.
#[derive(Debug, Deserialize)]
struct User {
    uid: String,
    cn: String,
    sn: String,
}


#[tokio::main]
async fn main(){
    let ldap_config = LdapConfig {
        bind_dn: String::from("cn=manager"),
        bind_password: String::from("password"),
        ldap_url: Url::parse("ldaps://localhost:1389/dc=example,dc=com").unwrap(),
        dn_attribute: None,
        connection_settings: None
    };
    let mut client = LdapClient::new(ldap_config).await.unwrap();
    let name_filter = EqFilter::from("cn".to_string(), "Sam".to_string());
    let user: User = client
        .search::<User>(
        "ou=people,dc=example,dc=com",
        Scope::OneLevel,
        &name_filter,
        &vec!["cn", "sn", "uid"],
    ).await.unwrap();
}
```
