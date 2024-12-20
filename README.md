# Simple LDAP client library for Ldap3

A ldap client library that wraps [ldap3](https://github.com/inejge/ldap3) to make it easy to use.

![CI](https://github.com/keaz/simple-ldap/actions/workflows/ci.yml/badge.svg)
[![Crates.io](https://img.shields.io/crates/v/simple-ldap)](https://crates.io/crates/simple-ldap)
[![Documentation](https://docs.rs/simple-ldap/badge.svg)](https://docs.rs/simple-ldap)

## Usage
```
cargo add simple-ldap
```


## Examples

### Authenticate a user

```rust
use simple-ldap::{LdapClient,Error,EqFilter};
use simple-ldap::ldap3::Scope;

#[tokio::main]
async fn main() -> Result<()> {
    let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
            // By default, simple-ldap uses the "entryDN" attribute to get a record's distinguished name.
            // In case the attribute containing the DN is named differently, you can use `dn_attribute` to
            // provide the correct attribute.
            dn_attribute: Some("distinguishedName"),
        };

    let pool = pool::build_connection_pool(&ldap_config).await;
    let mut ldap = pool.pool.get_connection().await.unwrap();
    let name_filter = EqFilter::from("cn".to_string(), "Ada".to_string());

    ldap.authenticate("ou=users,dc=example,dc=org", "Ada", "password", Box::new(name_filter))
        .await
        .expect("Authentication unsuccessful");
}
```

### Create a new record
```rust
use simple-ldap::{LdapClient,Error,EqFilter};
use simple-ldap::ldap3::Scope;

#[tokio::main]
async fn main() -> Result<()> {
    let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
            dn_attribute: None,
        };
        
    let pool = pool::build_connection_pool(&ldap_config).await;
    let mut ldap = pool.pool.get_connection().await.unwrap();

        let data = vec![
            (
                "objectClass",
                HashSet::from(["organizationalPerson", "inetorgperson", "top", "person"]),
            ),
            (
                "uid",
                HashSet::from(["bd9b91ec-7a69-4166-bf67-cc7e553b2fd9"]),
            ),
            ("cn", HashSet::from(["Kasun"])),
            ("sn", HashSet::from(["Ranasingh"])),
        ];
        let result = ldap
            .create(
                "bd9b91ec-7a69-4166-bf67-cc7e553b2fd9",
                "ou=people,dc=example,dc=com",
                data,
            )
            .await;
    Ok(ldap.unbind().await?)
}
```

### Search records
```rust
use simple-ldap::{LdapClient,Error,EqFilter};
use simple-ldap::ldap3::Scope;

#[tokio::main]
async fn main() -> Result<()> {
    let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
            dn_attribute: None,
        };
        
    let pool = pool::build_connection_pool(&ldap_config).await;
    let mut ldap = pool.pool.get_connection().await.unwrap();
        let name_filter = EqFilter::from("cn".to_string(), "Sam".to_string());
        let user = ldap
            .search::<User>(
                "ou=people,dc=example,dc=com",
                self::ldap3::Scope::OneLevel,
                &name_filter,
                vec!["cn", "sn", "uid"],
            )
            .await;
        assert!(user.is_ok());
        let user = user.unwrap();
    Ok(ldap.unbind().await?)
}
```

### Search Stream records
```rust
use simple-ldap::{LdapClient,Error,EqFilter};
use simple-ldap::ldap3::Scope;

#[tokio::main]
async fn main() -> Result<()> {
    let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
            dn_attribute: None,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let ldap = pool.get_connection().await.unwrap();

        let name_filter = EqFilter::from("cn".to_string(), "James".to_string());
        let attra = vec!["cn", "sn", "uid"];
        let result = ldap
            .streaming_search(
                "ou=people,dc=example,dc=com",
                self::ldap3::Scope::OneLevel,
                &name_filter,
                2,
                &attra,
            )
            .await;
        assert!(result.is_ok());
        let mut result = result.unwrap();
        let mut count = 0;
        while let Some(record) = result.next().await {
            match record {
                Ok(record) => {
                    let _ = record.to_record::<User>().unwrap();
                    count += 1;
                }
                Err(_) => {
                    break;
                }
            }
        }
    assert!(count == 2);
    Ok(result.cleanup().await?)
}
```

### Update a record
```rust
async fn main() -> Result<()> {
    let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
            dn_attribute: None,
        };
        
    let pool = pool::build_connection_pool(&ldap_config).await;
    let mut ldap = pool.pool.get_connection().await.unwrap();
        let data = vec![
            Mod::Replace("cn", HashSet::from(["Jhon_Update"])),
            Mod::Replace("sn", HashSet::from(["Eliet_Update"])),
        ];
        let result = ldap
            .update(
                "e219fbc0-6df5-4bc3-a6ee-986843bb157e",
                "ou=people,dc=example,dc=com",
                data,
                Option::None,
            )
            .await;
    Ok(ldap.unbind().await?)
}
```

### Delete a record
```rust
async fn main() -> Result<()> {
    let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
            dn_attribute: None,
        };
        
    let pool = pool::build_connection_pool(&ldap_config).await;
    let mut ldap = pool.pool.get_connection().await.unwrap();

        let result = ldap
            .delete(
                "4d9b08fe-9a14-4df0-9831-ea9992837f0d",
                "ou=people,dc=example,dc=com",
            )
            .await;
    Ok(ldap.unbind().await?)
}
```

### Create a group
```rust
use simple_ldap::LdapClient;
use simple_ldap::pool::LdapConfig;
     
let ldap_config = LdapConfig {
    bind_dn: "cn=manager".to_string(),
    bind_pw: "password".to_string(),
    ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    pool_size: 10,
    dn_attribute: None,
};
     
let pool = pool::build_connection_pool(&ldap_config).await;
let mut ldap = pool.pool.get_connection().await.unwrap();
let result = ldap.create_group("test_group", "ou=groups,dc=example,dc=com", "test group").await;

Ok(ldap.unbind().await?)
```

### Add user to a group
```rust
use simple_ldap::LdapClient;
use simple_ldap::pool::LdapConfig;

let ldap_config = LdapConfig {
    bind_dn: "cn=manager".to_string(),
    bind_pw: "password".to_string(),
    ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    pool_size: 10,
    dn_attribute: None,
};

let pool = pool::build_connection_pool(&ldap_config).await;
let mut ldap = pool.pool.get_connection().await.unwrap();
let result = ldap.add_user_to_group("test_group", "ou=groups,dc=example,dc=com", "test_user").await;

Ok(ldap.unbind().await?)
```


### Get users in a group
```rust
use simple_ldap::LdapClient;
use simple_ldap::pool::LdapConfig;

#[derive(Debug, Deserialize)]
struct User {
    uid: String,
    cn: String,
    sn: String,
}
let ldap_config = LdapConfig {
    bind_dn: "cn=manager".to_string(),
    bind_pw: "password".to_string(),
    ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    pool_size: 10,
    dn_attribute: None,
};

let pool = pool::build_connection_pool(&ldap_config).await;
let mut ldap = pool.pool.get_connection().await.unwrap();
let result = ldap.get_members::<User>("cn=test_group,ou=groups,dc=example,dc=com", "ou=people,dc=example,dc=com", self::ldap3::Scope::OneLevel, vec!["cn", "sn", "uid"]).await;

Ok(ldap.unbind().await?)
```

### Remove user from a group
```rust
use simple_ldap::LdapClient;
use simple_ldap::pool::LdapConfig;

let ldap_config = LdapConfig {
    bind_dn: "cn=manager".to_string(),
    bind_pw: "password".to_string(),
    ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    pool_size: 10,
    dn_attribute: None,
};

let pool = pool::build_connection_pool(&ldap_config).await;
let mut ldap = pool.pool.get_connection().await.unwrap();
let result = pool.pool.get_connection().await.unwrap().remove_users_from_group(
                "cn=test_group_2,dc=example,dc=com",
                vec![
                    "uid=f92f4cb2-e821-44a4-bb13-b8ebadf4ecc5,ou=people,dc=example,dc=com",
                    "uid=e219fbc0-6df5-4bc3-a6ee-986843bb157e,ou=people,dc=example,dc=com",
                ],).await;

Ok(ldap.unbind().await?)
```

### Get Associated Groups for a user
```rust
use simple_ldap::LdapClient;
use simple_ldap::pool::LdapConfig;

let ldap_config = LdapConfig {
    bind_dn: "cn=manager".to_string(),
    bind_pw: "password".to_string(),
    ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    pool_size: 10,
    dn_attribute: None,
};

let pool = pool::build_connection_pool(&ldap_config).await;
let mut ldap = pool.pool.get_connection().await.unwrap();
let result = ldap.get_associtated_groups("ou=group,dc=example,dc=com","uid=e219fbc0-6df5-4bc3-a6ee-986843bb157e,ou=people,dc=example,dc=com",).await;

Ok(ldap.unbind().await?)
```
