# Simple LDAP client library for Ldap3

A ldap client library that wraps [ldap3](https://github.com/inejge/ldap3) to make it easy to use.

### Status of the project
Currently this is in early alpha stage. Library only support use asynchronously. 

## Usage
```
cargo add simple-ldap
```


## Examples

### Create a new record
```rust
use simple-ldap::{LdapClient,Error,EqFilter};
use simple-ldap::ldap3::Scope;

#[tokio::main]
async fn main() -> Result<()> {
    let mut ldap = LdapClient::from(
            "ldap://localhost:1389/dc=example,dc=com",
            "cn=manager",
            "password",
        )
        .await;

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
    let mut ldap = LdapClient::from(
            "ldap://localhost:1389/dc=example,dc=com",
            "cn=manager",
            "password",
        )
        .await;
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
    let mut ldap = LdapClient::from(
            "ldap://localhost:1389/dc=example,dc=com",
            "cn=manager",
            "password",
        )
        .await;

        let name_filter = EqFilter::from("cn".to_string(), "James".to_string());
        let result = ldap
            .streaming_search::<User>(
                "ou=people,dc=example,dc=com",
                self::ldap3::Scope::OneLevel,
                &name_filter,
                2,
                vec!["cn", "sn", "uid"],
            )
            .await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.len() == 2);
    Ok(ldap.unbind().await?)
}
```

### Update a record
```rust
async fn main() -> Result<()> {
    let mut ldap = LdapClient::from(
            "ldap://localhost:1389/dc=example,dc=com",
            "cn=manager",
            "password",
        )
        .await;
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
    let mut ldap = LdapClient::from(
            "ldap://localhost:1389/dc=example,dc=com",
            "cn=manager",
            "password",
        )
        .await;

        let result = ldap
            .delete(
                "4d9b08fe-9a14-4df0-9831-ea9992837f0d",
                "ou=people,dc=example,dc=com",
            )
            .await;
    Ok(ldap.unbind().await?)
}
```

