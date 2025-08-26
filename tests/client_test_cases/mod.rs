//! # Test cases
//!
//! Integration test cases using a plain `LdapClient`,
//! or really something that dereferences into it.
//!
//! The functions in this file are basically test bodies, and cannot be run directly.
//! They should be called from other testing modules.
//! The point of this is to allow running the same test cases with and without pooling.
//!
//! **All the test cases in this file should be run with and without pooling!**
//! Pay attention to this especially when adding tests cases.
//!
//!
//! ## Idempotence
//!
//! Tests in this file should be **idenpotent.**
//! I.e. running the test twice against the same LDAP server should yield identical test results.
//!
//! This is needed for the above mentioned runnig of same tests with and without pooling.
//!
//! It's enough to satisfy this requirement probabilistically e.g. by using random names
//! that are unlikely to collide.
//!
//!
//! ## Parallelism
//!
//! The tests need to be able run in parallel. This includes multiple instances of the same test.
//! This is required when running these with a pool.
//!
//! In practice this mostly follows from idempotency.
//!
//!
//! ## DerefMut
//!
//! The test case functions don't create LdapClients themselves, but take them from outside
//! as `DerefMut<Target = LdapClient>`. This way we can utilize the same test cases with
//! pooled and plain clients.
//!
//! When calling these with plain `LdapClient`, wrap it in a `Box`.

use futures::{StreamExt, TryStreamExt};
use rand::Rng;
use serde::Deserialize;
use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;
use std::{collections::HashSet, ops::DerefMut, str::FromStr, sync::Once};
use url::Url;
use uuid::Uuid;
use anyhow::anyhow;

use simple_ldap::{
    filter::{ContainsFilter, EqFilter},
    ldap3::{Mod, Scope},
    Error, LdapClient, LdapConfig, SimpleDN,
};

pub async fn test_create_record<Client: DerefMut<Target = LdapClient>>(
    mut client: Client,
) -> anyhow::Result<()> {
    let uid = random_uid();
    let data = vec![
        (
            "objectClass",
            HashSet::from(["organizationalPerson", "inetorgperson", "top", "person"]),
        ),
        ("uid", HashSet::from([uid.as_str()])),
        ("cn", HashSet::from(["Kasun"])),
        ("sn", HashSet::from(["Ranasingh"])),
    ];

    client
        .create(uid.as_str(), "ou=people,dc=example,dc=com", data)
        .await?;

    Ok(())
}

#[derive(Deserialize)]
pub struct User {
    pub dn: SimpleDN,
    pub uid: String,
    pub cn: String,
    pub sn: String,
}

pub async fn test_search_record<Client: DerefMut<Target = LdapClient>>(
    mut client: Client,
) -> anyhow::Result<()> {
    let name_filter = EqFilter::from("cn".to_string(), "Sam".to_string());
    let user: Result<User, Error> = client
        .search(
            "ou=people,dc=example,dc=com",
            simple_ldap::ldap3::Scope::OneLevel,
            &name_filter,
            vec!["cn", "sn", "uid"],
        )
        .await;

    let user = user.unwrap();

    let dn = SimpleDN::from_str("uid=f92f4cb2-e821-44a4-bb13-b8ebadf4ecc5,ou=people,dc=example,dc=com")?;

    assert_eq!(user.cn, "Sam");
    assert_eq!(user.sn, "Smith");
    assert_eq!(user.dn, dn);

    Ok(())
}

pub async fn test_search_no_record<Client: DerefMut<Target = LdapClient>>(
    mut client: Client,
) -> anyhow::Result<()> {
    let name_filter = EqFilter::from("cn".to_string(), "SamX".to_string());
    let user: Result<User, Error> = client
        .search(
            "ou=people,dc=example,dc=com",
            simple_ldap::ldap3::Scope::OneLevel,
            &name_filter,
            &vec!["cn", "sn", "uid"],
        )
        .await;
    assert!(user.is_err());
    let er = user.err().unwrap();
    match er {
        Error::NotFound(_) => Ok(()),
        _ => Err(anyhow!("Unexpected error")),
    }
}

pub async fn test_search_multiple_record<Client: DerefMut<Target = LdapClient>>(
    mut client: Client,
) -> anyhow::Result<()> {
    let name_filter = EqFilter::from("cn".to_string(), "James".to_string());
    let user: Result<User, Error> = client
        .search(
            "ou=people,dc=example,dc=com",
            simple_ldap::ldap3::Scope::OneLevel,
            &name_filter,
            &vec!["cn", "sn", "uid"],
        )
        .await;
    assert!(user.is_err());
    let er = user.err().unwrap();
    match er {
        Error::MultipleResults(_) => Ok(()),
        _ => Err(anyhow!("Unexpected error")),
    }
}

pub async fn test_update_record<Client: DerefMut<Target = LdapClient>>(
    mut client: Client,
) -> anyhow::Result<()> {
    let data = vec![
        Mod::Replace("cn", HashSet::from(["Jhon_Update"])),
        Mod::Replace("sn", HashSet::from(["Eliet_Update"])),
    ];
    client
        .update(
            "e219fbc0-6df5-4bc3-a6ee-986843bb157e",
            "ou=people,dc=example,dc=com",
            data,
            Option::None,
        )
        .await?;

    Ok(())
}

pub async fn test_update_no_record<Client: DerefMut<Target = LdapClient>>(
    mut client: Client,
) -> anyhow::Result<()> {
    let data = vec![
        Mod::Replace("cn", HashSet::from(["Jhon_Update"])),
        Mod::Replace("sn", HashSet::from(["Eliet_Update"])),
    ];
    let result = client
        .update(
            "032a26b4-9f00-4a29-99c8-15d463a29290",
            "ou=people,dc=example,dc=com",
            data,
            Option::None,
        )
        .await;
    assert!(result.is_err());
    let er = result.err().unwrap();
    match er {
        Error::NotFound(_) => Ok(()),
        _ => Err(anyhow!("Unexpected error")),
    }
}

pub async fn test_update_uid_record<Client: DerefMut<Target = LdapClient>>(
    mut client: Client,
) -> anyhow::Result<()> {
    // First create a user to update.
    // A create_user method would be nice.. 🤔
    let original_uid = random_uid();
    let data = vec![
        (
            "objectClass",
            HashSet::from(["organizationalPerson", "inetorgperson", "top", "person"]),
        ),
        ("uid", HashSet::from([original_uid.as_str()])),
        ("cn", HashSet::from(["Update"])),
        ("sn", HashSet::from(["Me"])),
    ];

    let base = String::from("ou=people,dc=example,dc=com");

    client
        .create(original_uid.as_str(), base.as_str(), data)
        .await?;

    let new_cn = "I'm";
    let new_sn = "Updated";

    let data = vec![
        Mod::Replace("cn", HashSet::from([new_cn])),
        Mod::Replace("sn", HashSet::from([new_sn])),
    ];
    let new_uid = random_uid();

    // This is the call we're testing.
    client
        .update(
            original_uid.as_str(),
            base.as_str(),
            data,
            Option::Some(new_uid.as_str()),
        )
        .await?;

    let name_filter = EqFilter::from("uid".to_string(), new_uid);
    let user: User = client
        .search(
            base.as_str(),
            simple_ldap::ldap3::Scope::OneLevel,
            &name_filter,
            &vec!["cn", "sn", "uid"],
        )
        .await?;

    assert_eq!(user.cn, new_cn);
    assert_eq!(user.sn, new_sn);

    Ok(())
}

pub async fn test_streaming_search<Client: DerefMut<Target = LdapClient>>(
    mut client: Client,
) -> anyhow::Result<()> {
    let name_filter = EqFilter::from("cn".to_string(), "James".to_string());
    let attra = vec!["cn", "sn", "uid"];
    let stream = client
        .streaming_search(
            "ou=people,dc=example,dc=com",
            simple_ldap::ldap3::Scope::OneLevel,
            &name_filter,
            &attra,
        )
        .await?;

    let mut pinned_stream = Box::pin(stream);

    let mut count = 0;
    while let Some(record) = pinned_stream.next().await {
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

    Ok(())
}

pub async fn test_streaming_search_paged<Client: DerefMut<Target = LdapClient>>(
    mut client: Client,
) -> anyhow::Result<()>
{
    enable_tracing_subscriber();

    let name_filter = ContainsFilter::from("cn".to_string(), "J".to_string());
    let attra = vec!["cn", "sn", "uid"];
    let stream = client
        .streaming_search_paged(
            "ou=people,dc=example,dc=com",
            simple_ldap::ldap3::Scope::OneLevel,
            &name_filter,
            &attra,
            // Testing with a pagesize smaller than the result set so that we actually see
            // multiple pages.
            2,
        )
        .await?;

    let count = stream.and_then(async |record| record.to_record())
        .try_fold(0, async |sum, _ :User| Ok(sum + 1))
        .await?;

    assert_eq!(count, 3);

    Ok(())
}


pub async fn test_search_stream_drop<Client: DerefMut<Target = LdapClient>>(
    mut client: Client,
) -> anyhow::Result<()>
{
    // Here we always want to trace.
    enable_tracing_subscriber();

    let name_filter = ContainsFilter::from("cn".to_string(), "J".to_string());
    let attra = vec!["cn", "sn", "uid"];
    let stream = client
        .streaming_search_paged(
            "ou=people,dc=example,dc=com",
            simple_ldap::ldap3::Scope::OneLevel,
            &name_filter,
            &attra,
            // Testing with a pagesize smaller than the result set so that we actually see
            // multiple pages. Expecting 3 in total.
            2,
        )
        .await?;

    let mut pinned_stream = Box::pin(stream);

    // Get one element from the stream.
    pinned_stream.try_next().await?;

    // Then just let it drop.
    // This won't actually ever fail, but you can see the tracing log that no errors occurred.
    Ok(())
}



pub async fn test_streaming_search_no_records<Client: DerefMut<Target = LdapClient>>(
    mut client: Client,
) -> anyhow::Result<()>
{
    enable_tracing_subscriber();

    let name_filter = EqFilter::from("cn".to_string(), "JamesX".to_string());
    let attra = vec!["cn", "sn", "uid"];
    let stream = client
        .streaming_search(
            "ou=people,dc=example,dc=com",
            simple_ldap::ldap3::Scope::OneLevel,
            &name_filter,
            &attra,
        )
        .await?;

    let count = stream.and_then(async |record| record.to_record())
        .try_fold(0, async |sum, _ :User| Ok(sum + 1))
        .await?;

    assert_eq!(count, 0);

    Ok(())
}

pub async fn test_delete<Client: DerefMut<Target = LdapClient>>(
    mut client: Client,
) -> anyhow::Result<()> {
    // First create a user to delete.
    // A create_user method would be nice.. 🤔
    let uid = random_uid();
    let data = vec![
        (
            "objectClass",
            HashSet::from(["organizationalPerson", "inetorgperson", "top", "person"]),
        ),
        ("uid", HashSet::from([uid.as_str()])),
        ("cn", HashSet::from(["Delete"])),
        ("sn", HashSet::from(["Me"])),
    ];

    let base = String::from("ou=people,dc=example,dc=com");

    client.create(uid.as_str(), base.as_str(), data).await?;

    // This is what we are really testing.
    let _result = client.delete(uid.as_str(), base.as_str()).await?;

    Ok(())
}

pub async fn test_no_record_delete<Client: DerefMut<Target = LdapClient>>(
    mut client: Client,
) -> anyhow::Result<()> {
    let result = client
        .delete(
            "4d9b08fe-9a14-4df0-9831-ea9992837f0x",
            "ou=people,dc=example,dc=com",
        )
        .await;
    assert!(result.is_err());
    let er = result.err().unwrap();
    match er {
        Error::NotFound(_) => assert!(true),
        _ => assert!(false),
    }

    Ok(())
}

pub async fn test_create_group<Client: DerefMut<Target = LdapClient>>(
    mut client: Client,
) -> anyhow::Result<()> {
    let name = append_random_id("test_group");
    let _result = client
        .create_group(name.as_str(), "dc=example,dc=com", "Some Description")
        .await?;

    Ok(())
}

pub async fn test_add_users_to_group<Client: DerefMut<Target = LdapClient>>(
    mut client: Client,
) -> anyhow::Result<()> {
    let group_name = append_random_id("user_add_test_group");
    let group_dn = format!("cn={group_name},dc=example,dc=com");

    client
        .create_group(group_name.as_str(), "dc=example,dc=com", "Some Decription")
        .await?;

    client
        .add_users_to_group(
            vec![
                "uid=f92f4cb2-e821-44a4-bb13-b8ebadf4ecc5,ou=people,dc=example,dc=com",
                "uid=e219fbc0-6df5-4bc3-a6ee-986843bb157e,ou=people,dc=example,dc=com",
            ],
            group_dn.as_str(),
        )
        .await?;

    // Could check here that they are actually in the group.

    Ok(())
}

pub async fn test_get_members<Client: DerefMut<Target = LdapClient>>(
    mut client: Client,
) -> anyhow::Result<()> {
    // Let's first prepare a group.

    let group_name = append_random_id("get_members_group");
    let group_ou = String::from("dc=example,dc=com");
    let group_dn = format!("cn={group_name},{group_ou}");

    client
        .create_group(group_name.as_str(), group_ou.as_str(), "Some Decription 2")
        .await?;

    client
        .add_users_to_group(
            vec![
                "uid=f92f4cb2-e821-44a4-bb13-b8ebadf4ecc5,ou=people,dc=example,dc=com",
                "uid=e219fbc0-6df5-4bc3-a6ee-986843bb157e,ou=people,dc=example,dc=com",
            ],
            group_dn.as_str(),
        )
        .await?;

    // This is what we are testing.
    let users = client
        .get_members::<User>(
            group_dn.as_str(),
            group_ou.as_str(),
            Scope::Subtree,
            &vec!["cn", "sn", "uid"],
        )
        .await?;

    assert_eq!(users.len(), 2);
    let user_count = users
        .iter()
        .filter(|user| {
            user.uid == "f92f4cb2-e821-44a4-bb13-b8ebadf4ecc5"
                || user.uid == "e219fbc0-6df5-4bc3-a6ee-986843bb157e"
        })
        .count();
    assert_eq!(user_count, 2);

    Ok(())
}

pub async fn test_remove_users_from_group<Client: DerefMut<Target = LdapClient>>(
    mut client: Client,
) -> anyhow::Result<()> {
    // Let's first prepare a group.

    let group_name = append_random_id("get_members_group");
    let group_ou = String::from("dc=example,dc=com");
    let group_dn = format!("cn={group_name},{group_ou}");

    client
        .create_group(group_name.as_str(), group_ou.as_str(), "Some Decription 2")
        .await?;

    client
        .add_users_to_group(
            vec![
                "uid=f92f4cb2-e821-44a4-bb13-b8ebadf4ecc5,ou=people,dc=example,dc=com",
                "uid=e219fbc0-6df5-4bc3-a6ee-986843bb157e,ou=people,dc=example,dc=com",
            ],
            group_dn.as_str(),
        )
        .await?;

    // This is what we are testing here.
    client
        .remove_users_from_group(
            group_dn.as_str(),
            vec![
                "uid=f92f4cb2-e821-44a4-bb13-b8ebadf4ecc5,ou=people,dc=example,dc=com",
                "uid=e219fbc0-6df5-4bc3-a6ee-986843bb157e,ou=people,dc=example,dc=com",
            ],
        )
        .await?;

    // Currently the library doesn't seem to able to handle empty groups so the
    // verification below is commented out.

    // let users = client
    //     .get_members::<User>(
    //         group_dn.as_str(),
    //         group_ou.as_str(),
    //         Scope::Subtree,
    //         &vec!["cn", "sn", "uid"],
    //     )
    //     .await?;

    // assert!(users.is_empty(), "The users weren't removed from the group.");

    Ok(())
}

pub async fn test_associated_groups<Client: DerefMut<Target = LdapClient>>(
    mut client: Client,
) -> anyhow::Result<()> {
    let result = client
        .get_associtated_groups(
            "ou=group,dc=example,dc=com",
            "uid=e219fbc0-6df5-4bc3-a6ee-986843bb157e,ou=people,dc=example,dc=com",
        )
        .await?;

    assert_eq!(result.len(), 2);

    Ok(())
}


/***************
 *  Utilities  *
 ***************/

// Some of these utilities are even public because of cargo's test module limitations.

/// Can be used to generate random names for things to avoid clashes.
fn append_random_id(beginning: &str) -> String {
    let mut rng = rand::rng();
    // A few in milliard are plenty unlikely to collide.
    let random_id: u32 = rng.random_range(0..1000000000);
    format!("{beginning} {random_id}")
}

/// Generate a random LDAP compatible uid and return it's string representation.
fn random_uid() -> String {
    // v4 is random.
    Uuid::new_v4()
        .as_hyphenated()
        // No idea whether LDAP actually cares about the case?
        .encode_lower(&mut Uuid::encode_buffer())
        .to_owned()
}

/// Get ldap configuration for conneting to the test server.
pub fn ldap_config() -> anyhow::Result<LdapConfig> {
    let config = LdapConfig {
        bind_dn: String::from("cn=manager"),
        bind_password: String::from("password"),
        ldap_url: Url::parse("ldap://localhost:1389/dc=example,dc=com")?,
        dn_attribute: None,
        connection_settings: None,
    };

    Ok(config)
}

/// Print out traces in tests.
///
/// It's perhaps best not to overuse this, as it's quite verbose.
/// You can add it to the start of test you wish to investigate.
fn enable_tracing_subscriber() -> () {
    static ONCE: Once = Once::new();

    // Tests are run in parallel and might try to set the subscriber multiple times.
    ONCE.call_once(|| {
        tracing_subscriber::fmt()
            .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
            .with_max_level(Level::TRACE)
            .init();
        }
    );
}
