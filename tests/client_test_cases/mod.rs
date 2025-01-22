//! Integration test cases using a plain `LdapClient`.
//!
//! The functions in this file are basically test bodies, and cannot be run directly.
//! They should be called from other testing modules.
//! The point of this is to allow running the same test cases with and without pooling.

use std::collections::HashSet;
use futures::StreamExt;
use serde::Deserialize;
use simple_ldap::{
    filter::{ContainsFilter, EqFilter},
    ldap3::{Mod, Scope},
    Error, LdapClient
};


pub async fn test_create_record(mut client: LdapClient) -> anyhow::Result<()> {

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

    let _result = client
        .create(
            "bd9b91ec-7a69-4166-bf67-cc7e553b2fd9",
            "ou=people,dc=example,dc=com",
            data,
        )
        .await?;

    Ok(())
}


#[derive(Deserialize)]
pub struct User {
    pub uid: String,
    pub cn: String,
    pub sn: String,
}

pub async fn test_search_record(mut client: LdapClient) -> anyhow::Result<()> {
    let name_filter = EqFilter::from("cn".to_string(), "Sam".to_string());
    let user = client
        .search::<User>(
            "ou=people,dc=example,dc=com",
            simple_ldap::ldap3::Scope::OneLevel,
            &name_filter,
            &vec!["cn", "sn", "uid"],
        )
        .await;
    assert!(user.is_ok());
    let user = user.unwrap();
    assert_eq!(user.cn, "Sam");
    assert_eq!(user.sn, "Smith");

    Ok(())
}


pub async fn test_search_no_record(mut client: LdapClient) -> anyhow::Result<()> {
    let name_filter = EqFilter::from("cn".to_string(), "SamX".to_string());
    let user = client
        .search::<User>(
            "ou=people,dc=example,dc=com",
            simple_ldap::ldap3::Scope::OneLevel,
            &name_filter,
            &vec!["cn", "sn", "uid"],
        )
        .await;
    assert!(user.is_err());
    let er = user.err().unwrap();
    match er {
        Error::NotFound(_) => assert!(true),
        _ => panic!("Unexpected error"),
    }

    Ok(())
}


pub async fn test_search_multiple_record(mut client: LdapClient) -> anyhow::Result<()> {
    let name_filter = EqFilter::from("cn".to_string(), "James".to_string());
    let user = client
        .search::<User>(
            "ou=people,dc=example,dc=com",
            simple_ldap::ldap3::Scope::OneLevel,
            &name_filter,
            &vec!["cn", "sn", "uid"],
        )
        .await;
    assert!(user.is_err());
    let er = user.err().unwrap();
    match er {
        Error::MultipleResults(_) => assert!(true),
        _ => panic!("Unexpected error"),
    }

    Ok(())
}


pub async fn test_update_record(mut client: LdapClient) -> anyhow::Result<()> {
    let data = vec![
        Mod::Replace("cn", HashSet::from(["Jhon_Update"])),
        Mod::Replace("sn", HashSet::from(["Eliet_Update"])),
    ];
    let _result = client
        .update(
            "e219fbc0-6df5-4bc3-a6ee-986843bb157e",
            "ou=people,dc=example,dc=com",
            data,
            Option::None,
        )
        .await?;

    Ok(())
}


pub async fn test_update_no_record(mut client: LdapClient) -> anyhow::Result<()> {
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
        Error::NotFound(_) => assert!(true),
        _ => assert!(false),
    }

    Ok(())
}


pub async fn test_update_uid_record(mut client: LdapClient) -> anyhow::Result<()> {
    let data = vec![
        Mod::Replace("cn", HashSet::from(["David_Update"])),
        Mod::Replace("sn", HashSet::from(["Hanks_Update"])),
    ];
    let _result = client
        .update(
            "cb4bc91e-21d8-4bcc-bf6a-317b84c2e58b",
            "ou=people,dc=example,dc=com",
            data,
            Option::Some("6da70e51-7897-411f-9290-649ebfcb3269"),
        )
        .await?;

    let name_filter = EqFilter::from(
        "uid".to_string(),
        "6da70e51-7897-411f-9290-649ebfcb3269".to_string(),
    );
    let user = client
        .search::<User>(
            "ou=people,dc=example,dc=com",
            simple_ldap::ldap3::Scope::OneLevel,
            &name_filter,
            &vec!["cn", "sn", "uid"],
        )
        .await?;

    assert_eq!(user.cn, "David_Update");
    assert_eq!(user.sn, "Hanks_Update");

    Ok(())
}


pub async fn test_streaming_search(client: LdapClient) -> anyhow::Result<()> {
    let name_filter = EqFilter::from("cn".to_string(), "James".to_string());
    let attra = vec!["cn", "sn", "uid"];
    let mut result = client
        .streaming_search(
            "ou=people,dc=example,dc=com",
            simple_ldap::ldap3::Scope::OneLevel,
            &name_filter,
            &attra,
        )
        .await?;

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
    let _ = result.cleanup().await;
    assert!(count == 2);

    Ok(())
}


pub async fn test_streaming_search_with(client: LdapClient) -> anyhow::Result<()> {
    let name_filter = ContainsFilter::from("cn".to_string(), "J".to_string());
    let attra = vec!["cn", "sn", "uid"];
    let mut result = client
        .streaming_search_with(
            "ou=people,dc=example,dc=com",
            simple_ldap::ldap3::Scope::OneLevel,
            &name_filter,
            &attra,
            3,
        )
        .await?;

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
    assert!(count == 3);
    let _ = result.cleanup().await;

    Ok(())
}


pub async fn test_streaming_search_no_records(client: LdapClient) -> anyhow::Result<()> {
       let name_filter = EqFilter::from("cn".to_string(), "JamesX".to_string());
    let attra = vec!["cn", "sn", "uid"];
    let mut result = client
        .streaming_search(
            "ou=people,dc=example,dc=com",
            simple_ldap::ldap3::Scope::OneLevel,
            &name_filter,
            &attra,
        )
        .await?;

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
    assert_eq!(count, 0);
    let _ = result.cleanup().await;

    Ok(())
}


pub async fn test_delete(mut client: LdapClient) -> anyhow::Result<()> {
     let _result = client
        .delete(
            "4d9b08fe-9a14-4df0-9831-ea9992837f0d",
            "ou=people,dc=example,dc=com",
        )
        .await?;

    Ok(())
}


pub async fn test_no_record_delete(mut client: LdapClient) -> anyhow::Result<()> {
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


pub async fn test_create_group(mut client: LdapClient) -> anyhow::Result<()> {
    let _result = client
        .create_group("test_group", "dc=example,dc=com", "Some Description")
        .await?;

    Ok(())
}


pub async fn test_add_users_to_group(mut client: LdapClient) -> anyhow::Result<()> {
    let _result = client
        .create_group("test_group_1", "dc=example,dc=com", "Some Decription")
        .await?;

    let _result2 = client
        .add_users_to_group(
            vec![
                "uid=f92f4cb2-e821-44a4-bb13-b8ebadf4ecc5,ou=people,dc=example,dc=com",
                "uid=e219fbc0-6df5-4bc3-a6ee-986843bb157e,ou=people,dc=example,dc=com",
            ],
            "cn=test_group_1,dc=example,dc=com",
        )
        .await?;

    Ok(())
}


pub async fn test_get_members(mut client: LdapClient) -> anyhow::Result<()> {
    let _result = client
        .create_group("test_group_3", "dc=example,dc=com", "Some Decription 2")
        .await?;

    let _result = client
        .add_users_to_group(
            vec![
                "uid=f92f4cb2-e821-44a4-bb13-b8ebadf4ecc5,ou=people,dc=example,dc=com",
                "uid=e219fbc0-6df5-4bc3-a6ee-986843bb157e,ou=people,dc=example,dc=com",
            ],
            "cn=test_group_3,dc=example,dc=com",
        )
        .await?;

    let users = client
        .get_members::<User>(
            "cn=test_group_3,dc=example,dc=com",
            "dc=example,dc=com",
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


pub async fn test_remove_users_from_group(mut client: LdapClient) -> anyhow::Result<()> {
    let _result = client
        .create_group("test_group_2", "dc=example,dc=com", "Some Decription 2")
        .await?;

    let _result = client
        .add_users_to_group(
            vec![
                "uid=f92f4cb2-e821-44a4-bb13-b8ebadf4ecc5,ou=people,dc=example,dc=com",
                "uid=e219fbc0-6df5-4bc3-a6ee-986843bb157e,ou=people,dc=example,dc=com",
            ],
            "cn=test_group_2,dc=example,dc=com",
        )
        .await?;

    let _result = client
        .remove_users_from_group(
            "cn=test_group_2,dc=example,dc=com",
            vec![
                "uid=f92f4cb2-e821-44a4-bb13-b8ebadf4ecc5,ou=people,dc=example,dc=com",
                "uid=e219fbc0-6df5-4bc3-a6ee-986843bb157e,ou=people,dc=example,dc=com",
            ],
        )
        .await?;

    Ok(())
}


pub async fn test_associated_groups(mut client: LdapClient) -> anyhow::Result<()> {
    let result = client
        .get_associtated_groups(
            "ou=group,dc=example,dc=com",
            "uid=e219fbc0-6df5-4bc3-a6ee-986843bb157e,ou=people,dc=example,dc=com",
        )
        .await?;

    assert_eq!(result.len(), 2);

    Ok(())
}
