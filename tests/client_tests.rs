//! Module for running non-pooled client tests.
//! All the testing logic is implemented in `client_test_cases` and
//! this is just a thin wrapper around it.
mod client_test_cases;

use simple_ldap::{LdapClient, LdapConfig};



/// Get a normal LDAP client to run integration tests with.
///
/// You should use this, unless the test is specifically about creating a client.
async fn get_test_client() -> anyhow::Result<LdapClient> {
  let ldap_config = LdapConfig {
      bind_dn: "cn=manager".to_string(),
      bind_password: "password".to_string(),
      ldap_url: "ldap://localhost:1389/dc=example,dc=com".parse()?,
      dn_attribute: None,
      connection_settings: None
  };

  let client = LdapClient::new(ldap_config).await?;

  Ok(client)
}



#[tokio::test]
async fn test_create_record() -> anyhow::Result<()> {
  let client = get_test_client().await?;
  client_test_cases::test_create_record(client).await
}


#[tokio::test]
async fn test_search_record() -> anyhow::Result<()> {
  let client = get_test_client().await?;
  client_test_cases::test_search_record(client).await
}


#[tokio::test]
async fn test_search_no_record() -> anyhow::Result<()> {
  let client = get_test_client().await?;
  client_test_cases::test_search_no_record(client).await
}


#[tokio::test]
async fn test_search_multiple_record() -> anyhow::Result<()> {
  let client = get_test_client().await?;
  client_test_cases::test_search_multiple_record(client).await
}


#[tokio::test]
async fn test_update_record() -> anyhow::Result<()> {
  let client = get_test_client().await?;
  client_test_cases::test_update_record(client).await
}


#[tokio::test]
async fn test_update_no_record() -> anyhow::Result<()> {
  let client = get_test_client().await?;
  client_test_cases::test_update_no_record(client).await
}


#[tokio::test]
async fn test_update_uid_record() -> anyhow::Result<()> {
  let client = get_test_client().await?;
  client_test_cases::test_update_uid_record(client).await
}


#[tokio::test]
async fn test_streaming_search() -> anyhow::Result<()> {
  let client = get_test_client().await?;
  client_test_cases::test_streaming_search(client).await
}


#[tokio::test]
async fn test_streaming_search_with() -> anyhow::Result<()> {
  let client = get_test_client().await?;
  client_test_cases::test_streaming_search_with(client).await
}


#[tokio::test]
async fn test_streaming_search_no_records() -> anyhow::Result<()> {
  let client = get_test_client().await?;
  client_test_cases::test_streaming_search_no_records(client).await
}


#[tokio::test]
async fn test_delete() -> anyhow::Result<()> {
  let client = get_test_client().await?;
  client_test_cases::test_delete(client).await
}


#[tokio::test]
async fn test_no_record_delete() -> anyhow::Result<()> {
  let client = get_test_client().await?;
  client_test_cases::test_no_record_delete(client).await
}


#[tokio::test]
async fn test_create_group() -> anyhow::Result<()> {
  let client = get_test_client().await?;
  client_test_cases::test_create_group(client).await
}


#[tokio::test]
async fn test_add_users_to_group() -> anyhow::Result<()> {
  let client = get_test_client().await?;
  client_test_cases::test_add_users_to_group(client).await
}


#[tokio::test]
async fn test_get_members() -> anyhow::Result<()> {
  let client = get_test_client().await?;
  client_test_cases::test_get_members(client).await
}


#[tokio::test]
async fn test_remove_users_from_group() -> anyhow::Result<()> {
  let client = get_test_client().await?;
  client_test_cases::test_remove_users_from_group(client).await
}


#[tokio::test]
async fn test_associated_groups() -> anyhow::Result<()> {
  let client = get_test_client().await?;
  client_test_cases::test_associated_groups(client).await
}
