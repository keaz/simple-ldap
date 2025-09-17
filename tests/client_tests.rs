//! Module for running non-pooled client tests.
//! All the testing logic is implemented in `client_test_cases` and
//! this is just a thin wrapper around it.
mod client_test_cases;

use client_test_cases::ldap_config;
use simple_ldap::LdapClient;

/// Get a normal LDAP client to run integration tests with.
///
/// You should use this, unless the test is specifically about creating a client.
async fn get_test_client() -> anyhow::Result<LdapClient> {
    let ldap_config = ldap_config()?;

    let client = LdapClient::new(ldap_config).await?;

    Ok(client)
}

#[tokio::test]
async fn test_create_record() -> anyhow::Result<()> {
    let client = get_test_client().await?;
    client_test_cases::test_create_record(Box::new(client)).await
}

#[tokio::test]
async fn test_search_record() -> anyhow::Result<()> {
    let client = get_test_client().await?;
    client_test_cases::test_search_record(Box::new(client)).await
}

#[tokio::test]
async fn test_search_no_record() -> anyhow::Result<()> {
    let client = get_test_client().await?;
    client_test_cases::test_search_no_record(Box::new(client)).await
}

#[tokio::test]
async fn test_search_multiple_record() -> anyhow::Result<()> {
    let client = get_test_client().await?;
    client_test_cases::test_search_multiple_record(Box::new(client)).await
}

#[tokio::test]
async fn test_search_multi_valued() -> anyhow::Result<()> {
    let client = get_test_client().await?;
    client_test_cases::test_search_multi_valued(Box::new(client)).await
}

#[tokio::test]
async fn test_update_record() -> anyhow::Result<()> {
    let client = get_test_client().await?;
    client_test_cases::test_update_record(Box::new(client)).await
}

#[tokio::test]
async fn test_update_no_record() -> anyhow::Result<()> {
    let client = get_test_client().await?;
    client_test_cases::test_update_no_record(Box::new(client)).await
}

#[tokio::test]
async fn test_update_uid_record() -> anyhow::Result<()> {
    let client = get_test_client().await?;
    client_test_cases::test_update_uid_record(Box::new(client)).await
}

#[tokio::test]
async fn test_streaming_search() -> anyhow::Result<()> {
    let client = get_test_client().await?;
    client_test_cases::test_streaming_search(Box::new(client)).await
}

#[tokio::test]
async fn test_streaming_search_paged() -> anyhow::Result<()> {
    let client = get_test_client().await?;
    client_test_cases::test_streaming_search_paged(Box::new(client)).await
}

#[tokio::test]
async fn test_search_stream_drop() -> anyhow::Result<()> {
    let client = get_test_client().await?;
    client_test_cases::test_search_stream_drop(Box::new(client)).await
}

#[tokio::test]
async fn test_streaming_search_no_records() -> anyhow::Result<()> {
    let client = get_test_client().await?;
    client_test_cases::test_streaming_search_no_records(Box::new(client)).await
}

#[tokio::test]
async fn test_delete() -> anyhow::Result<()> {
    let client = get_test_client().await?;
    client_test_cases::test_delete(Box::new(client)).await
}

#[tokio::test]
async fn test_no_record_delete() -> anyhow::Result<()> {
    let client = get_test_client().await?;
    client_test_cases::test_no_record_delete(Box::new(client)).await
}

#[tokio::test]
async fn test_create_group() -> anyhow::Result<()> {
    let client = get_test_client().await?;
    client_test_cases::test_create_group(Box::new(client)).await
}

#[tokio::test]
async fn test_add_users_to_group() -> anyhow::Result<()> {
    let client = get_test_client().await?;
    client_test_cases::test_add_users_to_group(Box::new(client)).await
}

#[tokio::test]
async fn test_get_members() -> anyhow::Result<()> {
    let client = get_test_client().await?;
    client_test_cases::test_get_members(Box::new(client)).await
}

#[tokio::test]
async fn test_remove_users_from_group() -> anyhow::Result<()> {
    let client = get_test_client().await?;
    client_test_cases::test_remove_users_from_group(Box::new(client)).await
}

#[tokio::test]
async fn test_associated_groups() -> anyhow::Result<()> {
    let client = get_test_client().await?;
    client_test_cases::test_associated_groups(Box::new(client)).await
}

#[tokio::test]
async fn test_authenticate_success() -> anyhow::Result<()> {
    let client = get_test_client().await?;
    client_test_cases::test_authenticate_success(Box::new(client)).await
}

#[tokio::test]
async fn test_authenticate_wrong_password() -> anyhow::Result<()> {
    let client = get_test_client().await?;
    client_test_cases::test_authenticate_wrong_password(Box::new(client)).await
}
