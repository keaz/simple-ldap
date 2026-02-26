//! Module for running pooled client tests.
//! Most of the testing logic is implemented in `client_test_cases` module and
//! this is just a thin wrapper around it.

mod client_test_cases;

use std::{future::Future, num::NonZeroUsize};

use anyhow::Context;
use client_test_cases::ldap_config;
use futures::try_join;
use simple_ldap::pool::{Object, Pool, build_connection_pool};

/// A convenience function for building a connection pool for tests.
async fn build_pool() -> anyhow::Result<Pool> {
    let ldap_config = ldap_config()?;
    // Needs to be at lest 2 because of `dispatch_parallel_test`.
    let pool_size = NonZeroUsize::new(3).context("Wasn't non-zero")?;
    let pool = build_connection_pool(ldap_config, pool_size).await?;

    Ok(pool)
}

/// A convenience function for runnig the test function in parallel with a pool.
/// This should be used to evoke the test functions in `client_test_cases`.
///
/// Tries to simulate real pool usage.
async fn dispatch_parallel_test<Function, Fut>(test_case: Function) -> anyhow::Result<()>
where
    Function: Fn(Object) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    let pool = build_pool().await?;
    let client1 = pool.get().await?;
    let client2 = pool.get().await?;

    let future1 = test_case(client1);
    let future2 = test_case(client2);

    try_join!(future1, future2)?;

    Ok(())
}

#[tokio::test]
async fn test_create_record() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::test_create_record).await
}

#[tokio::test]
async fn test_search_record() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::test_search_record).await
}

#[tokio::test]
async fn test_search_no_record() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::test_search_no_record).await
}

#[tokio::test]
async fn test_search_multiple_record() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::test_search_multiple_record).await
}

#[tokio::test]
async fn test_search_multi_valued() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::test_search_multi_valued).await
}

#[tokio::test]
async fn test_update_record() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::test_update_record).await
}

#[tokio::test]
async fn test_update_no_record() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::test_update_no_record).await
}

#[tokio::test]
async fn test_update_uid_record() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::test_update_uid_record).await
}

#[tokio::test]
async fn test_streaming_search() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::test_streaming_search).await
}

#[tokio::test]
async fn test_streaming_search_paged() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::test_streaming_search_paged).await
}

#[tokio::test]
async fn sorted_paged_search() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::sorted_paged_search).await
}

#[tokio::test]
async fn sorted_paged_search_reverse() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::sorted_paged_search_reverse).await
}

#[tokio::test]
async fn test_search_stream_drop() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::test_search_stream_drop).await
}

#[tokio::test]
async fn test_streaming_search_no_records() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::test_streaming_search_no_records).await
}

#[tokio::test]
async fn test_delete() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::test_delete).await
}

#[tokio::test]
async fn test_no_record_delete() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::test_no_record_delete).await
}

#[tokio::test]
async fn test_create_group() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::test_create_group).await
}

#[tokio::test]
async fn test_add_users_to_group() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::test_add_users_to_group).await
}

#[tokio::test]
async fn test_get_members() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::test_get_members).await
}

#[tokio::test]
async fn test_remove_users_from_group() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::test_remove_users_from_group).await
}

#[tokio::test]
async fn test_associated_groups() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::test_associated_groups).await
}

#[tokio::test]
async fn test_authenticate_success() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::test_authenticate_success).await
}

#[tokio::test]
async fn test_authenticate_wrong_password() -> anyhow::Result<()> {
    dispatch_parallel_test(client_test_cases::test_authenticate_wrong_password).await
}
