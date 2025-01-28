//! Module for running pooled client tests.
//! Most of the testing logic is implemented in `client_test_cases` module and
//! this is just a thin wrapper around it.

mod client_test_cases;

use std::num::NonZeroUsize;

use anyhow::Context;
use client_test_cases::ldap_config;
use simple_ldap::pool::build_connection_pool;




#[tokio::test]
async fn test_create_record() -> anyhow::Result<()> {
  let ldap_config = ldap_config()?;
  let pool_size = NonZeroUsize::new(3)
    .context("Wasn't non-zero")?;
  let pool = build_connection_pool(ldap_config, pool_size).await?;


  let client = pool.get().await?;

  client_test_cases::test_create_record(client).await
}
