use deadpool::{
    managed::{self, Metrics, RecycleResult},
    managed_reexports,
};
/// # Pool
///
/// Module for LDAP connection pooling using [`deadpool`](https://docs.rs/deadpool/latest/deadpool/index.html).
///
/// A single LDAP connection is able to handle multiple operations concurrently, but beyond a certain
/// point it will become a bottleneck. This is where pooling comes in.
///
/// The pool keeps multiple connections alive and gives them to you upon request (or makes you wait for one to become available.)
///
///
/// ## Do I need connection pooling?
///
/// As always, there's no substitute for benchmarking on your particular usecase.
///
/// But as a general rule of thumb: If your code is some sort of service, e.g. a website needing to authenticate users as they try to login, use pooling. On the other hand if your code is a oneshot executable, such as the `ldapsearch` CLI tool, don't bother with pooling.
///
///
/// ## Example
///
/// ```no_run
/// use simple_ldap::{
///     LdapConfig,
///     pool::build_connection_pool
/// };
/// use std::num::NonZeroUsize;
/// use url::Url;
///
/// #[tokio::main]
/// async fn main() -> () {
///     let ldap_config = LdapConfig {
///         bind_dn: String::from("cn=manager"),
///         bind_password: String::from("password"),
///         ldap_url: Url::parse("ldap://localhost:1389/dc=example,dc=com").unwrap(),
///         dn_attribute: None,
///         connection_settings: None
///     };
///     let pool_size = NonZeroUsize::new(10).unwrap();
///
///     // Build the ldap connection pool.
///     let pool = build_connection_pool(ldap_config, pool_size).await.unwrap();
///
///     // Get clients from the pool.
///     let mut client_from_pool = pool.get().await.unwrap();
///
///     // Perform operations on them just as with a normal LdapClient.
///     let result = client_from_pool.create_group("New Group", "dc=example,dc=com", "Some Description").await;
/// }
/// ```
///
///
/// ## Unbind
///
/// You cannot `unbind` the clients got from the pool.
/// Just return them to the pool. It will take care of it.
///
use std::num::NonZeroUsize;
use tracing::debug;

use crate::{Error, LdapClient, LdapConfig};

// Export the pool types in a standard manner.
// Check the source to see the types this exposes
managed_reexports!(
    "simple_ldap",
    Manager,
    managed::Object<Manager>,
    crate::Error,
    // Config cannot fail
    std::convert::Infallible
);

/// Manager for deadpool.
pub struct Manager {
    /// Configuration for creating connections.
    config: LdapConfig,
}

/// LDAP Manager for the `deadpool` managed connection pool.
impl Manager {
    /// Creates a new manager.
    pub fn new(config: LdapConfig) -> Self {
        Self { config }
    }
}

impl deadpool::managed::Manager for Manager {
    type Type = LdapClient;
    type Error = crate::Error;

    /// Creates an already bound connection.
    async fn create(&self) -> Result<Self::Type, Self::Error> {
        debug!("Creating new connection");
        let ldap_client = LdapClient::new(self.config.clone()).await?;
        Ok(ldap_client)
    }

    async fn recycle(
        &self,
        client: &mut Self::Type,
        _metrics: &Metrics,
    ) -> RecycleResult<Self::Error> {
        debug!("recycling connection");
        client.unbind_ref().await?;
        Ok(())
    }
}

/// Create a new connection pool.
pub async fn build_connection_pool(
    ldap_config: LdapConfig,
    pool_size: NonZeroUsize,
) -> Result<Pool, BuildError> {
    let manager = Manager::new(ldap_config);
    let pool = Pool::builder(manager).max_size(pool_size.get()).build()?;

    Ok(pool)
}

impl LdapClient {
    /// End the LDAP connection.
    ///
    /// This unbind by reference is needed by deadpool.
    async fn unbind_ref(&mut self) -> Result<(), Error> {
        match self.ldap.unbind().await {
            Ok(_) => Ok(()),
            Err(error) => Err(Error::Close(String::from("Failed to unbind"), error)),
        }
    }
}
