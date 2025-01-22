///
/// Module for LDAP connection pooling.
///
/// A single LDAP connection is able to handle multiple operations concurrently, but beyond a certain
/// point it will become a bottleneck. This is where pooling comes in.
///
/// The pool keeps multiple connections alive and gives them to you upon request (unless they're all in use.)
///

use std::num::NonZeroUsize;
use deadpool::{managed::{self, Metrics, RecycleResult}, managed_reexports};
use tracing::debug;

use crate::{Error, LdapClient, LdapConfig};

// Export the pool types.
managed_reexports!(
    "simple_ldap",
    Manager,
    managed::Object<Manager>,
    crate::Error,
    // Config cannot fail
    std::convert::Infallible
);

/// Manager for deadpool.
pub struct Manager{
    /// Configuration for creating connections.
    config: LdapConfig
}

/// LDAP Manager for the `deadpool` managed connection pool.
impl Manager {
    /// Creates a new manager.
    pub fn new(config: LdapConfig) -> Self {
        Self{
            config
        }
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
pub async fn build_connection_pool(ldap_config: LdapConfig, pool_size: NonZeroUsize) -> Result<Pool, String> {
    let manager = Manager::new(ldap_config);
    let pool = Pool::builder(manager)
        .max_size(pool_size.get())
        .build()
        .map_err(|build_err| format!("Failed to build the pool: {build_err:?}"))?;

    Ok(pool)
}

impl LdapClient {
    /// End the LDAP connection.
    ///
    /// This unbind by reference is needed by deadpool.
    async fn unbind_ref(&mut self) -> Result<(), Error> {
        match self.ldap.unbind().await {
            Ok(_) => Ok(()),
            Err(error) => Err(Error::Close(String::from("Failed to unbind"), error))
        }
    }
}
