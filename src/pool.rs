use async_trait::async_trait;
use deadpool::managed::{Metrics, RecycleResult};
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings};
use log::debug;
use serde::Deserialize;

use crate::{Error, LdapClient};

pub struct Manager(String, LdapConnSettings);
pub type Pool = deadpool::managed::Pool<Manager>;

/// LDAP Manager for the `deadpool` managed connection pool.
impl Manager {
    /// Creates a new manager with the given URL.
    /// URL can be anything that can go Into a String (e.g. String or &str)
    pub fn new<S: Into<String>>(ldap_url: S) -> Self {
        Self(ldap_url.into(), LdapConnSettings::new())
    }

    /// Set a custom LdapConnSettings object on the manager.
    /// Returns a copy of the Manager.
    pub fn with_connection_settings(mut self, settings: LdapConnSettings) -> Self {
        self.1 = settings;
        self
    }
}

#[async_trait]
impl deadpool::managed::Manager for Manager {
    type Type = Ldap;
    type Error = ldap3::LdapError;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        debug!("Creating new connection");
        let (conn, ldap) = LdapConnAsync::with_settings(self.1.clone(), &self.0).await?;
        ldap3::drive!(conn);
        Ok(ldap)
    }

    async fn recycle(
        &self,
        conn: &mut Self::Type,
        _metrics: &Metrics,
    ) -> RecycleResult<Self::Error> {
        debug!("recycling connection");
        conn.simple_bind("", "").await?;
        Ok(())
    }
}

pub async fn build_connection_pool(ldap_config: &LdapConfig) -> LdapPool {
    let manager = Manager::new(&ldap_config.ldap_url);
    let pool = Pool::builder(manager)
        .max_size(ldap_config.pool_size)
        .build()
        .unwrap();
    LdapPool {
        pool,
        config: ldap_config.clone(),
    }
}

pub struct LdapPool {
    pool: Pool,
    config: LdapConfig,
}

impl LdapPool {
    /// Returns an existing LDAP connection from the pool or creates a new one if required.
    pub async fn get_connection(&self) -> Result<LdapClient, Error> {
        let mut ldap = self.pool.get().await.map_err(Error::Pool)?;
        ldap.simple_bind(self.config.bind_dn.as_str(), self.config.bind_pw.as_str())
            .await
            .map_err(|e| Error::Connection("unable to create connection".into(), e))?
            .success()
            .map_err(|e| Error::Connection("unable to create connection".into(), e))?;

        Ok(LdapClient::from(ldap, self.config.dn_attribute.clone()))
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct LdapConfig {
    pub ldap_url: String,
    pub bind_dn: String,
    pub bind_pw: String,
    pub pool_size: usize,
    pub dn_attribute: Option<String>,
}
