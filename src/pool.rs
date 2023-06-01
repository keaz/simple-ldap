use std::{collections::HashSet, sync::Arc, time::Duration};

use ldap3::tokio::sync::Mutex;

use crate::LdapClient;

pub struct LdapPool {
    not_used: Arc<Mutex<Vec<LdapClient>>>,
    in_use: Arc<Mutex<HashSet<usize>>>,
    configuration: PoolConfiguration,
}

pub struct PoolConfiguration {
    url: String,
    bind_dn: String,
    bind_pw: String,
    pool_size: usize,
    max_size: Option<usize>,
}

pub async fn from(configuration: PoolConfiguration) -> LdapPool {
    let mut not_used = Vec::new();
    let in_use = HashSet::new();

    for i in 1..=configuration.pool_size {
        let client = LdapClient::for_pool(
            configuration.url.as_str(),
            configuration.bind_dn.as_str(),
            configuration.bind_pw.as_str(),
            i,
        )
        .await;
        not_used.push(client);
    }

    LdapPool {
        not_used: Arc::new(Mutex::new(not_used)),
        in_use: Arc::new(Mutex::new(in_use)),
        configuration,
    }
}

impl LdapPool {
    pub async fn get(&self) -> Result<LdapClient, PoolError> {
        let mut not_used = self.not_used.lock().await;
        while (not_used).len() == 0 {
            if let Some(max_pool) = self.configuration.max_size {
                let mut in_use = self.in_use.lock().await;
                let in_use_size = (*in_use).len();
                if in_use_size == max_pool {
                    return Err(PoolError::MaxPoolReached(
                        "Max pool size reached".to_string(),
                    ));
                }
                let client = LdapClient::for_pool(
                    self.configuration.url.as_str(),
                    self.configuration.bind_dn.as_str(),
                    self.configuration.bind_pw.as_str(),
                    in_use_size + 1,
                )
                .await;
                in_use.insert(client.id);
                return Ok(client);
            }
            ldap3::tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let client = not_used.pop().unwrap();
        let mut in_use = self.in_use.lock().await;
        in_use.insert(client.id);
        return Ok(client);
    }

    pub async fn put(&self, client: LdapClient) -> Result<(), PoolError> {
        let mut in_use = self.in_use.lock().await;
        let is_in_used = in_use.remove(&client.id);
        if !is_in_used {
            return Err(PoolError::UnManagedClient(
                "Client is not a managed client".to_string(),
            ));
        }
        let mut not_used = self.not_used.lock().await;
        not_used.push(client);

        Ok(())
    }
}

pub enum PoolError {
    MaxPoolReached(String),
    UnManagedClient(String),
}
