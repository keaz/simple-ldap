//! # simple-ldap
//! This is a high-level LDAP client library created by wrapping the rust LDAP3 clinet.
//! This provides high-level functions that helps to interact with LDAP.
//!
//! # Documentation
//! * [Examples Repository](https://github.com/keaz/simple-ldap)
//!
use std::collections::{HashMap, HashSet};

use deadpool::managed::Object;
use filter::Filter;
use ldap3::{
    log::{debug, error},
    Ldap, LdapError, Mod, Scope, SearchEntry, StreamState,
};
use pool::Manager;

pub mod filter;
pub mod pool;
pub extern crate ldap3;

const LDAP_ENTRY_DN: [&str; 1] = ["entryDN"];
const NO_SUCH_RECORD: u32 = 32;
///
/// High-level LDAP client wrapper ontop of ldap3 crate. This wrapper provides a high-level interface to perform LDAP operations
/// including authentication, search, update, delete
///
///
pub struct LdapClient {
    pub ldap: Object<Manager>,
}

impl LdapClient {
    ///
    /// Returns the ldap3 client
    ///
    pub fn get_inner(&self) -> Ldap {
        self.ldap.clone()
    }
}

impl LdapClient {
    fn from(ldap: Object<Manager>) -> Self {
        LdapClient { ldap }
    }

    pub async fn unbind(&mut self) -> Result<(), String> {
        match self.ldap.unbind().await {
            Ok(_) => Ok(()),
            Err(error) => Err(format!("Failed to unbind {:?}", error)),
        }
    }

    ///
    /// The user is authenticated by searching for the user in the LDAP server.
    /// The search is performed using the provided filter. The filter should be a filter that matches a single user.
    ///
    /// # Arguments
    /// * `base` - The base DN to search for the user
    /// * `uid` - The uid of the user
    /// * `password` - The password of the user
    /// * `filter` - The filter to search for the user
    ///
    /// # Returns
    /// * `Result<(), Error>` - Returns an error if the authentication fails
    ///
    /// # Example
    /// ```
    ///
    /// use simple_ldap::filter::EqFilter;
    /// use simple_ldap::LdapClient;
    /// use simple_ldap::pool::LdapConfig;
    ///
    /// let ldap_config = LdapConfig {
    ///     bind_dn: "cn=manager".to_string(),
    ///     bind_pw: "password".to_string(),
    ///     ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    ///     pool_size: 10,
    /// };
    ///
    /// let pool = pool::build_connection_pool(&ldap_config).await;
    /// let mut ldap = pool.get_connection().await;
    /// let name_filter = EqFilter::from("cn".to_string(), "Sam".to_string());
    ///
    /// let result = ldap.authenticate("", "Sam", "password", Box::new(name_filter)).await;
    /// ```
    pub async fn authenticate(
        &mut self,
        base: &str,
        uid: &str,
        password: &str,
        filter: Box<dyn Filter>,
    ) -> Result<(), Error> {
        let rs = self
            .ldap
            .search(
                base,
                Scope::OneLevel,
                filter.filter().as_str(),
                LDAP_ENTRY_DN,
            )
            .await
            .unwrap();
        let (data, _rs) = rs.success().unwrap();
        if data.is_empty() {
            return Err(Error::NotFound(format!("No record found {:?}", uid)));
        }

        if data.len() > 1 {
            return Err(Error::MultipleResults(format!(
                "Found multiple records for uid {:?}",
                uid
            )));
        }

        let record = data.get(0).unwrap().to_owned();
        let record = SearchEntry::construct(record);
        let result: HashMap<&str, String> = record
            .attrs
            .iter()
            .filter(|(_, value)| !value.is_empty())
            .map(|(arrta, value)| (arrta.as_str(), value.get(0).unwrap().clone()))
            .collect();

        let entry_dn = result.get("entryDN").unwrap();

        let result = self.ldap.simple_bind(entry_dn, password).await;
        if result.is_err() {
            return Err(Error::AuthenticationFailed(format!(
                "Error authenticating user: {:?}",
                uid
            )));
        }

        let result = result.unwrap().success();
        if result.is_err() {
            return Err(Error::AuthenticationFailed(format!(
                "Error authenticating user: {:?}",
                uid
            )));
        }

        Ok(())
    }

    async fn search_innter(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &dyn Filter,
        attributes: Vec<&str>,
    ) -> Result<SearchEntry, Error> {
        let search = self
            .ldap
            .search(base, scope, filter.filter().as_str(), attributes)
            .await;
        if let Err(error) = search {
            return Err(Error::Query(
                format!("Error searching for record: {:?}", error),
                error,
            ));
        }
        let result = search.unwrap().success();
        if let Err(error) = result {
            return Err(Error::Query(
                format!("Error searching for record: {:?}", error),
                error,
            ));
        }

        let records = result.unwrap().0;

        if records.len() > 1 {
            return Err(Error::MultipleResults(format!(
                "Found multiple records for the search criteria"
            )));
        }

        if records.len() == 0 {
            return Err(Error::NotFound(format!(
                "No records found for the search criteria"
            )));
        }

        let record = records.get(0).unwrap();

        Ok(SearchEntry::construct(record.to_owned()))
    }

    ///
    /// Search a single value from the LDAP server. The search is performed using the provided filter.
    /// The filter should be a filter that matches a single record. if the filter matches multiple users, an error is returned.
    /// This operatrion is useful when records has single value attributes.
    /// Result will be mapped to a struct of type T.
    ///
    /// # Arguments
    /// * `base` - The base DN to search for the user
    /// * `scope` - The scope of the search
    /// * `filter` - The filter to search for the user
    /// * `attributes` - The attributes to return from the search
    ///
    /// # Returns
    /// * `Result<T, Error>` - The result will be mapped to a struct of type T
    ///
    /// # Example
    /// ```
    /// use simple_ldap::filter::EqFilter;
    /// use simple_ldap::LdapClient;
    /// use simple_ldap::pool::LdapConfig;
    ///
    /// let ldap_config = LdapConfig {
    ///     bind_dn: "cn=manager".to_string(),
    ///     bind_pw: "password".to_string(),
    ///     ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    ///     pool_size: 10,
    /// };
    ///
    /// let pool = pool::build_connection_pool(&ldap_config).await;
    /// let mut ldap = pool.get_connection().await;
    ///
    /// let name_filter = EqFilter::from("cn".to_string(), "Sam".to_string());
    /// let user = ldap
    /// .search::<User>(
    ///    "ou=people,dc=example,dc=com",
    ///    self::ldap3::Scope::OneLevel,
    ///    &name_filter,
    ///    vec!["cn", "sn", "uid"],
    /// ).await;
    ///
    /// ```
    ///
    pub async fn search<T: for<'a> serde::Deserialize<'a>>(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &dyn Filter,
        attributes: Vec<&str>,
    ) -> Result<T, Error> {
        let search_entry = self.search_innter(base, scope, filter, attributes).await?;

        let json = LdapClient::create_json_signle_value(search_entry)?;
        LdapClient::map_to_struct(json)
    }

    ///
    /// Search a single value from the LDAP server. The search is performed using the provided filter.
    /// The filter should be a filter that matches a single record. if the filter matches multiple users, an error is returned.
    /// This operatrion is useful when records has multi-valued attributes.
    ///
    /// # Arguments
    /// * `base` - The base DN to search for the user
    /// * `scope` - The scope of the search
    /// * `filter` - The filter to search for the user
    /// * `attributes` - The attributes to return from the search
    ///
    /// # Returns
    /// * `Result<T, Error>` - The result will be mapped to a struct of type T
    ///
    /// # Example
    /// ```
    /// use simple_ldap::filter::EqFilter;
    /// use simple_ldap::LdapClient;
    /// use simple_ldap::pool::LdapConfig;
    ///
    ///
    /// #[derive(Debug, Deserialize)]
    /// struct TestMultiValued {
    ///    key1: Vec<String>,
    ///    key2: Vec<String>,
    /// }
    ///
    /// let ldap_config = LdapConfig {
    ///     bind_dn: "cn=manager".to_string(),
    ///     bind_pw: "password".to_string(),
    ///     ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    ///     pool_size: 10,
    /// };
    ///
    /// let pool = pool::build_connection_pool(&ldap_config).await;
    /// let mut ldap = pool.get_connection().await;
    ///
    /// let name_filter = EqFilter::from("cn".to_string(), "Sam".to_string());
    /// let user = ldap.search_multi_valued::<TestMultiValued>("", self::ldap3::Scope::OneLevel, &name_filter, vec!["cn", "sn", "uid"]).await;
    ///
    /// ```
    ///
    pub async fn search_multi_valued<T: for<'a> serde::Deserialize<'a>>(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &dyn Filter,
        attributes: Vec<&str>,
    ) -> Result<T, Error> {
        let search_entry = self.search_innter(base, scope, filter, attributes).await?;
        let json = LdapClient::create_json_multi_value(search_entry)?;

        LdapClient::map_to_struct(json)
    }

    fn map_to_struct<T: for<'a> serde::Deserialize<'a>>(json: String) -> Result<T, Error> {
        let result: Result<T, serde_json::Error> = serde_json::from_str(&json);
        match result {
            Ok(result) => Ok(result),
            Err(error) => Err(Error::Mapping(format!(
                "Error converting search result to object: {:?}",
                error
            ))),
        }
    }

    fn create_json_signle_value(search_entry: SearchEntry) -> Result<String, Error> {
        let result: HashMap<&str, Option<&String>> = search_entry
            .attrs
            .iter()
            .filter(|(_, value)| !value.is_empty())
            .map(|(arrta, value)| (arrta.as_str(), value.get(0).to_owned()))
            .collect();
        let json = serde_json::to_string(&result);
        match json {
            Ok(json) => Ok(json),
            Err(error) => Err(Error::Mapping(format!(
                "Error converting search result to json: {:?}",
                error
            ))),
        }
    }

    fn create_json_multi_value(search_entry: SearchEntry) -> Result<String, Error> {
        let result: HashMap<&str, Vec<String>> = search_entry
            .attrs
            .iter()
            .filter(|(_, value)| !value.is_empty())
            .map(|(arrta, value)| (arrta.as_str(), value.to_owned()))
            .collect();

        let json = serde_json::to_string(&result);
        match json {
            Ok(json) => Ok(json),
            Err(error) => Err(Error::Mapping(format!(
                "Error converting search result to json: {:?}",
                error
            ))),
        }
    }

    async fn streaming_search_inner(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &dyn Filter,
        limit: i32,
        attributes: Vec<&str>,
    ) -> Result<Vec<SearchEntry>, Error> {
        let search_stream = self
            .ldap
            .streaming_search(base, scope, filter.filter().as_str(), attributes)
            .await;
        if let Err(error) = search_stream {
            return Err(Error::Query(
                format!("Error searching for record: {:?}", error),
                error,
            ));
        }
        let mut search_stream = search_stream.unwrap();

        let mut entries = Vec::new();
        let mut count = 0;

        loop {
            let next = search_stream.next().await;
            if next.is_err() {
                break;
            }

            if search_stream.state() != StreamState::Active {
                break;
            }

            let entry = next.unwrap();
            if entry.is_none() {
                break;
            }
            if let Some(entry) = entry {
                entries.push(SearchEntry::construct(entry));
                count += 1;
            }

            if count == limit {
                break;
            }
        }

        let _res = search_stream.finish().await;
        let msgid = search_stream.ldap_handle().last_id();
        self.ldap.abandon(msgid).await.unwrap();

        Ok(entries)
    }

    ///
    /// This method is used to search multiple records from the LDAP server. The search is performed using the provided filter.
    /// Method will return a vector of structs of type T. return vector will be maximum of the limit provided.
    ///
    /// # Arguments
    /// * `base` - The base DN to search for the user
    /// * `scope` - The scope of the search
    /// * `filter` - The filter to search for the user
    /// * `limit` - The maximum number of records to return
    /// * `attributes` - The attributes to return from the search
    ///
    /// # Returns
    /// * `Result<T, Error>` - The result will be mapped to a struct of type T
    ///
    /// # Example
    /// ```
    /// use simple_ldap::filter::EqFilter;
    /// use simple_ldap::LdapClient;
    /// use simple_ldap::pool::LdapConfig;
    ///
    ///
    /// #[derive(Debug, Deserialize)]
    /// struct TestMultiValued {
    ///    key1: Vec<String>,
    ///    key2: Vec<String>,
    /// }
    ///
    /// let ldap_config = LdapConfig {
    ///     bind_dn: "cn=manager".to_string(),
    ///     bind_pw: "password".to_string(),
    ///     ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    ///     pool_size: 10,
    /// };
    ///
    /// let pool = pool::build_connection_pool(&ldap_config).await;
    /// let mut ldap = pool.get_connection().await;
    ///
    /// let name_filter = EqFilter::from("cn".to_string(), "Sam".to_string());
    /// let user = ldap.streaming_search::<User>("", self::ldap3::Scope::OneLevel, &name_filter, 2, vec!["cn", "sn", "uid"]).await;
    ///
    /// ```
    pub async fn streaming_search<T: for<'a> serde::Deserialize<'a>>(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &dyn Filter,
        limit: i32,
        attributes: Vec<&str>,
    ) -> Result<Vec<T>, Error> {
        let entries = self
            .streaming_search_inner(base, scope, filter, limit, attributes)
            .await?;

        if entries.is_empty() {
            return Ok(Vec::new());
        }

        let jsons = entries
            .iter()
            .map(|entry| LdapClient::create_json_signle_value(entry.to_owned()).unwrap())
            .collect::<Vec<String>>();

        let data = jsons
            .iter()
            .map(|json| LdapClient::map_to_struct::<T>(json.to_owned()).unwrap())
            .collect::<Vec<T>>();

        Ok(data)
    }

    ///
    /// This method is used to search multiple records from the LDAP server. The search is performed using the provided filter.
    /// This operatrion is useful when records has single value attributes.
    /// Method will return a vector of structs of type T. return vector will be maximum of the limit provided.
    ///
    /// # Arguments
    /// * `base` - The base DN to search for the user
    /// * `scope` - The scope of the search
    /// * `filter` - The filter to search for the user
    /// * `limit` - The maximum number of records to return
    /// * `attributes` - The attributes to return from the search
    ///
    /// # Returns
    /// * `Result<T, Error>` - The result will be mapped to a struct of type T
    ///
    /// # Example
    /// ```
    /// use simple_ldap::filter::EqFilter;
    /// use simple_ldap::LdapClient;
    /// use simple_ldap::pool::LdapConfig;
    ///
    ///
    /// #[derive(Debug, Deserialize)]
    /// struct TestMultiValued {
    ///    key1: Vec<String>,
    ///    key2: Vec<String>,
    /// }
    ///
    /// let ldap_config = LdapConfig {
    ///     bind_dn: "cn=manager".to_string(),
    ///     bind_pw: "password".to_string(),
    ///     ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    ///     pool_size: 10,
    /// };
    ///
    /// let pool = pool::build_connection_pool(&ldap_config).await;
    /// let mut ldap = pool.get_connection().await;
    ///
    /// let name_filter = EqFilter::from("cn".to_string(), "Sam".to_string());
    /// let user = ldap.streaming_search_multi_valued::<TestMultiValued>("", self::ldap3::Scope::OneLevel, &name_filter, 2, vec!["cn", "sn", "uid"]).await;
    ///
    /// ```
    pub async fn streaming_search_multi_valued<T: for<'a> serde::Deserialize<'a>>(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &dyn Filter,
        limit: i32,
        attributes: Vec<&str>,
    ) -> Result<Vec<T>, Error> {
        let entries = self
            .streaming_search_inner(base, scope, filter, limit, attributes)
            .await?;

        let jsons = entries
            .iter()
            .map(|entry| LdapClient::create_json_multi_value(entry.to_owned()).unwrap())
            .collect::<Vec<String>>();

        let data = jsons
            .iter()
            .map(|json| LdapClient::map_to_struct::<T>(json.to_owned()).unwrap())
            .collect::<Vec<T>>();

        Ok(data)
    }

    ///
    /// Create a new record in the LDAP server. The record will be created in the provided base DN.
    ///
    /// # Arguments
    /// * `uid` - The uid of the record
    /// * `base` - The base DN to create the record
    /// * `data` - The attributes of the record
    ///
    /// # Returns
    /// * `Result<(), Error>` - Returns an error if the record creation fails
    ///
    /// # Example
    /// ```
    /// use simple_ldap::LdapClient;
    /// use simple_ldap::pool::LdapConfig;
    ///
    /// let ldap_config = LdapConfig {
    ///     bind_dn: "cn=manager".to_string(),
    ///     bind_pw: "password".to_string(),
    ///     ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    ///     pool_size: 10,
    /// };
    ///
    /// let pool = pool::build_connection_pool(&ldap_config).await;
    /// let mut ldap = pool.get_connection().await;
    ///
    /// let data = vec![
    ///     ( "objectClass",HashSet::from(["organizationalPerson", "inetorgperson", "top", "person"]),),
    ///     ("uid",HashSet::from(["bd9b91ec-7a69-4166-bf67-cc7e553b2fd9"]),),
    ///     ("cn", HashSet::from(["Kasun"])),
    ///     ("sn", HashSet::from(["Ranasingh"])),
    /// ];
    ///
    /// let result = ldap.create("bd9b91ec-7a69-4166-bf67-cc7e553b2fd9", "ou=people,dc=example,dc=com", data).await;
    ///
    /// ```
    ///
    pub async fn create(
        &mut self,
        uid: &str,
        base: &str,
        data: Vec<(&str, HashSet<&str>)>,
    ) -> Result<(), Error> {
        let dn = format!("uid={},{}", uid, base);
        let save = self.ldap.add(dn.as_str(), data).await;
        if let Err(err) = save {
            return Err(Error::Create(
                format!("Error saving record: {:?}", err),
                err,
            ));
        }
        let save = save.unwrap().success();

        if let Err(err) = save {
            return Err(Error::Create(
                format!("Error saving record: {:?}", err),
                err,
            ));
        }
        let res = save.unwrap();
        debug!("Sucessfully created record result: {:?}", res);
        Ok(())
    }

    ///
    /// Update a record in the LDAP server. The record will be updated in the provided base DN.
    ///
    /// # Arguments
    /// * `uid` - The uid of the record
    /// * `base` - The base DN to update the record
    /// * `data` - The attributes of the record
    /// * `new_uid` - The new uid of the record. If the new uid is provided, the uid of the record will be updated.
    ///
    /// # Returns
    /// * `Result<(), Error>` - Returns an error if the record update fails
    ///
    /// # Example
    /// ```
    /// use simple_ldap::LdapClient;
    /// use simple_ldap::pool::LdapConfig;
    ///
    /// let ldap_config = LdapConfig {
    ///     bind_dn: "cn=manager".to_string(),
    ///     bind_pw: "password".to_string(),
    ///     ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    ///     pool_size: 10,
    /// };
    ///
    /// let pool = pool::build_connection_pool(&ldap_config).await;
    /// let mut ldap = pool.get_connection().await;
    ///
    /// let data = vec![
    ///     Mod::Replace("cn", HashSet::from(["Jhon_Update"])),
    ///     Mod::Replace("sn", HashSet::from(["Eliet_Update"])),
    /// ];
    ///
    /// let result = ldap.update("e219fbc0-6df5-4bc3-a6ee-986843bb157e", "ou=people,dc=example,dc=com", data, Option::None).await;
    ///
    /// ```
    pub async fn update(
        &mut self,
        uid: &str,
        base: &str,
        data: Vec<Mod<&str>>,
        new_uid: Option<&str>,
    ) -> Result<(), Error> {
        let dn = format!("uid={},{}", uid, base);

        let res = self.ldap.modify(dn.as_str(), data).await;
        if let Err(err) = res {
            return Err(Error::Update(
                format!("Error updating record: {:?}", err),
                err,
            ));
        }

        let res = res.unwrap().success();
        if let Err(err) = res {
            match err {
                LdapError::LdapResult { result } => {
                    if result.rc == NO_SUCH_RECORD {
                        return Err(Error::NotFound(format!(
                            "No records found for the uid: {:?}",
                            uid
                        )));
                    }
                }
                _ => {
                    return Err(Error::Update(
                        format!("Error updating record: {:?}", err),
                        err,
                    ));
                }
            }
        }

        if new_uid.is_none() {
            return Ok(());
        }

        let new_uid = new_uid.unwrap();
        if !uid.eq_ignore_ascii_case(new_uid) {
            let new_dn = format!("uid={}", new_uid);
            let dn_update = self
                .ldap
                .modifydn(dn.as_str(), new_dn.as_str(), true, None)
                .await;
            if let Err(err) = dn_update {
                error!("Failed to update dn for record {:?} error {:?}", uid, err);
                return Err(Error::Update(
                    format!("Failed to update dn for record {:?}", uid),
                    err,
                ));
            }

            let dn_update = dn_update.unwrap().success();
            if let Err(err) = dn_update {
                error!("Failed to update dn for record {:?} error {:?}", uid, err);
                return Err(Error::Update(
                    format!("Failed to update dn for record {:?}", uid),
                    err,
                ));
            }

            let res = dn_update.unwrap();
            debug!("Sucessfully updated dn result: {:?}", res);
        }

        Ok(())
    }

    ///
    /// Delete a record in the LDAP server. The record will be deleted in the provided base DN.
    ///
    /// # Arguments
    /// * `uid` - The uid of the record
    /// * `base` - The base DN to delete the record
    ///
    /// # Returns
    /// * `Result<(), Error>` - Returns an error if the record delete fails
    ///
    /// # Example
    /// ```
    /// use simple_ldap::LdapClient;
    /// use simple_ldap::pool::LdapConfig;
    ///
    /// let ldap_config = LdapConfig {
    ///     bind_dn: "cn=manager".to_string(),
    ///     bind_pw: "password".to_string(),
    ///     ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    ///     pool_size: 10,
    /// };
    ///
    /// let pool = pool::build_connection_pool(&ldap_config).await;
    /// let mut ldap = pool.get_connection().await;
    ///
    /// let result = ldap.delete("e219fbc0-6df5-4bc3-a6ee-986843bb157e", "ou=people,dc=example,dc=com").await;
    ///
    /// ```
    pub async fn delete(&mut self, uid: &str, base: &str) -> Result<(), Error> {
        let dn = format!("uid={},{}", uid, base);
        let delete = self.ldap.delete(dn.as_str()).await;

        if let Err(err) = delete {
            return Err(Error::Delete(
                format!("Error deleting record: {:?}", err),
                err,
            ));
        }
        let delete = delete.unwrap().success();
        if let Err(err) = delete {
            match err {
                LdapError::LdapResult { result } => {
                    if result.rc == NO_SUCH_RECORD {
                        return Err(Error::NotFound(format!(
                            "No records found for the uid: {:?}",
                            uid
                        )));
                    }
                }
                _ => {
                    return Err(Error::Delete(
                        format!("Error deleting record: {:?}", err),
                        err,
                    ));
                }
            }
        }
        debug!("Sucessfully deleted record result: {:?}", uid);
        Ok(())
    }
}

///
/// The error type for the LDAP client
///
#[derive(Debug)]
pub enum Error {
    ///
    /// Error occured when performing a LDAP query
    Query(String, LdapError),
    /// No records found for the search criteria
    NotFound(String),
    /// Multiple records found for the search criteria
    MultipleResults(String),
    /// Authentication failed
    AuthenticationFailed(String),
    /// Error occured when creating a record
    Create(String, LdapError),
    /// Error occured when updating a record
    Update(String, LdapError),
    /// Error occured when deleting a record
    Delete(String, LdapError),
    /// Error occured when mapping the search result to a struct
    Mapping(String),
}

#[cfg(test)]
mod tests {
    use ldap3::tokio;
    use serde::Deserialize;

    use crate::{filter::EqFilter, pool::LdapConfig};

    use super::*;

    #[test]
    fn create_json_multi_value_test() {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        map.insert(
            "key1".to_string(),
            vec!["value1".to_string(), "value2".to_string()],
        );
        map.insert(
            "key2".to_string(),
            vec!["value3".to_string(), "value4".to_string()],
        );
        let entry = SearchEntry {
            dn: "dn".to_string(),
            attrs: map,
            bin_attrs: HashMap::new(),
        };

        let json = LdapClient::create_json_multi_value(entry).unwrap();
        let test = LdapClient::map_to_struct::<TestMultiValued>(json);
        assert!(test.is_ok());
        let test = test.unwrap();
        assert_eq!(test.key1, vec!["value1".to_string(), "value2".to_string()]);
        assert_eq!(test.key2, vec!["value3".to_string(), "value4".to_string()]);
    }

    #[test]
    fn create_json_single_value_test() {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        map.insert("key1".to_string(), vec!["value1".to_string()]);
        map.insert("key2".to_string(), vec!["value2".to_string()]);
        let entry = SearchEntry {
            dn: "dn".to_string(),
            attrs: map,
            bin_attrs: HashMap::new(),
        };

        let json = LdapClient::create_json_signle_value(entry).unwrap();
        let test = LdapClient::map_to_struct::<TestSingleValued>(json);
        assert!(test.is_ok());
        let test = test.unwrap();
        assert_eq!(test.key1, "value1".to_string());
        assert_eq!(test.key2, "value2".to_string());
    }

    #[derive(Debug, Deserialize)]
    struct TestMultiValued {
        key1: Vec<String>,
        key2: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    struct TestSingleValued {
        key1: String,
        key2: String,
    }

    #[tokio::test]
    async fn test_create_record() {
        let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;

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
        let result = pool
            .get_connection()
            .await
            .create(
                "bd9b91ec-7a69-4166-bf67-cc7e553b2fd9",
                "ou=people,dc=example,dc=com",
                data,
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_search_record() {
        let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let mut ldap = pool.get_connection().await;
        let name_filter = EqFilter::from("cn".to_string(), "Sam".to_string());
        let user = ldap
            .search::<User>(
                "ou=people,dc=example,dc=com",
                self::ldap3::Scope::OneLevel,
                &name_filter,
                vec!["cn", "sn", "uid"],
            )
            .await;
        assert!(user.is_ok());
        let user = user.unwrap();
        assert_eq!(user.cn, "Sam");
        assert_eq!(user.sn, "Smith");
    }

    #[tokio::test]
    async fn test_search_no_record() {
        let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let mut ldap = pool.get_connection().await;
        let name_filter = EqFilter::from("cn".to_string(), "SamX".to_string());
        let user = ldap
            .search::<User>(
                "ou=people,dc=example,dc=com",
                self::ldap3::Scope::OneLevel,
                &name_filter,
                vec!["cn", "sn", "uid"],
            )
            .await;
        assert!(user.is_err());
        let er = user.err().unwrap();
        match er {
            Error::NotFound(_) => assert!(true),
            _ => assert!(false),
        }
    }

    #[tokio::test]
    async fn test_search_multiple_record() {
        let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let mut ldap = pool.get_connection().await;
        let name_filter = EqFilter::from("cn".to_string(), "James".to_string());
        let user = ldap
            .search::<User>(
                "ou=people,dc=example,dc=com",
                self::ldap3::Scope::OneLevel,
                &name_filter,
                vec!["cn", "sn", "uid"],
            )
            .await;
        assert!(user.is_err());
        let er = user.err().unwrap();
        match er {
            Error::MultipleResults(_) => assert!(true),
            _ => assert!(false),
        }
    }

    #[tokio::test]
    async fn test_update_record() {
        let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let mut ldap = pool.get_connection().await;
        let data = vec![
            Mod::Replace("cn", HashSet::from(["Jhon_Update"])),
            Mod::Replace("sn", HashSet::from(["Eliet_Update"])),
        ];
        let result = ldap
            .update(
                "e219fbc0-6df5-4bc3-a6ee-986843bb157e",
                "ou=people,dc=example,dc=com",
                data,
                Option::None,
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_update_no_record() {
        let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let mut ldap = pool.get_connection().await;
        let data = vec![
            Mod::Replace("cn", HashSet::from(["Jhon_Update"])),
            Mod::Replace("sn", HashSet::from(["Eliet_Update"])),
        ];
        let result = ldap
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
    }

    #[tokio::test]
    async fn test_update_uid_record() {
        let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let mut ldap = pool.get_connection().await;
        let data = vec![
            Mod::Replace("cn", HashSet::from(["David_Update"])),
            Mod::Replace("sn", HashSet::from(["Hanks_Update"])),
        ];
        let result = ldap
            .update(
                "cb4bc91e-21d8-4bcc-bf6a-317b84c2e58b",
                "ou=people,dc=example,dc=com",
                data,
                Option::Some("6da70e51-7897-411f-9290-649ebfcb3269"),
            )
            .await;

        assert!(result.is_ok());

        let mut ldap = pool.get_connection().await;
        let name_filter = EqFilter::from(
            "uid".to_string(),
            "6da70e51-7897-411f-9290-649ebfcb3269".to_string(),
        );
        let user = ldap
            .search::<User>(
                "ou=people,dc=example,dc=com",
                self::ldap3::Scope::OneLevel,
                &name_filter,
                vec!["cn", "sn", "uid"],
            )
            .await;
        assert!(user.is_ok());
        let user = user.unwrap();
        assert_eq!(user.cn, "David_Update");
        assert_eq!(user.sn, "Hanks_Update");
    }

    #[tokio::test]
    async fn test_streaming_search() {
        let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let mut ldap = pool.get_connection().await;

        let name_filter = EqFilter::from("cn".to_string(), "James".to_string());
        let result = ldap
            .streaming_search::<User>(
                "ou=people,dc=example,dc=com",
                self::ldap3::Scope::OneLevel,
                &name_filter,
                2,
                vec!["cn", "sn", "uid"],
            )
            .await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.len() == 2);
    }

    #[tokio::test]
    async fn test_streaming_search_no_records() {
        let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let mut ldap = pool.get_connection().await;

        let name_filter = EqFilter::from("cn".to_string(), "JamesX".to_string());
        let result = ldap
            .streaming_search::<User>(
                "ou=people,dc=example,dc=com",
                self::ldap3::Scope::OneLevel,
                &name_filter,
                2,
                vec!["cn", "sn", "uid"],
            )
            .await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), 0);
    }

    #[tokio::test]
    async fn test_delete() {
        let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let mut ldap = pool.get_connection().await;

        let result = ldap
            .delete(
                "4d9b08fe-9a14-4df0-9831-ea9992837f0d",
                "ou=people,dc=example,dc=com",
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_no_record_delete() {
        let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let mut ldap = pool.get_connection().await;

        let result = ldap
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
    }

    #[derive(Deserialize)]
    struct User {
        pub uid: String,
        pub cn: String,
        pub sn: String,
    }
}
