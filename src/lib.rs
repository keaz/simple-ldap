//! # simple-ldap
//! This is a high-level LDAP client library created by wrapping the rust LDAP3 clinet.
//! This provides high-level functions that helps to interact with LDAP.
//!
//! # Documentation
//! * [Examples Repository](https://github.com/keaz/simple-ldap)
//!
//! # Usage
//! Add this to your `Cargo.toml`:
//! ```toml
//! [dependencies]
//! simple-ldap = "1.4.1"
//!
//! ```
//! ## Compile time features
//! * `tls` - (Enabled by default) Enables TLS support (delegates to `ldap3`'s `tls` feature)
//! * `tls-rustls` - Enables TLS support using `rustls` (delegates to `ldap3`'s `tls-rustls` feature)
//! * `gsasl` - Enables SASL support (delegates to `ldap3`'s `gsasl` feature)
//! * `sync` - (Enabled by default) Enables synchronous support (delegates to `ldap3`'s `sync` feature)
//!
//! ## Features
//! * [x] Authentication
//! * [x] Search
//! * [x] Create
//! * [x] Update
//! * [x] Delete
//! * [x] Streaming Search
//! * [x] Streaming Search Multi Valued
//! * [x] Create Group
//! * [x] Add Users to Group
//! * [x] Delete Group
//! * [x] Remove Users from Group
//! * [x] Get Group Members
//!
use std::{
    collections::{HashMap, HashSet},
    pin::Pin,
    task::{Context, Poll},
};

use deadpool::managed::{Object, PoolError};
use filter::{AndFilter, EqFilter, Filter};
use futures::{future::BoxFuture, FutureExt};
use ldap3::{
    adapters::PagedResults,
    log::{debug, error},
    Ldap, LdapError, Mod, Scope, SearchEntry, SearchStream, StreamState,
};
use pool::Manager;

pub mod filter;
pub mod pool;
pub extern crate ldap3;

const LDAP_ENTRY_DN: &str = "entryDN";
const NO_SUCH_RECORD: u32 = 32;
///
/// High-level LDAP client wrapper ontop of ldap3 crate. This wrapper provides a high-level interface to perform LDAP operations
/// including authentication, search, update, delete
///
///
pub struct LdapClient {
    pub ldap: Object<Manager>,
    pub dn_attr: Option<String>,
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
    fn from(ldap: Object<Manager>, dn_attr: Option<String>) -> Self {
        LdapClient { ldap, dn_attr }
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
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: "cn=manager".to_string(),
    ///         bind_pw: "password".to_string(),
    ///         ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    ///         pool_size: 10,
    ///         dn_attribute: None
    ///     };
    ///     let pool = pool::build_connection_pool(&ldap_config).await;
    ///     let mut ldap = pool.get_connection().await;
    ///     let name_filter = EqFilter::from("cn".to_string(), "Sam".to_string());
    ///
    ///     let result = ldap.authenticate("", "Sam", "password", Box::new(name_filter)).await;
    /// }
    /// ```
    pub async fn authenticate(
        &mut self,
        base: &str,
        uid: &str,
        password: &str,
        filter: Box<dyn Filter>,
    ) -> Result<(), Error> {
        let attr_dn = self
            .dn_attr
            .as_ref()
            .map(|a| a.as_str())
            .unwrap_or(LDAP_ENTRY_DN);

        let rs = self
            .ldap
            .search(base, Scope::OneLevel, filter.filter().as_str(), [attr_dn])
            .await
            .map_err(|e| Error::Query("Unable to query user for authentication".into(), e))?;

        let (data, _rs) = rs
            .success()
            .map_err(|e| Error::Query("Could not find user for authentication".into(), e))?;

        if data.is_empty() {
            return Err(Error::NotFound(format!("No record found {:?}", uid)));
        }
        if data.len() > 1 {
            return Err(Error::MultipleResults(format!(
                "Found multiple records for uid {:?}",
                uid
            )));
        }

        let record = data.first().unwrap().to_owned();
        let record = SearchEntry::construct(record);
        let result: HashMap<&str, String> = record
            .attrs
            .iter()
            .filter(|(_, value)| !value.is_empty())
            .map(|(arrta, value)| (arrta.as_str(), value.first().unwrap().clone()))
            .collect();

        let entry_dn = result.get(attr_dn).ok_or_else(|| {
            Error::AuthenticationFailed(format!("Unable to retrieve DN of user {uid}"))
        })?;

        self.ldap
            .simple_bind(entry_dn, password)
            .await
            .map_err(|_| {
                Error::AuthenticationFailed(format!("Error authenticating user: {:?}", uid))
            })
            .and_then(|r| {
                r.success().map_err(|_| {
                    Error::AuthenticationFailed(format!("Error authenticating user: {:?}", uid))
                })
            })
            .and(Ok(()))
    }

    async fn search_innter(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &(impl Filter + ?Sized),
        attributes: &Vec<&str>,
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
            return Err(Error::MultipleResults(String::from(
                "Found multiple records for the search criteria",
            )));
        }

        if records.is_empty() {
            return Err(Error::NotFound(String::from(
                "No records found for the search criteria",
            )));
        }

        let record = records.first().unwrap();

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
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: "cn=manager".to_string(),
    ///         bind_pw: "password".to_string(),
    ///         ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    ///         pool_size: 10,
    ///         dn_attribute: None
    ///     };
    ///
    ///     let pool = pool::build_connection_pool(&ldap_config).await;
    ///     let mut ldap = pool.get_connection().await;
    ///
    ///     let name_filter = EqFilter::from("cn".to_string(), "Sam".to_string());
    ///     let user = ldap
    ///         .search::<User>(
    ///         "ou=people,dc=example,dc=com",
    ///         self::ldap3::Scope::OneLevel,
    ///         &name_filter,
    ///         vec!["cn", "sn", "uid"],
    ///         ).await;
    /// }
    /// ```
    ///
    pub async fn search<T: for<'a> serde::Deserialize<'a>>(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &impl Filter,
        attributes: &Vec<&str>,
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
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: "cn=manager".to_string(),
    ///         bind_pw: "password".to_string(),
    ///         ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    ///         pool_size: 10,
    ///         dn_attribute: None
    ///     };
    ///
    ///     let pool = pool::build_connection_pool(&ldap_config).await;
    ///     let mut ldap = pool.get_connection().await;
    ///
    ///     let name_filter = EqFilter::from("cn".to_string(), "Sam".to_string());
    ///     let user = ldap.search_multi_valued::<TestMultiValued>("", self::ldap3::Scope::OneLevel, &name_filter, vec!["cn", "sn", "uid"]).await;
    /// }
    /// ```
    ///
    pub async fn search_multi_valued<T: for<'a> serde::Deserialize<'a>>(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &impl Filter,
        attributes: &Vec<&str>,
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
            .map(|(arrta, value)| (arrta.as_str(), value.first().to_owned()))
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

    async fn streaming_search_inner<'a>(
        mut self,
        base: &'a str,
        scope: Scope,
        filter: &'a (impl Filter + ?Sized),
        attributes: &'a Vec<&'a str>,
    ) -> Result<Stream<'a, &'a str, &'a Vec<&'a str>>, Error> {
        let search_stream: Result<SearchStream<'_, &str, &Vec<&str>>, LdapError> = self
            .ldap
            .streaming_search(base, scope, filter.filter().as_str(), attributes)
            .await;
        if let Err(error) = search_stream {
            return Err(Error::Query(
                format!("Error searching for record: {:?}", error),
                error,
            ));
        }

        let search_stream = search_stream.unwrap();

        let stream = Stream::new(self.ldap, search_stream);
        Ok(stream)
    }

    ///
    /// This method is used to search multiple records from the LDAP server. The search is performed using the provided filter.
    /// Method will return a Stream. The stream can be used to iterate through the search results.
    ///
    /// # Arguments
    /// * `base` - The base DN to search for the user
    /// * `scope` - The scope of the search
    /// * `filter` - The filter to search for the user
    /// * `attributes` - The attributes to return from the search
    ///
    /// # Returns
    /// * `Result<Stream, Error>` - The result will be mapped to a Stream.
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
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: "cn=manager".to_string(),
    ///         bind_pw: "password".to_string(),
    ///         ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    ///         pool_size: 10,
    ///         dn_attribute: None
    ///     };
    ///
    ///     let pool = pool::build_connection_pool(&ldap_config).await;
    ///     let mut ldap = pool.get_connection().await;
    ///
    ///     let name_filter = EqFilter::from("cn".to_string(), "Sam".to_string());
    ///     let user = ldap.streaming_search::<User>("", self::ldap3::Scope::OneLevel, &name_filter,vec!["cn", "sn", "uid"]).await;
    /// }
    /// ```
    pub async fn streaming_search<'a>(
        self,
        base: &'a str,
        scope: Scope,
        filter: &'a impl Filter,
        attributes: &'a Vec<&'a str>,
    ) -> Result<Stream<'a, &'a str, &'a Vec<&'a str>>, Error> {
        let entry = self
            .streaming_search_inner(base, scope, filter, attributes)
            .await?;

        Ok(entry)
    }

    ///
    /// This method is used to search multiple records from the LDAP server and results will be pageinated.
    /// Method will return a Stream. The stream can be used to iterate through the search results.
    ///
    /// # Arguments
    /// * `base` - The base DN to search for the user
    /// * `scope` - The scope of the search
    /// * `filter` - The filter to search for the user
    /// * `page_size` - The maximum number of records in a page
    /// * `attributes` - The attributes to return from the search
    ///
    /// # Returns
    /// * `Result<Stream, Error>` - A stream that can be used to iterate through the search results.
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
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: "cn=manager".to_string(),
    ///         bind_pw: "password".to_string(),
    ///         ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    ///         pool_size: 10,
    ///         dn_attribute: None
    ///     };
    ///
    ///     let pool = pool::build_connection_pool(&ldap_config).await;
    ///     let mut ldap = pool.get_connection().await;
    ///
    ///     let name_filter = EqFilter::from("cn".to_string(), "Sam".to_string());
    ///     let user = ldap.streaming_search::<User>("", self::ldap3::Scope::OneLevel, &name_filter, 3, vec!["cn", "sn", "uid"]).await;
    /// }
    /// ```
    pub async fn streaming_search_with<'a>(
        mut self,
        base: &'a str,
        scope: Scope,
        filter: &'a (impl Filter + ?Sized),
        attributes: &'a Vec<&'a str>,
        page_size: i32,
    ) -> Result<Stream<'a, &'a str, &'a Vec<&'a str>>, Error> {
        let search_stream = self
            .ldap
            .streaming_search_with(
                PagedResults::new(page_size),
                base,
                scope,
                filter.filter().as_str(),
                attributes,
            )
            .await;

        if let Err(error) = search_stream {
            return Err(Error::Query(
                format!("Error searching for record: {:?}", error),
                error,
            ));
        }

        let search_stream = search_stream.unwrap();

        let stream = Stream::new(self.ldap, search_stream);
        Ok(stream)
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
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: "cn=manager".to_string(),
    ///         bind_pw: "password".to_string(),
    ///         ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    ///         pool_size: 10,
    ///         dn_attribute: None
    ///     };
    ///
    ///     let pool = pool::build_connection_pool(&ldap_config).await;
    ///     let mut ldap = pool.get_connection().await;
    ///
    ///     let data = vec![
    ///         ( "objectClass",HashSet::from(["organizationalPerson", "inetorgperson", "top", "person"]),),
    ///         ("uid",HashSet::from(["bd9b91ec-7a69-4166-bf67-cc7e553b2fd9"]),),
    ///         ("cn", HashSet::from(["Kasun"])),
    ///         ("sn", HashSet::from(["Ranasingh"])),
    ///     ];
    ///
    ///     let result = ldap.create("bd9b91ec-7a69-4166-bf67-cc7e553b2fd9", "ou=people,dc=example,dc=com", data).await;
    /// }
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
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: "cn=manager".to_string(),
    ///         bind_pw: "password".to_string(),
    ///         ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    ///         pool_size: 10,
    ///         dn_attribute: None
    ///     };
    ///
    ///     let pool = pool::build_connection_pool(&ldap_config).await;
    ///     let mut ldap = pool.get_connection().await;
    ///
    ///     let data = vec![
    ///         Mod::Replace("cn", HashSet::from(["Jhon_Update"])),
    ///         Mod::Replace("sn", HashSet::from(["Eliet_Update"])),
    ///     ];
    ///
    ///     let result = ldap.update("e219fbc0-6df5-4bc3-a6ee-986843bb157e", "ou=people,dc=example,dc=com", data, Option::None).await;
    /// }
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
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: "cn=manager".to_string(),
    ///         bind_pw: "password".to_string(),
    ///         ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    ///         pool_size: 10,
    ///         dn_attribute: None
    ///     };
    ///
    ///     let pool = pool::build_connection_pool(&ldap_config).await;
    ///     let mut ldap = pool.get_connection().await;
    ///
    ///     let result = ldap.delete("e219fbc0-6df5-4bc3-a6ee-986843bb157e", "ou=people,dc=example,dc=com").await;
    /// }
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

    ///
    /// Create a new group in the LDAP server. The group will be created in the provided base DN.
    ///
    /// # Arguments
    /// * `group_name` - The name of the group
    /// * `group_ou` - The ou of the group
    /// * `description` - The description of the group
    ///
    /// # Returns
    /// * `Result<(), Error>` - Returns an error if the group creation fails
    ///
    /// # Example
    /// ```
    /// use simple_ldap::LdapClient;
    /// use simple_ldap::pool::LdapConfig;
    ///
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: "cn=manager".to_string(),
    ///         bind_pw: "password".to_string(),
    ///         ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    ///         pool_size: 10,
    ///         dn_attribute: None
    ///     };
    ///
    ///     let pool = pool::build_connection_pool(&ldap_config).await;
    ///     let mut ldap = pool.get_connection().await;
    ///
    ///     let result = ldap.create_group("test_group", "ou=groups,dc=example,dc=com", "test group").await;
    /// }
    /// ```
    pub async fn create_group(
        &mut self,
        group_name: &str,
        group_ou: &str,
        description: &str,
    ) -> Result<(), Error> {
        let dn = format!("cn={},{}", group_name, group_ou);

        let data = vec![
            ("objectClass", HashSet::from(["top", "groupOfNames"])),
            ("cn", HashSet::from([group_name])),
            ("ou", HashSet::from([group_ou])),
            ("description", HashSet::from([description])),
        ];
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
                format!("Error creating group: {:?}", err),
                err,
            ));
        }
        let res = save.unwrap();
        debug!("Sucessfully created group result: {:?}", res);
        Ok(())
    }

    ///
    /// Add users to a group in the LDAP server. The group will be updated in the provided base DN.
    ///
    /// # Arguments
    /// * `users` - The list of users to add to the group
    /// * `group_dn` - The dn of the group
    ///
    /// # Returns
    /// * `Result<(), Error>` - Returns an error if failed to add users to the group
    ///
    /// # Example
    /// ```
    /// use simple_ldap::LdapClient;
    /// use simple_ldap::pool::LdapConfig;
    ///
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: "cn=manager".to_string(),
    ///         bind_pw: "password".to_string(),
    ///         ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    ///         pool_size: 10,
    ///         dn_attribute: None
    ///     };
    ///
    ///     let pool = pool::build_connection_pool(&ldap_config).await;
    ///     let mut ldap = pool.get_connection().await;
    ///
    ///     let result = ldap.add_users_to_group(vec!["uid=bd9b91ec-7a69-4166-bf67-cc7e553b2fd9,ou=people,dc=example,dc=com"],
    ///     "cn=test_group,ou=groups,dc=example,dc=com").await;
    /// }
    /// ```
    pub async fn add_users_to_group(
        &mut self,
        users: Vec<&str>,
        group_dn: &str,
    ) -> Result<(), Error> {
        let mut mods = Vec::new();
        let users = users.iter().copied().collect::<HashSet<&str>>();
        mods.push(Mod::Replace("member", users));
        let res = self.ldap.modify(group_dn, mods).await;
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
                            group_dn
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
        Ok(())
    }

    ///
    /// Get users of a group in the LDAP server. The group will be searched in the provided base DN.
    ///
    /// # Arguments
    /// * `group_dn` - The dn of the group
    /// * `base_dn` - The base dn to search for the users
    /// * `scope` - The scope of the search
    /// * `attributes` - The attributes to return from the search
    ///
    /// # Returns
    /// * `Result<Vec<T>, Error>` - Returns a vector of structs of type T
    ///
    /// # Example
    /// ```
    /// use simple_ldap::LdapClient;
    /// use simple_ldap::pool::LdapConfig;
    ///
    /// #[derive(Debug, Deserialize)]
    /// struct User {
    ///     uid: String,
    ///     cn: String,
    ///     sn: String,
    /// }
    ///
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: "cn=manager".to_string(),
    ///         bind_pw: "password".to_string(),
    ///         ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    ///         pool_size: 10,
    ///         dn_attribute: None
    ///     };
    ///
    ///     let pool = pool::build_connection_pool(&ldap_config).await;
    ///     let mut ldap = pool.get_connection().await;
    ///
    ///     let result = ldap.get_members::<User>("cn=test_group,ou=groups,dc=example,dc=com",
    ///     "ou=people,dc=example,dc=com",
    ///     self::ldap3::Scope::OneLevel, vec!["cn", "sn", "uid"]).await;
    /// }
    /// ```
    pub async fn get_members<T: for<'a> serde::Deserialize<'a>>(
        &mut self,
        group_dn: &str,
        base_dn: &str,
        scope: Scope,
        attributes: &Vec<&str>,
    ) -> Result<Vec<T>, Error> {
        let search = self
            .ldap
            .search(
                group_dn,
                Scope::Base,
                "(objectClass=groupOfNames)",
                vec!["member"],
            )
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
            return Err(Error::MultipleResults(String::from(
                "Found multiple records for the search criteria",
            )));
        }

        if records.is_empty() {
            return Err(Error::NotFound(String::from(
                "No records found for the search criteria",
            )));
        }

        let record = records.first().unwrap();

        let x = SearchEntry::construct(record.to_owned());
        let result: HashMap<&str, Vec<String>> = x
            .attrs
            .iter()
            .filter(|(_, value)| !value.is_empty())
            .map(|(arrta, value)| (arrta.as_str(), value.to_owned()))
            .collect();

        let mut members = Vec::new();
        for member in result.get("member").unwrap() {
            let uid = member.split(',').collect::<Vec<&str>>()[0]
                .split('=')
                .collect::<Vec<&str>>();
            let filter = EqFilter::from(uid[0].to_string(), uid[1].to_string());
            let x = self.search::<T>(base_dn, scope, &filter, attributes).await;
            match x {
                Ok(x) => {
                    members.push(x);
                }
                Err(err) => {
                    error!("Error getting member {:?} error {:?}", member, err);
                }
            }
        }

        Ok(members)
    }

    ///
    /// Remove users from a group in the LDAP server. The group will be updated in the provided base DN.
    /// This method will remove all the users provided from the group.
    /// # Arguments
    /// * `group_dn` - The dn of the group
    /// * `users` - The list of users to remove from the group
    ///
    /// # Returns
    /// * `Result<(), Error>` - Returns an error if failed to remove users from the group
    ///
    /// # Example
    /// ```
    /// use simple_ldap::LdapClient;
    /// use simple_ldap::pool::LdapConfig;
    /// use std::collections::HashSet;
    ///
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: "cn=manager".to_string(),
    ///         bind_pw: "password".to_string(),
    ///         ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    ///         pool_size: 10,
    ///         dn_attribute: None
    ///     };
    ///
    ///     let pool = pool::build_connection_pool(&ldap_config).await;
    ///     let mut ldap = pool.get_connection().await;
    ///
    ///     ldap.remove_users_from_group("cn=test_group,ou=groups,dc=example,dc=com",
    ///     vec!["uid=bd9b91ec-7a69-4166-bf67-cc7e553b2fd9,ou=people,dc=example,dc=com"]).await;
    /// }
    /// ```
    pub async fn remove_users_from_group(
        &mut self,
        group_dn: &str,
        users: Vec<&str>,
    ) -> Result<(), Error> {
        let mut mods = Vec::new();
        let users = users.iter().copied().collect::<HashSet<&str>>();
        mods.push(Mod::Delete("member", users));
        let res = self.ldap.modify(group_dn, mods).await;
        if let Err(err) = res {
            return Err(Error::Update(
                format!("Error removing users from group:{:?}: {:?}", group_dn, err),
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
                            group_dn
                        )));
                    }
                }
                _ => {
                    return Err(Error::Update(
                        format!("Error removing users from group:{:?}: {:?}", group_dn, err),
                        err,
                    ));
                }
            }
        }
        Ok(())
    }

    ///
    /// Get the groups associated with a user in the LDAP server. The user will be searched in the provided base DN.
    ///
    /// # Arguments
    /// * `group_ou` - The ou to search for the groups
    /// * `user_dn` - The dn of the user
    ///
    /// # Returns
    /// * `Result<Vec<String>, Error>` - Returns a vector of group names
    ///
    /// # Example
    /// ```
    /// use simple_ldap::LdapClient;
    /// use simple_ldap::pool::LdapConfig;
    ///
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: "cn=manager".to_string(),
    ///         bind_pw: "password".to_string(),
    ///         ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
    ///         pool_size: 10,
    ///         dn_attribute: None
    ///     };
    ///
    ///     let pool = pool::build_connection_pool(&ldap_config).await;
    ///     let mut ldap = pool.get_connection().await;
    ///
    ///     let result = ldap.get_associtated_groups("ou=groups,dc=example,dc=com",
    ///     "uid=bd9b91ec-7a69-4166-bf67-cc7e553b2fd9,ou=people,dc=example,dc=com").await;
    /// }
    /// ```
    pub async fn get_associtated_groups(
        &mut self,
        group_ou: &str,
        user_dn: &str,
    ) -> Result<Vec<String>, Error> {
        let group_filter = Box::new(EqFilter::from(
            "objectClass".to_string(),
            "groupOfNames".to_string(),
        ));

        let user_filter = Box::new(EqFilter::from("member".to_string(), user_dn.to_string()));
        let mut filter = AndFilter::default();
        filter.add(group_filter);
        filter.add(user_filter);

        let search = self
            .ldap
            .search(
                group_ou,
                Scope::Subtree,
                filter.filter().as_str(),
                vec!["cn"],
            )
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

        if records.is_empty() {
            return Err(Error::NotFound(String::from(
                "User does not belong to any groups",
            )));
        }

        let record = records
            .iter()
            .map(|record| SearchEntry::construct(record.to_owned()))
            .map(|se| se.attrs)
            .flat_map(|att| {
                att.get("cn")
                    .unwrap()
                    .iter()
                    .map(|x| x.to_owned())
                    .collect::<Vec<String>>()
            })
            .collect::<Vec<String>>();

        Ok(record)
    }
}

pub struct Stream<'a, S, A> {
    ldap: Object<Manager>,
    search_stream: SearchStream<'a, S, A>,
    cleanup_future: Option<BoxFuture<'a, ()>>,
}

impl<'a, S, A> Stream<'a, S, A>
where
    S: AsRef<str> + Send + Sync + 'a,
    A: AsRef<[S]> + Send + Sync + 'a,
{
    fn new(ldap: Object<Manager>, search_stream: SearchStream<'a, S, A>) -> Stream<'a, S, A> {
        Stream {
            ldap,
            search_stream,
            cleanup_future: None,
        }
    }

    async fn next_inner(&mut self) -> Result<StreamResult<SearchEntry>, Error> {
        let next = self.search_stream.next().await;
        if let Err(err) = next {
            return Err(Error::Query(
                format!("Error getting next record: {:?}", err),
                err,
            ));
        }

        if self.search_stream.state() != StreamState::Active {
            // self.limit = self.count; // Set the limit to the count, to that poll_next will return None
            return Ok(StreamResult::Finished);
        }

        let entry = next.unwrap();
        match entry {
            Some(entry) => {
                // self.count += 1;
                let entry = SearchEntry::construct(entry);
                return Ok(StreamResult::Record(entry));
            }
            None => {
                // self.limit = self.count; // Set the limit to the count, to that poll_next will return None
                return Ok(StreamResult::Finished);
            }
        }
    }

    pub async fn multi_valued_next<T: for<'b> serde::Deserialize<'b>>(
        &mut self,
    ) -> Result<StreamResult<T>, Error> {
        let entry = self.next_inner().await?;
        match entry {
            StreamResult::Record(entry) => {
                let json = LdapClient::create_json_multi_value(entry).unwrap();
                let data = LdapClient::map_to_struct::<T>(json);
                if let Err(err) = data {
                    return Err(Error::Mapping(format!("Error mapping record: {:?}", err)));
                }
                return Ok(StreamResult::Record(data.unwrap()));
            }
            StreamResult::Done => Ok(StreamResult::Done),
            StreamResult::Finished => Ok(StreamResult::Finished),
        }
    }

    pub async fn cleanup(&mut self) {
        println!("Cleaning up");
        let _res = self.search_stream.finish().await;
        let msgid = self.search_stream.ldap_handle().last_id();
        self.ldap.abandon(msgid).await.unwrap();
    }
}

impl<'a, S, A> futures::stream::Stream for Stream<'a, S, A>
where
    S: AsRef<str> + Send + Sync + 'a,
    A: AsRef<[S]> + Send + Sync + 'a,
{
    type Item = Result<Record, Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Record, Error>>> {
        let poll = self.next_inner().boxed().as_mut().poll(cx);
        match poll {
            Poll::Ready(result) => match result {
                Ok(result) => match result {
                    StreamResult::Record(record) => Poll::Ready(Some(Ok(Record {
                        search_entry: record,
                    }))),
                    StreamResult::Done => Poll::Ready(None),
                    StreamResult::Finished => Poll::Ready(None),
                },
                Err(er) => {
                    return Poll::Ready(Some(Err(er)));
                }
            },
            Poll::Pending => {
                // if self.count == self.limit {
                //     return Poll::Ready(None);
                // }
                // Ensure the task is woken when the next record is ready
                Poll::Pending
            }
        }
    }
}

pub struct Record {
    search_entry: SearchEntry,
}

impl Record {
    pub fn to_record<T: for<'b> serde::Deserialize<'b>>(self) -> Result<T, Error> {
        let json = LdapClient::create_json_signle_value(self.search_entry).unwrap();
        let data = LdapClient::map_to_struct::<T>(json);
        if let Err(err) = data {
            return Err(Error::Mapping(format!("Error mapping record: {:?}", err)));
        }
        return Ok(data.unwrap());
    }

    pub fn to_multi_valued_record_<T: for<'b> serde::Deserialize<'b>>(
        self,
    ) -> Result<StreamResult<T>, Error> {
        let json = LdapClient::create_json_multi_value(self.search_entry).unwrap();
        let data = LdapClient::map_to_struct::<T>(json);
        if let Err(err) = data {
            return Err(Error::Mapping(format!("Error mapping record: {:?}", err)));
        }
        return Ok(StreamResult::Record(data.unwrap()));
    }
}

pub enum StreamResult<T> {
    Record(T),
    Done,
    Finished,
}

///
/// The error type for the LDAP client
///
#[derive(Debug)]
pub enum Error {
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
    /// Error occurred while attempting to create a LDAP connection
    Connection(String, LdapError),
    /// Error occurred while using the connection pool
    Pool(PoolError<LdapError>),
}

#[cfg(test)]
mod tests {

    use filter::{ContainsFilter, LikeFilter, WildardOn};
    use futures::StreamExt;
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
            dn_attribute: None,
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
            .unwrap()
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
            dn_attribute: None,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let mut ldap = pool.get_connection().await.unwrap();
        let name_filter = EqFilter::from("cn".to_string(), "Sam".to_string());
        let user = ldap
            .search::<User>(
                "ou=people,dc=example,dc=com",
                self::ldap3::Scope::OneLevel,
                &name_filter,
                &vec!["cn", "sn", "uid"],
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
            dn_attribute: None,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let mut ldap = pool.get_connection().await.unwrap();
        let name_filter = EqFilter::from("cn".to_string(), "SamX".to_string());
        let user = ldap
            .search::<User>(
                "ou=people,dc=example,dc=com",
                self::ldap3::Scope::OneLevel,
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
    }

    #[tokio::test]
    async fn test_search_multiple_record() {
        let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
            dn_attribute: None,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let mut ldap = pool.get_connection().await.unwrap();
        let name_filter = EqFilter::from("cn".to_string(), "James".to_string());
        let user = ldap
            .search::<User>(
                "ou=people,dc=example,dc=com",
                self::ldap3::Scope::OneLevel,
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
    }

    #[tokio::test]
    async fn test_update_record() {
        let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
            dn_attribute: None,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let mut ldap = pool.get_connection().await.unwrap();
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
            dn_attribute: None,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let mut ldap = pool.get_connection().await.unwrap();
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
            dn_attribute: None,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let mut ldap = pool.get_connection().await.unwrap();
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

        let mut ldap = pool.get_connection().await.unwrap();
        let name_filter = EqFilter::from(
            "uid".to_string(),
            "6da70e51-7897-411f-9290-649ebfcb3269".to_string(),
        );
        let user = ldap
            .search::<User>(
                "ou=people,dc=example,dc=com",
                self::ldap3::Scope::OneLevel,
                &name_filter,
                &vec!["cn", "sn", "uid"],
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
            dn_attribute: None,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let ldap = pool.get_connection().await.unwrap();

        let name_filter = EqFilter::from("cn".to_string(), "James".to_string());
        let attra = vec!["cn", "sn", "uid"];
        let result = ldap
            .streaming_search(
                "ou=people,dc=example,dc=com",
                self::ldap3::Scope::OneLevel,
                &name_filter,
                &attra,
            )
            .await;
        assert!(result.is_ok());
        let mut result = result.unwrap();
        let mut count = 0;
        while let Some(record) = result.next().await {
            match record {
                Ok(record) => {
                    let user = record.to_record::<User>().unwrap();
                    count += 1;
                }
                Err(_) => {
                    break;
                }
            }
        }
        assert!(count == 2);
    }

    #[tokio::test]
    async fn test_streaming_search_with() {
        let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
            dn_attribute: None,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let ldap = pool.get_connection().await.unwrap();

        let name_filter = ContainsFilter::from("cn".to_string(), "J".to_string());
        let attra = vec!["cn", "sn", "uid"];
        let result = ldap
            .streaming_search_with(
                "ou=people,dc=example,dc=com",
                self::ldap3::Scope::OneLevel,
                &name_filter,
                &attra,
                3,
            )
            .await;
        assert!(result.is_ok());
        let mut result = result.unwrap();
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
    }

    #[tokio::test]
    async fn test_streaming_search_no_records() {
        let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
            dn_attribute: None,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let ldap = pool.get_connection().await.unwrap();

        let name_filter = EqFilter::from("cn".to_string(), "JamesX".to_string());
        let attra = vec!["cn", "sn", "uid"];
        let result = ldap
            .streaming_search(
                "ou=people,dc=example,dc=com",
                self::ldap3::Scope::OneLevel,
                &name_filter,
                &attra,
            )
            .await;
        assert!(result.is_ok());
        let mut result = result.unwrap();
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
    }

    #[tokio::test]
    async fn test_delete() {
        let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 10,
            dn_attribute: None,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let mut ldap = pool.get_connection().await.unwrap();

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
            dn_attribute: None,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;
        let mut ldap = pool.get_connection().await.unwrap();

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

    #[tokio::test]
    async fn test_create_group() {
        let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://localhost:1389/dc=example,dc=com".to_string(),
            pool_size: 1,
            dn_attribute: None,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;

        let result = pool
            .get_connection()
            .await
            .unwrap()
            .create_group("test_group", "dc=example,dc=com", "Some Description")
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_add_users_to_group() {
        let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://localhost:1389/dc=example,dc=com".to_string(),
            pool_size: 1,
            dn_attribute: None,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;

        let _result = pool
            .get_connection()
            .await
            .unwrap()
            .create_group("test_group_1", "dc=example,dc=com", "Some Decription")
            .await;

        let result = pool
            .get_connection()
            .await
            .unwrap()
            .add_users_to_group(
                vec![
                    "uid=f92f4cb2-e821-44a4-bb13-b8ebadf4ecc5,ou=people,dc=example,dc=com",
                    "uid=e219fbc0-6df5-4bc3-a6ee-986843bb157e,ou=people,dc=example,dc=com",
                ],
                "cn=test_group_1,dc=example,dc=com",
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_members() {
        let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            // ldap_url: "ldap://localhost:1389/dc=example,dc=com".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 1,
            dn_attribute: None,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;

        let _result = pool
            .get_connection()
            .await
            .unwrap()
            .create_group("test_group_3", "dc=example,dc=com", "Some Decription 2")
            .await;

        let _result = pool
            .get_connection()
            .await
            .unwrap()
            .add_users_to_group(
                vec![
                    "uid=f92f4cb2-e821-44a4-bb13-b8ebadf4ecc5,ou=people,dc=example,dc=com",
                    "uid=e219fbc0-6df5-4bc3-a6ee-986843bb157e,ou=people,dc=example,dc=com",
                ],
                "cn=test_group_3,dc=example,dc=com",
            )
            .await;

        let result = pool
            .get_connection()
            .await
            .unwrap()
            .get_members::<User>(
                "cn=test_group_3,dc=example,dc=com",
                "dc=example,dc=com",
                Scope::Subtree,
                &vec!["cn", "sn", "uid"],
            )
            .await;

        assert!(result.is_ok());
        let users = result.unwrap();
        assert_eq!(users.len(), 2);
        let user_count = users
            .iter()
            .filter(|user| {
                user.uid == "f92f4cb2-e821-44a4-bb13-b8ebadf4ecc5"
                    || user.uid == "e219fbc0-6df5-4bc3-a6ee-986843bb157e"
            })
            .count();
        assert_eq!(user_count, 2);
    }

    #[tokio::test]
    async fn test_remove_users_from_group() {
        let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 1,
            dn_attribute: None,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;

        let _result = pool
            .get_connection()
            .await
            .unwrap()
            .create_group("test_group_2", "dc=example,dc=com", "Some Decription 2")
            .await;

        let _result = pool
            .get_connection()
            .await
            .unwrap()
            .add_users_to_group(
                vec![
                    "uid=f92f4cb2-e821-44a4-bb13-b8ebadf4ecc5,ou=people,dc=example,dc=com",
                    "uid=e219fbc0-6df5-4bc3-a6ee-986843bb157e,ou=people,dc=example,dc=com",
                ],
                "cn=test_group_2,dc=example,dc=com",
            )
            .await;

        let result = pool
            .get_connection()
            .await
            .unwrap()
            .remove_users_from_group(
                "cn=test_group_2,dc=example,dc=com",
                vec![
                    "uid=f92f4cb2-e821-44a4-bb13-b8ebadf4ecc5,ou=people,dc=example,dc=com",
                    "uid=e219fbc0-6df5-4bc3-a6ee-986843bb157e,ou=people,dc=example,dc=com",
                ],
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_associated_groups() {
        let ldap_config = LdapConfig {
            bind_dn: "cn=manager".to_string(),
            bind_pw: "password".to_string(),
            ldap_url: "ldap://ldap_server:1389/dc=example,dc=com".to_string(),
            pool_size: 1,
            dn_attribute: None,
        };

        let pool = pool::build_connection_pool(&ldap_config).await;

        let result = pool
            .get_connection()
            .await
            .unwrap()
            .get_associtated_groups(
                "ou=group,dc=example,dc=com",
                "uid=e219fbc0-6df5-4bc3-a6ee-986843bb157e,ou=people,dc=example,dc=com",
            )
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[derive(Deserialize)]
    struct User {
        pub uid: String,
        pub cn: String,
        pub sn: String,
    }
}
