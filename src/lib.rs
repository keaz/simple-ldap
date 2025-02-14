//! # simple-ldap
//!
//! This is a high-level LDAP client library created by wrapping the rust LDAP3 clinet.
//! This provides high-level functions that helps to interact with LDAP.
//!
//!
//! ## Features
//!
//! - All the usual LDAP operations
//! - Search result deserialization
//! - Connection pooling
//! - Streaming search with native rust [`Stream`](https://docs.rs/futures/latest/futures/stream/trait.Stream.html)s
//!
//!
//! ## Usage
//!
//! Adding `simple_ldap` as a dependency to your project:
//!
//! ```commandline
//! cargo add simple-ldap
//! ```
//!
//! Most functionalities are defined on the `LdapClient` type. Have a look at the docs.
//!
//!
//! ### Example
//!
//! Examples of individual operations are scattered throughout the docs, but here's the basic usage:
//!
//! ```no_run
//! use simple_ldap::{
//!     LdapClient, LdapConfig,
//!     filter::EqFilter,
//!     ldap3::Scope
//! };
//! use url::Url;
//! use serde::Deserialize;
//!
//! // A type for deserializing the search result into.
//! #[derive(Debug, Deserialize)]
//! struct User {
//!     uid: String,
//!     cn: String,
//!     sn: String,
//! }
//!
//!
//! #[tokio::main]
//! async fn main(){
//!     let ldap_config = LdapConfig {
//!         bind_dn: String::from("cn=manager"),
//!         bind_password: String::from("password"),
//!         ldap_url: Url::parse("ldaps://localhost:1389/dc=example,dc=com").unwrap(),
//!         dn_attribute: None,
//!         connection_settings: None
//!     };
//!     let mut client = LdapClient::new(ldap_config).await.unwrap();
//!     let name_filter = EqFilter::from("cn".to_string(), "Sam".to_string());
//!     let user: User = client
//!         .search::<User>(
//!         "ou=people,dc=example,dc=com",
//!         Scope::OneLevel,
//!         &name_filter,
//!         &vec!["cn", "sn", "uid"],
//!     ).await.unwrap();
//! }
//! ```
//!
//!
//! ## Compile time features
//!
//! * `tls-native` - (Enabled by default) Enables TLS support using the systems native implementation.
//! * `tls-rustls` - Enables TLS support using `rustls`. **Conflicts with `tls-native` so you need to disable default features to use this.
//! * `pool` - Enable connection pooling
//!

use std::{
    collections::{HashMap, HashSet},
    pin::Pin,
    task::{Context, Poll},
};

use filter::{AndFilter, EqFilter, Filter};
use futures::FutureExt;
use ldap3::{
    adapters::{Adapter, EntriesOnly, PagedResults},
    Ldap, LdapConnAsync, LdapConnSettings, LdapError, Mod, Scope, SearchEntry, SearchStream,
    StreamState,
};
use serde::Deserialize;
use thiserror::Error;
use tracing::{debug, error};
use url::Url;

pub mod filter;
#[cfg(feature = "pool")]
pub mod pool;
pub extern crate ldap3;

const LDAP_ENTRY_DN: &str = "entryDN";
const NO_SUCH_RECORD: u32 = 32;


/// Configuration and authentication for LDAP connection
#[derive(derive_more::Debug, Clone)]
pub struct LdapConfig {
    pub ldap_url: Url,
    /// DistinguishedName, aka the "username" to use for the connection.
    pub bind_dn: String,
    #[debug(skip)] // We don't want to print passwords.
    pub bind_password: String,
    pub dn_attribute: Option<String>,
    /// Low level configuration for the connection.
    /// You can probably skip it.
    #[debug(skip)] // Debug omitted, because it just doesn't implement it.
    pub connection_settings: Option<LdapConnSettings>,
}


///
/// High-level LDAP client wrapper ontop of ldap3 crate. This wrapper provides a high-level interface to perform LDAP operations
/// including authentication, search, update, delete
///
#[derive(Debug, Clone)]
pub struct LdapClient {
    /// The internal connection handle.
    ldap: Ldap,
    dn_attr: Option<String>,
}

impl LdapClient {
    ///
    /// Creates a new asynchronous LDAP client.s
    /// It's capable of running multiple operations concurrently.
    ///
    /// # Bind
    ///
    /// This performs a bind on the connection so need to worry about that.
    ///
    pub async fn new(config: LdapConfig) -> Result<Self, Error> {
        debug!("Creating new connection");

        // With or without connection settings
        let (conn, mut ldap) = match config.connection_settings {
            None => LdapConnAsync::from_url(&config.ldap_url).await,
            Some(settings) => {
                LdapConnAsync::from_url_with_settings(settings, &config.ldap_url).await
            }
        }
        .map_err(|ldap_err| {
            Error::Connection(
                String::from("Failed to initialize LDAP connection."),
                ldap_err,
            )
        })?;

        ldap3::drive!(conn);

        ldap.simple_bind(&config.bind_dn, &config.bind_password)
            .await
            .map_err(|ldap_err| Error::Connection(String::from("Bind failed"), ldap_err))?
            .success()
            .map_err(|ldap_err| Error::Connection(String::from("Bind failed"), ldap_err))?;

        Ok(Self {
            dn_attr: config.dn_attribute,
            ldap,
        })
    }
}

impl LdapClient {
    /// Returns the ldap3 client
    #[deprecated = "This abstraction leakage will be removed in a future release.
                    Use the provided methods instead. If something's missing, open an issue in github."]
    pub fn get_inner(&self) -> Ldap {
        self.ldap.clone()
    }

    /// End the LDAP connection.
    ///
    /// **Caution advised!**
    ///
    /// This will close the connection for all clones of this client as well,
    /// including open streams. So make sure that you're really good to close.
    ///
    /// Closing an LDAP connection with an unbind is *a curtesy.*
    /// It's fine to skip it, and because of the async hurdless outlined above,
    /// I would perhaps even recommend it.
    // Consuming self to prevent accidental use after unbind.
    // This also conveniently prevents calling this with pooled clients, as the
    // wrapper `Object` prohibiths moving.
    pub async fn unbind(mut self) -> Result<(), Error> {
        match self.ldap.unbind().await {
            Ok(_) => Ok(()),
            Err(error) => Err(Error::Close(String::from("Failed to unbind"), error)),
        }
    }

    ///
    /// The user is authenticated by searching for the user in the LDAP server.
    /// The search is performed using the provided filter. The filter should be a filter that matches a single user.
    ///
    /// # Arguments
    ///
    /// * `base` - The base DN to search for the user
    /// * `uid` - The uid of the user
    /// * `password` - The password of the user
    /// * `filter` - The filter to search for the user
    ///
    ///
    /// # Returns
    ///
    /// * `Result<(), Error>` - Returns an error if the authentication fails
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// use simple_ldap::{
    ///     LdapClient, LdapConfig,
    ///     filter::EqFilter
    /// };
    /// use url::Url;
    ///
    /// #[tokio::main]
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: String::from("cn=manager"),
    ///         bind_password: String::from("password"),
    ///         ldap_url: Url::parse("ldaps://localhost:1389/dc=example,dc=com").unwrap(),
    ///         dn_attribute: None,
    ///         connection_settings: None
    ///     };
    ///
    ///     let mut client = LdapClient::new(ldap_config).await.unwrap();
    ///     let name_filter = EqFilter::from("cn".to_string(), "Sam".to_string());
    ///
    ///     let result = client.authenticate("", "Sam", "password", Box::new(name_filter)).await;
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
    ///
    /// * `base` - The base DN to search for the user
    /// * `scope` - The scope of the search
    /// * `filter` - The filter to search for the user
    /// * `attributes` - The attributes to return from the search
    ///
    ///
    /// # Returns
    ///
    /// * `Result<T, Error>` - The result will be mapped to a struct of type T
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// use simple_ldap::{
    ///     LdapClient, LdapConfig,
    ///     filter::EqFilter,
    ///     ldap3::Scope
    /// };
    /// use url::Url;
    /// use serde::Deserialize;
    ///
    ///
    /// #[derive(Debug, Deserialize)]
    /// struct User {
    ///     uid: String,
    ///     cn: String,
    ///     sn: String,
    /// }
    ///
    /// #[tokio::main]
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: String::from("cn=manager"),
    ///         bind_password: String::from("password"),
    ///         ldap_url: Url::parse("ldaps://localhost:1389/dc=example,dc=com").unwrap(),
    ///         dn_attribute: None,
    ///         connection_settings: None
    ///     };
    ///
    ///     let mut client = LdapClient::new(ldap_config).await.unwrap();
    ///
    ///     let name_filter = EqFilter::from("cn".to_string(), "Sam".to_string());
    ///     let user_result = client
    ///         .search::<User>(
    ///         "ou=people,dc=example,dc=com",
    ///         Scope::OneLevel,
    ///         &name_filter,
    ///         &vec!["cn", "sn", "uid"],
    ///     ).await;
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
        to_signle_value(search_entry)
    }

    ///
    /// Search a single value from the LDAP server. The search is performed using the provided filter.
    /// The filter should be a filter that matches a single record. if the filter matches multiple users, an error is returned.
    /// This operatrion is useful when records has multi-valued attributes.
    ///
    /// # Arguments
    ///
    /// * `base` - The base DN to search for the user
    /// * `scope` - The scope of the search
    /// * `filter` - The filter to search for the user
    /// * `attributes` - The attributes to return from the search
    ///
    ///
    /// # Returns
    ///
    /// * `Result<T, Error>` - The result will be mapped to a struct of type T
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// use simple_ldap::{
    ///     LdapClient, LdapConfig,
    ///     filter::EqFilter,
    ///     ldap3::Scope
    /// };
    /// use url::Url;
    /// use serde::Deserialize;
    ///
    ///
    /// #[derive(Debug, Deserialize)]
    /// struct TestMultiValued {
    ///    key1: Vec<String>,
    ///    key2: Vec<String>,
    /// }
    ///
    /// #[tokio::main]
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: String::from("cn=manager"),
    ///         bind_password: String::from("password"),
    ///         ldap_url: Url::parse("ldaps://localhost:1389/dc=example,dc=com").unwrap(),
    ///         dn_attribute: None,
    ///         connection_settings: None
    ///     };
    ///
    ///     let mut client = LdapClient::new(ldap_config).await.unwrap();
    ///
    ///     let name_filter = EqFilter::from("cn".to_string(), "Sam".to_string());
    ///     let user_result = client.search_multi_valued::<TestMultiValued>(
    ///         "",
    ///         Scope::OneLevel,
    ///         &name_filter,
    ///         &vec!["cn", "sn", "uid"]
    ///     ).await;
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
        to_multi_value(search_entry)
    }

    async fn streaming_search_inner<'a>(
        &mut self,
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

        let stream = Stream::new(search_stream);
        Ok(stream)
    }

    ///
    /// This method is used to search multiple records from the LDAP server. The search is performed using the provided filter.
    /// Method will return a Stream. The stream will lazily fetch batches of results resulting in a smaller
    /// memory footprint.
    ///
    /// Prefer streaming search if you don't know that the result set is going to be small.
    ///
    ///
    /// # Arguments
    ///
    /// * `base` - The base DN to search for the user
    /// * `scope` - The scope of the search
    /// * `filter` - The filter to search for the user
    /// * `attributes` - The attributes to return from the search
    ///
    ///
    /// # Returns
    ///
    /// * `Result<Stream, Error>` - The result will be mapped to a Stream. **Remember to `cleanup()` it when you're done!**
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// use simple_ldap::{
    ///     LdapClient, LdapConfig,
    ///     filter::EqFilter,
    ///     ldap3::Scope
    /// };
    /// use url::Url;
    /// use serde::Deserialize;
    /// use futures::StreamExt;
    ///
    ///
    /// #[derive(Deserialize, Debug)]
    /// struct User {
    ///     uid: String,
    ///     cn: String,
    ///     sn: String,
    /// }
    ///
    /// #[tokio::main]
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: String::from("cn=manager"),
    ///         bind_password: String::from("password"),
    ///         ldap_url: Url::parse("ldaps://localhost:1389/dc=example,dc=com").unwrap(),
    ///         dn_attribute: None,
    ///         connection_settings: None
    ///     };
    ///
    ///     let mut client = LdapClient::new(ldap_config).await.unwrap();
    ///
    ///     let name_filter = EqFilter::from(String::from("cn"), String::from("Sam"));
    ///     let attributes = vec!["cn", "sn", "uid"];
    ///
    ///     let mut stream = client.streaming_search(
    ///         "",
    ///         Scope::OneLevel,
    ///         &name_filter,
    ///         &attributes
    ///     ).await.unwrap();
    ///
    ///     while let Some(result) = stream.next().await {
    ///         match result {
    ///             Ok(element) => {
    ///                 let user: User = element.to_record().unwrap();
    ///                 println!("User: {:?}", user);
    ///             }
    ///             Err(err) => {
    ///                 println!("Error: {:?}", err);
    ///             }
    ///         }
    ///     }
    ///     stream.cleanup().await;
    /// }
    /// ```
    ///
    pub async fn streaming_search<'a>(
        // This self reference  lifetime has some nuance behind it.
        //
        // In principle it could just be a value, but then you wouldn't be able to call this
        // with a pooled client, as the deadpool `Object` wrapper only ever gives out references.
        //
        // The lifetime is needed to guarantee that the client is not returned to the pool before
        // the returned stream is finished. This requirement is artificial. Internally the `ldap3` client
        // just makes copy. So this lifetime is here just to enforce correct pool usage.
        &'a mut self,
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
    /// This method is used to search multiple records from the LDAP server and results will be paginated.
    /// Method will return a Stream. The stream will lazily fetch batches of results resulting in a smaller
    /// memory footprint.
    ///
    /// Prefer streaming search if you don't know that the result set is going to be small.
    ///
    ///
    /// # Arguments
    ///
    /// * `base` - The base DN to search for the user
    /// * `scope` - The scope of the search
    /// * `filter` - The filter to search for the user
    /// * `page_size` - The maximum number of records in a page
    /// * `attributes` - The attributes to return from the search
    ///
    ///
    /// # Returns
    ///
    /// * `Result<Stream, Error>` - A stream that can be used to iterate through the search results.
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// use simple_ldap::{
    ///     LdapClient, LdapConfig,
    ///     filter::EqFilter,
    ///     ldap3::Scope
    /// };
    /// use url::Url;
    /// use serde::Deserialize;
    /// use futures::StreamExt;
    ///
    ///
    /// #[derive(Deserialize, Debug)]
    /// struct User {
    ///     uid: String,
    ///     cn: String,
    ///     sn: String,
    /// }
    ///
    /// #[tokio::main]
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: String::from("cn=manager"),
    ///         bind_password: String::from("password"),
    ///         ldap_url: Url::parse("ldaps://localhost:1389/dc=example,dc=com").unwrap(),
    ///         dn_attribute: None,
    ///         connection_settings: None
    ///     };
    ///
    ///     let mut client = LdapClient::new(ldap_config).await.unwrap();
    ///
    ///     let name_filter = EqFilter::from(String::from("cn"), String::from("Sam"));
    ///     let attributes = vec!["cn", "sn", "uid"];
    ///
    ///     let mut stream = client.streaming_search_with(
    ///         "",
    ///         Scope::OneLevel,
    ///         &name_filter,
    ///         &attributes,
    ///         200 // The pagesize
    ///     ).await.unwrap();
    ///
    ///     while let Some(result) = stream.next().await {
    ///         match result {
    ///             Ok(element) => {
    ///                 let user: User = element.to_record().unwrap();
    ///                 println!("User: {:?}", user);
    ///             }
    ///             Err(err) => {
    ///                 println!("Error: {:?}", err);
    ///             }
    ///         }
    ///     }
    ///     stream.cleanup().await;
    /// }
    /// ```
    ///
    pub async fn streaming_search_with<'a>(
        // This self reference  lifetime has some nuance behind it.
        //
        // In principle it could just be a value, but then you wouldn't be able to call this
        // with a pooled client, as the deadpool `Object` wrapper only ever gives out references.
        //
        // The lifetime is needed to guarantee that the client is not returned to the pool before
        // the returned stream is finished. This requirement is artificial. Internally the `ldap3` client
        // just makes copy. So this lifetime is here just to enforce correct pool usage.
        &'a mut self,
        base: &'a str,
        scope: Scope,
        filter: &'a (impl Filter + ?Sized),
        attributes: &'a Vec<&'a str>,
        page_size: i32,
    ) -> Result<Stream<'a, &'a str, &'a Vec<&'a str>>, Error> {
        let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(page_size)),
        ];
        let search_stream = self
            .ldap
            .streaming_search_with(adapters, base, scope, filter.filter().as_str(), attributes)
            .await;

        if let Err(error) = search_stream {
            return Err(Error::Query(
                format!("Error searching for record: {:?}", error),
                error,
            ));
        }

        let search_stream = search_stream.unwrap();

        let stream = Stream::new(search_stream);
        Ok(stream)
    }

    ///
    /// Create a new record in the LDAP server. The record will be created in the provided base DN.
    ///
    /// # Arguments
    ///
    /// * `uid` - The uid of the record
    /// * `base` - The base DN to create the record
    /// * `data` - The attributes of the record
    ///
    ///
    /// # Returns
    ///
    /// * `Result<(), Error>` - Returns an error if the record creation fails
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// use simple_ldap::{LdapClient, LdapConfig};
    /// use url::Url;
    /// use std::collections::HashSet;
    ///
    /// #[tokio::main]
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: String::from("cn=manager"),
    ///         bind_password: String::from("password"),
    ///         ldap_url: Url::parse("ldaps://localhost:1389/dc=example,dc=com").unwrap(),
    ///         dn_attribute: None,
    ///         connection_settings: None
    ///     };
    ///
    ///     let mut client = LdapClient::new(ldap_config).await.unwrap();
    ///
    ///     let data = vec![
    ///         ( "objectClass",HashSet::from(["organizationalPerson", "inetorgperson", "top", "person"]),),
    ///         ("uid",HashSet::from(["bd9b91ec-7a69-4166-bf67-cc7e553b2fd9"]),),
    ///         ("cn", HashSet::from(["Kasun"])),
    ///         ("sn", HashSet::from(["Ranasingh"])),
    ///     ];
    ///
    ///     let result = client.create("bd9b91ec-7a69-4166-bf67-cc7e553b2fd9", "ou=people,dc=example,dc=com", data).await;
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
    ///
    /// * `uid` - The uid of the record
    /// * `base` - The base DN to update the record
    /// * `data` - The attributes of the record
    /// * `new_uid` - The new uid of the record. If the new uid is provided, the uid of the record will be updated.
    ///
    ///
    /// # Returns
    ///
    /// * `Result<(), Error>` - Returns an error if the record update fails
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// use simple_ldap::{
    ///     LdapClient, LdapConfig,
    ///     ldap3::Mod
    /// };
    /// use url::Url;
    /// use std::collections::HashSet;
    ///
    /// #[tokio::main]
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: String::from("cn=manager"),
    ///         bind_password: String::from("password"),
    ///         ldap_url: Url::parse("ldaps://localhost:1389/dc=example,dc=com").unwrap(),
    ///         dn_attribute: None,
    ///         connection_settings: None
    ///     };
    ///
    ///     let mut client = LdapClient::new(ldap_config).await.unwrap();
    ///
    ///     let data = vec![
    ///         Mod::Replace("cn", HashSet::from(["Jhon_Update"])),
    ///         Mod::Replace("sn", HashSet::from(["Eliet_Update"])),
    ///     ];
    ///
    ///     let result = client.update(
    ///         "e219fbc0-6df5-4bc3-a6ee-986843bb157e",
    ///         "ou=people,dc=example,dc=com",
    ///         data,
    ///         None
    ///     ).await;
    /// }
    /// ```
    ///
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
    ///
    /// * `uid` - The uid of the record
    /// * `base` - The base DN to delete the record
    ///
    ///
    /// # Returns
    ///
    /// * `Result<(), Error>` - Returns an error if the record delete fails
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// use simple_ldap::{LdapClient, LdapConfig};
    /// use url::Url;
    ///
    /// #[tokio::main]
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: String::from("cn=manager"),
    ///         bind_password: String::from("password"),
    ///         ldap_url: Url::parse("ldaps://localhost:1389/dc=example,dc=com").unwrap(),
    ///         dn_attribute: None,
    ///         connection_settings: None
    ///     };
    ///
    ///     let mut client = LdapClient::new(ldap_config).await.unwrap();
    ///
    ///     let result = client.delete("e219fbc0-6df5-4bc3-a6ee-986843bb157e", "ou=people,dc=example,dc=com").await;
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
    ///
    /// * `group_name` - The name of the group
    /// * `group_ou` - The ou of the group
    /// * `description` - The description of the group
    ///
    /// # Returns
    ///
    /// * `Result<(), Error>` - Returns an error if the group creation fails
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// use simple_ldap::{LdapClient, LdapConfig};
    /// use url::Url;
    ///
    /// #[tokio::main]
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: String::from("cn=manager"),
    ///         bind_password: String::from("password"),
    ///         ldap_url: Url::parse("ldaps://localhost:1389/dc=example,dc=com").unwrap(),
    ///         dn_attribute: None,
    ///         connection_settings: None
    ///     };
    ///
    ///     let mut client = LdapClient::new(ldap_config).await.unwrap();
    ///
    ///     let result = client.create_group("test_group", "ou=groups,dc=example,dc=com", "test group").await;
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
    ///
    /// * `users` - The list of users to add to the group
    /// * `group_dn` - The dn of the group
    ///
    ///
    /// # Returns
    ///
    /// * `Result<(), Error>` - Returns an error if failed to add users to the group
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// use simple_ldap::{LdapClient, LdapConfig};
    /// use url::Url;
    ///
    /// #[tokio::main]
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: String::from("cn=manager"),
    ///         bind_password: String::from("password"),
    ///         ldap_url: Url::parse("ldaps://localhost:1389/dc=example,dc=com").unwrap(),
    ///         dn_attribute: None,
    ///         connection_settings: None
    ///     };
    ///
    ///     let mut client = LdapClient::new(ldap_config).await.unwrap();
    ///
    ///     let result = client.add_users_to_group(
    ///         vec!["uid=bd9b91ec-7a69-4166-bf67-cc7e553b2fd9,ou=people,dc=example,dc=com"],
    ///         "cn=test_group,ou=groups,dc=example,dc=com").await;
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
    ///
    /// * `group_dn` - The dn of the group
    /// * `base_dn` - The base dn to search for the users
    /// * `scope` - The scope of the search
    /// * `attributes` - The attributes to return from the search
    ///
    ///
    /// # Returns
    ///
    /// * `Result<Vec<T>, Error>` - Returns a vector of structs of type T
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// use simple_ldap::{
    ///     LdapClient, LdapConfig,
    ///     ldap3::Scope
    /// };
    /// use url::Url;
    /// use serde::Deserialize;
    ///
    /// #[derive(Debug, Deserialize)]
    /// struct User {
    ///     uid: String,
    ///     cn: String,
    ///     sn: String,
    /// }
    ///
    /// #[tokio::main]
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: String::from("cn=manager"),
    ///         bind_password: String::from("password"),
    ///         ldap_url: Url::parse("ldaps://localhost:1389/dc=example,dc=com").unwrap(),
    ///         dn_attribute: None,
    ///         connection_settings: None
    ///     };
    ///
    ///     let mut client = LdapClient::new(ldap_config).await.unwrap();
    ///
    ///     let result = client.get_members::<User>(
    ///         "cn=test_group,ou=groups,dc=example,dc=com",
    ///         "ou=people,dc=example,dc=com",
    ///         Scope::OneLevel,
    ///         &vec!["cn", "sn", "uid"]
    ///     ).await;
    /// }
    /// ```
    ///
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
    ///
    ///
    /// # Arguments
    ///
    /// * `group_dn` - The dn of the group
    /// * `users` - The list of users to remove from the group
    ///
    ///
    /// # Returns
    ///
    /// * `Result<(), Error>` - Returns an error if failed to remove users from the group
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// use simple_ldap::{LdapClient, LdapConfig};
    /// use url::Url;
    /// use std::collections::HashSet;
    ///
    /// #[tokio::main]
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: String::from("cn=manager"),
    ///         bind_password: String::from("password"),
    ///         ldap_url: Url::parse("ldaps://localhost:1389/dc=example,dc=com").unwrap(),
    ///         dn_attribute: None,
    ///         connection_settings: None
    ///     };
    ///
    ///     let mut client = LdapClient::new(ldap_config).await.unwrap();
    ///
    ///     let result = client.remove_users_from_group("cn=test_group,ou=groups,dc=example,dc=com",
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
    ///
    /// * `group_ou` - The ou to search for the groups
    /// * `user_dn` - The dn of the user
    ///
    /// # Returns
    ///
    /// * `Result<Vec<String>, Error>` - Returns a vector of group names
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// use simple_ldap::{LdapClient, LdapConfig};
    /// use url::Url;
    ///
    /// #[tokio::main]
    /// async fn main(){
    ///     let ldap_config = LdapConfig {
    ///         bind_dn: String::from("cn=manager"),
    ///         bind_password: String::from("password"),
    ///         ldap_url: Url::parse("ldaps://localhost:1389/dc=example,dc=com").unwrap(),
    ///         dn_attribute: None,
    ///         connection_settings: None
    ///     };
    ///
    ///     let mut client = LdapClient::new(ldap_config).await.unwrap();
    ///
    ///     let result = client.get_associtated_groups("ou=groups,dc=example,dc=com",
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

fn to_signle_value<T: for<'a> Deserialize<'a>>(search_entry: SearchEntry) -> Result<T, Error> {
    let result: HashMap<&str, serde_value::Value> = search_entry
        .attrs
        .iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(arrta, value)| (arrta.as_str(), map_to_single_value(value.first())))
        .collect();

    let value = serde_value::Value::Map(
        result
            .into_iter()
            .map(|(k, v)| (serde_value::Value::String(k.to_string()), v))
            .collect(),
    );

    Ok(T::deserialize(value).map_err(|err| {
        Error::Mapping(format!(
            "Error converting search result to object, {:?}",
            err
        ))
    })?)
}

fn to_multi_value<T: for<'a> Deserialize<'a>>(search_entry: SearchEntry) -> Result<T, Error> {
    let result: HashMap<&str, serde_value::Value> = search_entry
        .attrs
        .iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(arrta, value)| (arrta.as_str(), map_to_multi_value(value)))
        .collect();

    let value = serde_value::Value::Map(
        result
            .into_iter()
            .map(|(k, v)| (serde_value::Value::String(k.to_string()), v))
            .collect(),
    );

    Ok(T::deserialize(value).map_err(|err| {
        Error::Mapping(format!(
            "Error converting search result to object, {:?}",
            err
        ))
    })?)
}

fn map_to_single_value(attra_value: Option<&String>) -> serde_value::Value {
    match attra_value {
        Some(value) => serde_value::Value::String(value.to_string()),
        None => serde_value::Value::Option(Option::None),
    }
}

fn map_to_multi_value(attra_value: &Vec<String>) -> serde_value::Value {
    serde_value::Value::Seq(
        attra_value
            .iter()
            .map(|value| serde_value::Value::String(value.to_string()))
            .collect(),
    )
}

/// The Stream struct is used to iterate through the search results.
/// The stream will return a Record object. The Record object can be used to map the search result to a struct.
/// After the stream is finished, the cleanup method should be called to cleanup the stream.
///
pub struct Stream<'a, S, A> {
    search_stream: SearchStream<'a, S, A>,
}

impl<'a, S, A> Stream<'a, S, A>
where
    S: AsRef<str> + Send + Sync + 'a,
    A: AsRef<[S]> + Send + Sync + 'a,
{
    fn new(search_stream: SearchStream<'a, S, A>) -> Stream<'a, S, A> {
        Stream { search_stream }
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

    ///
    /// Cleanup the stream. This method should be called after the stream is finished,
    /// especially if you're stopping before the stream ends naturally.
    ///
    /// This method will cleanup the stream and close the connection.
    ///
    pub async fn cleanup(&mut self) -> Result<(), Error> {
        let state = self.search_stream.state();
        if state == StreamState::Done || state == StreamState::Closed {
            return Ok(());
        }
        let _res = self.search_stream.finish().await;
        let msgid = self.search_stream.ldap_handle().last_id();
        let result = self.search_stream.ldap_handle().abandon(msgid).await;

        match result {
            Ok(_) => {
                debug!("Sucessfully abandoned search result: {:?}", msgid);
                Ok(())
            }
            Err(err) => {
                error!("Error abandoning search result: {:?}", err);
                Err(Error::Abandon(
                    format!("Error abandoning search result: {:?}", err),
                    err,
                ))
            }
        }
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
            Poll::Pending => Poll::Pending,
        }
    }
}

/// The Record struct is used to map the search result to a struct.
/// The Record struct has a method to_record which will map the search result to a struct.
/// The Record struct has a method to_multi_valued_record which will map the search result to a struct with multi valued attributes.
pub struct Record {
    search_entry: SearchEntry,
}

impl Record {
    ///
    /// Create a new Record object with single valued attributes.
    /// This is essentially parsing the response records into usable types.
    //
    // This is kind of missnomer, as we aren't creating records here.
    // Perhaps something like "deserialize" would fit better?
    pub fn to_record<T: for<'b> serde::Deserialize<'b>>(self) -> Result<T, Error> {
        to_signle_value(self.search_entry)
    }

    pub fn to_multi_valued_record_<T: for<'b> serde::Deserialize<'b>>(self) -> Result<T, Error> {
        to_multi_value(self.search_entry)
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
#[derive(Debug, Error)]
pub enum Error {
    /// Error occured when performing a LDAP query
    #[error("{0}")]
    Query(String, #[source] LdapError),
    /// No records found for the search criteria
    #[error("{0}")]
    NotFound(String),
    /// Multiple records found for the search criteria
    #[error("{0}")]
    MultipleResults(String),
    /// Authenticating a user failed.
    #[error("{0}")]
    AuthenticationFailed(String),
    /// Error occured when creating a record
    #[error("{0}")]
    Create(String, #[source] LdapError),
    /// Error occured when updating a record
    #[error("{0}")]
    Update(String, #[source] LdapError),
    /// Error occured when deleting a record
    #[error("{0}")]
    Delete(String, #[source] LdapError),
    /// Error occured when mapping the search result to a struct
    #[error("{0}")]
    Mapping(String),
    /// Error occurred while attempting to create an LDAP connection
    #[error("{0}")]
    Connection(String, #[source] LdapError),
    /// Error occurred while attempting to close an LDAP connection.
    /// Includes unbind issues.
    #[error("{0}")]
    Close(String, #[source] LdapError),
    /// Error occurred while abandoning the search result
    #[error("{0}")]
    Abandon(String, #[source] LdapError),
}

#[cfg(test)]
mod tests {
    //! Local tests that don't need to connect to a server.

    use super::*;
    use serde::Deserialize;

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

        let test = to_multi_value::<TestMultiValued>(entry);
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
        map.insert("key4".to_string(), vec!["value4".to_string()]);
        let entry = SearchEntry {
            dn: "dn".to_string(),
            attrs: map,
            bin_attrs: HashMap::new(),
        };

        let test = to_signle_value::<TestSingleValued>(entry);
        assert!(test.is_ok());
        let test = test.unwrap();
        assert_eq!(test.key1, "value1".to_string());
        assert_eq!(test.key2, "value2".to_string());
        assert!(test.key3.is_none());
        assert_eq!(test.key4.unwrap(), "value4".to_string());
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
        key3: Option<String>,
        key4: Option<String>,
    }
}

// Add readme examples to doctests:
// https://doc.rust-lang.org/rustdoc/write-documentation/documentation-tests.html#include-items-only-when-collecting-doctests
#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;
