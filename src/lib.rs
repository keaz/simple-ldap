//! # simple-ldap
//!
//! This is a high-level LDAP client library created by wrapping the rust LDAP3 clinet.
//! This provides high-level functions that helps to interact with LDAP.
//!
//!
//! ## Features
//!
//! - All the usual LDAP operations
//! - Search result [deserialization](#deserialization)
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
//! Most functionalities are defined on the [`LdapClient`] type. Have a look at the docs.
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
//! ### Deserialization
//!
//! Search results are deserialized into user provided types using [`serde`](https://serde.rs/).
//! Define a type that reflects the expected results of your search, and derive `Deserialize` for it. For example:
//!
//! ```
//! use serde::Deserialize;
//! use serde_with::serde_as;
//! use serde_with::OneOrMany;
//!
//! // A type for deserializing the search result into.
//! #[serde_as] // serde_with for multiple values
//! #[derive(Debug, Deserialize)]
//! struct User {
//!     // DN is always returned as single value string, whether you ask it or not.
//!     dn: String,
//!     cn: String,
//!     // LDAP and Rust naming conventions differ.
//!     // You can make up for the difference by using serde's renaming annotations.
//!     #[serde(rename = "mayNotExist")]
//!     may_not_exist: Option<String>,
//!     #[serde_as(as = "OneOrMany<_>")] // serde_with for multiple values
//!     multivalued_attribute: Vec<String>
//! }
//! ```
//!
//! Take care to actually request for all the attribute fields in the search.
//! Otherwise they won't be returned, and the deserialization will fail (unless you used an `Option`).
//!
//!
//! #### String attributes
//!
//! Most attributes are returned as strings. You can deserialize them into just Strings, but also into
//! anything else that can supports deserialization from a string. E.g. perhaps the string represents a
//! timestamp, and you can deserialize it directly into [`chrono::DateTime`](https://docs.rs/chrono/latest/chrono/struct.DateTime.html).
//!
//!
//! #### Binary attributes
//!
//! Some attributes may be binary encoded. (Active Directory especially has a bad habit of using these.)
//! You can just capture the bytes directly into a `Vec<u8>`, but you can also use a type that knows how to
//! deserialize from bytes. E.g. [`uuid::Uuid`](https://docs.rs/uuid/latest/uuid/struct.Uuid.html)
//!
//!
//! #### Multi-valued attributes
//!
//! Multi-valued attributes should be marked as #[serde_as(as = "OneOrMany<_>")] using `serde_with`. Currently, there is a limitation when handing
//! binary attributes. This will be fixed in the future. As a workaround, you can use `search_multi_valued` or `Record::to_multi_valued_record_`.
//! To use those method all the attributes should be multi-valued.
//!
//!
//! ## Compile time features
//!
//! * `tls-native` - (Enabled by default) Enables TLS support using the systems native implementation.
//! * `tls-rustls` - Enables TLS support using `rustls`. **Conflicts with `tls-native` so you need to disable default features to use this.**
//! * `pool` - Enable connection pooling
//!

use std::{
    collections::{HashMap, HashSet},
    iter,
};

use filter::{AndFilter, EqFilter, Filter, OrFilter};
use futures::{executor::block_on, stream, Stream, StreamExt};
use ldap3::{
    adapters::{Adapter, EntriesOnly, PagedResults},
    Ldap, LdapConnAsync, LdapConnSettings, LdapError, LdapResult, Mod, Scope, SearchEntry,
    SearchStream, StreamState,
};
use serde::{Deserialize, Serialize};
use serde_value::Value;
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn, Level};
use url::Url;

pub mod filter;
#[cfg(feature = "pool")]
pub mod pool;
pub mod simple_dn;
// Export the main type of the module right here in the root.
pub use simple_dn::SimpleDN;

// Would likely be better if we could avoid re-exporting this.
// I suspect it's only used in some configs?
pub extern crate ldap3;

const LDAP_ENTRY_DN: &str = "entryDN";
const NO_SUCH_RECORD: u32 = 32;

/// Configuration and authentication for LDAP connection
#[derive(derive_more::Debug, Clone)]
pub struct LdapConfig {
    pub ldap_url: Url,
    /// DistinguishedName, aka the "username" to use for the connection.
    // Perhaps we don't want to use SimpleDN here, as it would make it impossible to bind to weird DNs.
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
    /// This performs a simple bind on the connection so need to worry about that.
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
        let attr_dn = self.dn_attr.as_deref().unwrap_or(LDAP_ENTRY_DN);

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
    /// This operation will treat all the attributes as single-valued, silently ignoring the possible extra
    /// values.
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
        to_value(search_entry)
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

    ///
    /// This method is used to search multiple records from the LDAP server. The search is performed using the provided filter.
    /// Method will return a Stream. The stream will lazily fetch the results, resulting in a smaller
    /// memory footprint.
    ///
    /// You might also want to take a look at [`streaming_search_paged()`].
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
    /// A stream that can be used to iterate through the search results.
    ///
    ///
    /// ## Blocking drop caveat
    ///
    /// Dropping this stream may issue blocking network requests to cancel the search.
    /// Running the stream to it's end will minimize the chances of this happening.
    /// You should take this into account if latency is critical to your application.
    ///
    /// We're waiting for [`AsyncDrop`](https://github.com/rust-lang/rust/issues/126482) for implementing this properly.
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
    ///     let stream = client.streaming_search(
    ///         "",
    ///         Scope::OneLevel,
    ///         &name_filter,
    ///         &attributes
    ///     ).await.unwrap();
    ///
    ///     // The returned stream is not Unpin, so you may need to pin it to use certain operations,
    ///     // such as next() below.
    ///     let mut pinned_steam = Box::pin(stream);
    ///
    ///     while let Some(result) = pinned_steam.next().await {
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
    /// }
    /// ```
    ///
    pub async fn streaming_search<'a, F: Filter>(
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
        filter: &'a F,
        attributes: &'a Vec<&'a str>,
    ) -> Result<impl Stream<Item = Result<Record, crate::Error>> + use<'a, F>, Error> {
        let search_stream = self
            .ldap
            .streaming_search(base, scope, filter.filter().as_str(), attributes)
            .await
            .map_err(|ldap_error| {
                Error::Query(
                    format!("Error searching for record: {ldap_error:?}"),
                    ldap_error,
                )
            })?;

        to_native_stream(search_stream)
    }

    ///
    /// This method is used to search multiple records from the LDAP server and results will be paginated.
    /// Method will return a Stream. The stream will lazily fetch batches of results resulting in a smaller
    /// memory footprint.
    ///
    /// This is the recommended search method, especially if you don't know that the result set is going to be small.
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
    /// A stream that can be used to iterate through the search results.
    ///
    ///
    /// ## Blocking drop caveat
    ///
    /// Dropping this stream may issue blocking network requests to cancel the search.
    /// Running the stream to it's end will minimize the chances of this happening.
    /// You should take this into account if latency is critical to your application.
    ///
    /// We're waiting for [`AsyncDrop`](https://github.com/rust-lang/rust/issues/126482) for implementing this properly.
    ///
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
    /// use futures::{StreamExt, TryStreamExt};
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
    ///     let stream = client.streaming_search_paged(
    ///         "",
    ///         Scope::OneLevel,
    ///         &name_filter,
    ///         &attributes,
    ///         200 // The pagesize
    ///     ).await.unwrap();
    ///
    ///     // Map the search results to User type.
    ///     stream.and_then(async |record| record.to_record())
    ///          // Do something with the Users concurrently.
    ///         .try_for_each(async |user: User| {
    ///             println!("User: {:?}", user);
    ///             Ok(())
    ///         })
    ///         .await
    ///         .unwrap();
    /// }
    /// ```
    ///
    pub async fn streaming_search_paged<'a, F: Filter>(
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
        filter: &'a F,
        attributes: &'a Vec<&'a str>,
        page_size: i32,
    ) -> Result<impl Stream<Item = Result<Record, crate::Error>> + use<'a, F>, Error> {
        let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(page_size)),
        ];
        let search_stream = self
            .ldap
            .streaming_search_with(adapters, base, scope, filter.filter().as_str(), attributes)
            .await
            .map_err(|ldap_error| {
                Error::Query(
                    format!("Error searching for record: {ldap_error:?}"),
                    ldap_error,
                )
            })?;

        to_native_stream(search_stream)
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

        let mut or_filter = OrFilter::default();

        let search_entry = SearchEntry::construct(record.to_owned());
        search_entry
            .attrs
            .into_iter()
            .filter(|(_, value)| !value.is_empty())
            .map(|(arrta, value)| (arrta.to_owned(), value.to_owned()))
            .filter(|(attra, _)| attra.eq("member"))
            .flat_map(|(_, value)| value)
            .map(|val| {
                val.split(',').collect::<Vec<&str>>()[0]
                    .split('=')
                    .map(|split| split.to_string())
                    .collect::<Vec<String>>()
            })
            .map(|uid| EqFilter::from(uid[0].to_string(), uid[1].to_string()))
            .for_each(|eq| or_filter.add(Box::new(eq)));

        let result = self
            .streaming_search(base_dn, scope, &or_filter, attributes)
            .await;

        let mut members = Vec::new();
        match result {
            Ok(result) => {
                let mut stream = Box::pin(result);
                while let Some(member) = stream.next().await {
                    match member {
                        Ok(member) => {
                            let user: T = member.to_record().unwrap();
                            members.push(user);
                        }
                        Err(err) => {
                            // TODO: Exit with an error instead?
                            error!("Error getting member error {:?}", err);
                        }
                    }
                }
                return Ok(members);
            }
            Err(err) => {
                // TODO: Exit with an error instead?
                error!("Error getting members {:?} error {:?}", group_dn, err);
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

/// A proxy type for deriving `Serialize` for `ldap3::SearchEntry`.
/// https://serde.rs/remote-derive.html
#[derive(Serialize)]
#[serde(remote = "ldap3::SearchEntry")]
struct Ldap3SearchEntry {
    /// Entry DN.
    pub dn: String,
    /// Attributes.
    /// Flattening to ease up the serialization step.
    #[serde(flatten)]
    pub attrs: HashMap<String, Vec<String>>,
    /// Binary-valued attributes.
    /// Flattening to ease up the serialization step.
    #[serde(flatten)]
    pub bin_attrs: HashMap<String, Vec<Vec<u8>>>,
}

/// This is needed for invoking the deserialize impl directly.
/// https://serde.rs/remote-derive.html#invoking-the-remote-impl-directly
#[derive(Serialize)]
#[serde(transparent)]
struct SerializeWrapper(#[serde(with = "Ldap3SearchEntry")] ldap3::SearchEntry);

// Allowing users to debug serialization issues from the logs.
#[instrument(level = Level::DEBUG)]
fn to_signle_value<T: for<'a> Deserialize<'a>>(search_entry: SearchEntry) -> Result<T, Error> {
    let string_attributes = search_entry
        .attrs
        .into_iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(arrta, value)| {
            if value.len() > 1 {
                warn!("Treating multivalued attribute {arrta} as singlevalued.")
            }
            (Value::String(arrta), map_to_single_value(value.first()))
        });

    let binary_attributes = search_entry
        .bin_attrs
        .into_iter()
        // I wonder if it's possible to have empties here..?
        .filter(|(_, value)| !value.is_empty())
        .map(|(arrta, value)| {
            if value.len() > 1 {
                warn!("Treating multivalued attribute {arrta} as singlevalued.")
            }
            (
                Value::String(arrta),
                map_to_single_value_bin(value.first().cloned()),
            )
        });

    // DN is always returned.
    // Adding it to the serialized fields as well.
    let dn_iter = iter::once(search_entry.dn)
        .map(|dn| (Value::String(String::from("dn")), Value::String(dn)));

    let all_fields = string_attributes
        .chain(binary_attributes)
        .chain(dn_iter)
        .collect();

    let value = serde_value::Value::Map(all_fields);

    T::deserialize(value).map_err(|err| {
        Error::Mapping(format!(
            "Error converting search result to object, {:?}",
            err
        ))
    })
}

#[instrument(level = Level::DEBUG)]
fn to_value<T: for<'a> Deserialize<'a>>(search_entry: SearchEntry) -> Result<T, Error> {
    let string_attributes = search_entry
        .attrs
        .into_iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(arrta, value)| {
            if value.len() == 1 {
                return (Value::String(arrta), map_to_single_value(value.first()));
            }
            (Value::String(arrta), map_to_multi_value(value))
        });

    let binary_attributes = search_entry
        .bin_attrs
        .into_iter()
        // I wonder if it's possible to have empties here..?
        .filter(|(_, value)| !value.is_empty())
        .map(|(arrta, value)| {
            if value.len() > 1 {
                //#TODO: This is a bit of a hack to get multi-valued attributes to work for non binary values. SHOULD fix this.
                warn!("Treating multivalued attribute {arrta} as singlevalued.")
            }
            (
                Value::String(arrta),
                map_to_single_value_bin(value.first().cloned()),
            )
            // if value.len() == 1 {
            //     return (
            //         Value::String(arrta),
            //         map_to_single_value_bin(value.first().cloned()),
            //     );
            // }
            // (Value::String(arrta), map_to_multi_value_bin(value))
        });

    // DN is always returned.
    // Adding it to the serialized fields as well.
    let dn_iter = iter::once(search_entry.dn)
        .map(|dn| (Value::String(String::from("dn")), Value::String(dn)));

    let all_fields = string_attributes
        .chain(binary_attributes)
        .chain(dn_iter)
        .collect();

    let value = serde_value::Value::Map(all_fields);

    T::deserialize(value).map_err(|err| {
        Error::Mapping(format!(
            "Error converting search result to object, {:?}",
            err
        ))
    })
}

fn map_to_multi_value(attra_value: Vec<String>) -> serde_value::Value {
    serde_value::Value::Seq(
        attra_value
            .iter()
            .map(|value| serde_value::Value::String(value.to_string()))
            .collect(),
    )
}

fn map_to_multi_value_bin(attra_values: Vec<Vec<u8>>) -> serde_value::Value {
    let value_bytes = attra_values
        .iter()
        .map(|value| {
            value
                .iter()
                .map(|byte| Value::U8(*byte))
                .collect::<Vec<Value>>()
        })
        .map(serde_value::Value::Seq)
        .collect::<Vec<Value>>();

    serde_value::Value::Seq(value_bytes)
}

// Allowing users to debug serialization issues from the logs.
#[instrument(level = Level::DEBUG)]
fn to_multi_value<T: for<'a> Deserialize<'a>>(search_entry: SearchEntry) -> Result<T, Error> {
    let value = serde_value::to_value(SerializeWrapper(search_entry)).map_err(|err| {
        Error::Mapping(format!(
            "Error converting search result to object, {:?}",
            err
        ))
    })?;

    T::deserialize(value).map_err(|err| {
        Error::Mapping(format!(
            "Error converting search result to object, {:?}",
            err
        ))
    })
}

fn map_to_single_value(attra_value: Option<&String>) -> serde_value::Value {
    match attra_value {
        Some(value) => serde_value::Value::String(value.to_string()),
        None => serde_value::Value::Option(Option::None),
    }
}

fn map_to_single_value_bin(attra_values: Option<Vec<u8>>) -> serde_value::Value {
    match attra_values {
        Some(bytes) => {
            let value_bytes = bytes.into_iter().map(Value::U8).collect();

            serde_value::Value::Seq(value_bytes)
        }
        None => serde_value::Value::Option(Option::None),
    }
}

/// This wrapper exists solely for the purpose of runnig some cleanup in `drop()`.
///
/// This should be refactored to implement `AsyncDrop` when it gets stabilized:
/// https://github.com/rust-lang/rust/issues/126482
struct StreamDropWrapper<'a, S, A>
where
    S: AsRef<str> + Send + Sync + 'a,
    A: AsRef<[S]> + Send + Sync + 'a,
{
    pub search_stream: SearchStream<'a, S, A>,
}

impl<'a, S, A> Drop for StreamDropWrapper<'a, S, A>
where
    S: AsRef<str> + Send + Sync + 'a,
    A: AsRef<[S]> + Send + Sync + 'a,
{
    fn drop(&mut self) {
        // Making this blocking call in drop is suboptimal.
        // We should use async-drop, when it's stabilized:
        // https://github.com/rust-lang/rust/issues/126482
        block_on(self.cleanup());
    }
}

impl<'a, S, A> StreamDropWrapper<'a, S, A>
where
    S: AsRef<str> + Send + Sync + 'a,
    A: AsRef<[S]> + Send + Sync + 'a,
{
    ///
    /// Cleanup the stream. This method should be called when dropping the stream.
    ///
    /// This method will cleanup the stream and close the connection.
    ///
    ///
    /// # Errors
    ///
    /// No errors are returned, as this is meant to be called from `drop()`.
    /// Traces are emitted though.
    ///
    #[instrument(level = Level::TRACE, skip_all)]
    async fn cleanup(&mut self) -> () {
        // Calling this might not be strictly necessary,
        // but it's probably expected so let's just do it.
        // I don't think this does any networkig most of the time.
        let finish_result = self.search_stream.finish().await;

        match finish_result.success() {
            Ok(_) => (), // All good.
            // This is returned if the stream is cancelled in the middle.
            // Which is fine for us.
            Err(LdapError::LdapResult {result: LdapResult{rc: return_code, ..}})
                // https://ldap.com/ldap-result-code-reference-client-side-result-codes/#rc-userCanceled
                if return_code == 88 => (),
            Err(finish_err) => error!("The stream finished with an error: {finish_err}"),
        }

        match self.search_stream.state() {
            // Stream processed to the end, no need to cancel the operation.
            // This should be the common case.
            StreamState::Done | StreamState::Closed => (),
            StreamState::Error => {
                error!("Stream is in Error state. Not trying to cancel it as it could do more harm than good.");
                ()
            }
            StreamState::Fresh | StreamState::Active => {
                info!("Stream is still open. Issuing cancellation to the server.");
                let msgid = self.search_stream.ldap_handle().last_id();
                let result = self.search_stream.ldap_handle().abandon(msgid).await;

                match result {
                    Ok(_) => (),
                    Err(err) => {
                        error!("Error abandoning search result: {:?}", err);
                        ()
                    }
                }
            }
        }
    }
}

/// A helper to create native rust streams out of `ldap3::SearchStream`s.
fn to_native_stream<'a, S, A>(
    ldap3_stream: SearchStream<'a, S, A>,
) -> Result<impl Stream<Item = Result<Record, crate::Error>> + use<'a, S, A>, Error>
where
    S: AsRef<str> + Send + Sync + 'a,
    A: AsRef<[S]> + Send + Sync + 'a,
{
    // This will handle stream cleanup.
    let stream_wrapper = StreamDropWrapper {
        search_stream: ldap3_stream,
    };

    // Produce the steam itself by unfolding.
    let stream = stream::try_unfold(stream_wrapper, async |mut search| {
        match search.search_stream.next().await {
            // In the middle of the stream. Produce the next result.
            Ok(Some(result_entry)) => Ok(Some((
                Record {
                    search_entry: SearchEntry::construct(result_entry),
                },
                search,
            ))),
            // Stream is done.
            Ok(None) => Ok(None),
            Err(ldap_error) => Err(Error::Query(
                format!("Error getting next record: {ldap_error:?}"),
                ldap_error,
            )),
        }
    });

    Ok(stream)
}

/// The Record struct is used to map the search result to a struct.
/// The Record struct has a method to_record which will map the search result to a struct.
/// The Record struct has a method to_multi_valued_record which will map the search result to a struct with multi valued attributes.
//
// It would be nice to hide this record type from the public API and just expose already
// deserialized user types.
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
        to_value(self.search_entry)
    }

    #[deprecated(
        since = "6.0.0",
        note = "Use to_record instead. This method is deprecated and will be removed in future versions."
    )]
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
    use anyhow::anyhow;
    use serde::Deserialize;
    use serde_with::serde_as;
    use serde_with::OneOrMany;
    use uuid::Uuid;

    #[test]
    fn create_multi_value_test() {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        map.insert(
            "key1".to_string(),
            vec!["value1".to_string(), "value2".to_string()],
        );
        map.insert(
            "key2".to_string(),
            vec!["value3".to_string(), "value4".to_string()],
        );

        let dn = "CN=Thing,OU=Unit,DC=example,DC=org";
        let entry = SearchEntry {
            dn: dn.to_string(),
            attrs: map,
            bin_attrs: HashMap::new(),
        };

        let test = to_multi_value::<TestMultiValued>(entry);

        let test = test.unwrap();
        assert_eq!(test.key1, vec!["value1".to_string(), "value2".to_string()]);
        assert_eq!(test.key2, vec!["value3".to_string(), "value4".to_string()]);
        assert_eq!(test.dn, dn);
    }

    #[test]
    fn create_single_value_test() {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        map.insert("key1".to_string(), vec!["value1".to_string()]);
        map.insert("key2".to_string(), vec!["value2".to_string()]);
        map.insert("key4".to_string(), vec!["value4".to_string()]);

        let dn = "CN=Thing,OU=Unit,DC=example,DC=org";

        let entry = SearchEntry {
            dn: dn.to_string(),
            attrs: map,
            bin_attrs: HashMap::new(),
        };

        let test = to_signle_value::<TestSingleValued>(entry);

        let test = test.unwrap();
        assert_eq!(test.key1, "value1".to_string());
        assert_eq!(test.key2, "value2".to_string());
        assert!(test.key3.is_none());
        assert_eq!(test.key4.unwrap(), "value4".to_string());
        assert_eq!(test.dn, dn);
    }

    #[test]
    fn create_to_value_string_test() {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        map.insert("key1".to_string(), vec!["value1".to_string()]);
        map.insert("key2".to_string(), vec!["value2".to_string()]);
        map.insert("key4".to_string(), vec!["value4".to_string()]);
        map.insert(
            "key5".to_string(),
            vec!["value5".to_string(), "value6".to_string()],
        );

        let dn = "CN=Thing,OU=Unit,DC=example,DC=org";

        let entry = SearchEntry {
            dn: dn.to_string(),
            attrs: map,
            bin_attrs: HashMap::new(),
        };

        let test = to_value::<TestValued>(entry);

        let test = test.unwrap();
        assert_eq!(test.key1, "value1".to_string());
        assert!(test.key3.is_none());
        let key4 = test.key4;
        assert_eq!(key4[0], "value4".to_string());
        let key5 = test.key5;
        assert_eq!(key5[0], "value5".to_string());
        assert_eq!(key5[1], "value6".to_string());

        assert_eq!(test.dn, dn);
    }

    #[test]
    fn binary_single_to_value_test() -> anyhow::Result<()> {
        #[derive(Deserialize)]
        struct TestMultivalueBinary {
            pub uuids: Uuid,
            pub key1: String,
        }

        let (bytes, correct_string_representation) = get_binary_uuid();

        let entry = SearchEntry {
            dn: String::from("CN=Thing,OU=Unit,DC=example,DC=org"),
            attrs: HashMap::from([(String::from("key1"), vec![String::from("value1")])]),
            bin_attrs: HashMap::from([(String::from("uuids"), vec![bytes])]),
        };

        let test = to_value::<TestMultivalueBinary>(entry).unwrap();

        let string_uuid = test.uuids.hyphenated().to_string();
        assert_eq!(string_uuid, correct_string_representation);
        Ok(())
    }

    // #[test] // This test is not working, because the OneOrMany trait is not implemented for Uuid. Will fix this later.
    fn binary_multi_to_value_test() -> anyhow::Result<()> {
        #[serde_as]
        #[derive(Deserialize)]
        struct TestMultivalueBinary {
            #[serde_as(as = "OneOrMany<_>")]
            pub uuids: Vec<Uuid>,
            pub key1: String,
        }

        let (bytes, correct_string_representation) = get_binary_uuid();

        let entry = SearchEntry {
            dn: String::from("CN=Thing,OU=Unit,DC=example,DC=org"),
            attrs: HashMap::from([(String::from("key1"), vec![String::from("value1")])]),
            bin_attrs: HashMap::from([(String::from("uuids"), vec![bytes])]),
        };

        let test = to_value::<TestMultivalueBinary>(entry).unwrap();

        match test.uuids.as_slice() {
            [one] => {
                let string_uuid = one.hyphenated().to_string();
                assert_eq!(string_uuid, correct_string_representation);
                Ok(())
            }
            [..] => Err(anyhow!("There was supposed to be exactly one uuid.")),
        }
    }

    #[derive(Debug, Deserialize)]
    struct TestMultiValued {
        dn: String,
        key1: Vec<String>,
        key2: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    struct TestSingleValued {
        dn: String,
        key1: String,
        key2: String,
        key3: Option<String>,
        key4: Option<String>,
    }

    #[serde_as]
    #[derive(Debug, Deserialize)]
    struct TestValued {
        dn: String,
        key1: String,
        key3: Option<String>,
        #[serde_as(as = "OneOrMany<_>")]
        key4: Vec<String>,
        #[serde_as(as = "OneOrMany<_>")]
        key5: Vec<String>,
    }
    /// Get the binary and hyphenated string representations of an UUID for testing.
    fn get_binary_uuid() -> (Vec<u8>, String) {
        // Exaple grabbed from uuid docs:
        // https://docs.rs/uuid/latest/uuid/struct.Uuid.html#method.from_bytes
        let bytes = vec![
            0xa1, 0xa2, 0xa3, 0xa4, 0xb1, 0xb2, 0xc1, 0xc2, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6,
            0xd7, 0xd8,
        ];

        let correct_string_representation = String::from("a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8");

        (bytes, correct_string_representation)
    }

    #[test]
    fn deserialize_binary_multi_value_test() -> anyhow::Result<()> {
        #[derive(Deserialize)]
        struct TestMultivalueBinary {
            pub uuids: Vec<Uuid>,
        }

        let (bytes, correct_string_representation) = get_binary_uuid();

        let entry = SearchEntry {
            dn: String::from("CN=Thing,OU=Unit,DC=example,DC=org"),
            attrs: HashMap::new(),
            bin_attrs: HashMap::from([(String::from("uuids"), vec![bytes])]),
        };

        let record = Record {
            search_entry: entry,
        };

        let deserialized: TestMultivalueBinary = record.to_multi_valued_record_()?;

        match deserialized.uuids.as_slice() {
            [one] => {
                let string_uuid = one.hyphenated().to_string();
                assert_eq!(string_uuid, correct_string_representation);
                Ok(())
            }
            [..] => Err(anyhow!("There was supposed to be exactly one uuid.")),
        }
    }

    #[test]
    fn deserialize_binary_single_value_test() -> anyhow::Result<()> {
        #[derive(Deserialize)]
        struct TestSingleValueBinary {
            pub uuid: Uuid,
        }

        let (bytes, correct_string_representation) = get_binary_uuid();

        let entry = SearchEntry {
            dn: String::from("CN=Thing,OU=Unit,DC=example,DC=org"),
            attrs: HashMap::new(),
            bin_attrs: HashMap::from([(String::from("uuid"), vec![bytes])]),
        };

        let record = Record {
            search_entry: entry,
        };

        let deserialized: TestSingleValueBinary = record.to_record()?;

        let string_uuid = deserialized.uuid.hyphenated().to_string();
        assert_eq!(string_uuid, correct_string_representation);

        Ok(())
    }
}

// Add readme examples to doctests:
// https://doc.rust-lang.org/rustdoc/write-documentation/documentation-tests.html#include-items-only-when-collecting-doctests
#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;
