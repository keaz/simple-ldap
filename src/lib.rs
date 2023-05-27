use std::collections::{HashMap, HashSet};

use ldap3::{
    log::{debug, error},
    Ldap, LdapConnAsync, LdapError, Mod, Scope, SearchEntry, StreamState,
};

pub extern crate ldap3;

const LDAP_ENTRY_DN: [&str; 1] = ["entryDN"];

pub struct LdapClient {
    ldap: Ldap,
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

    ///
    /// Open a connection to an LDAP server specified by `url`.
    /// 
    pub async fn from(url: &str, bind_dn: &str, bind_pw: &str) -> Self {

        let (conn, mut ldap) = LdapConnAsync::new(url).await.unwrap();

        ldap3::drive!(conn);
        ldap.simple_bind(bind_dn, bind_pw)
            .await
            .unwrap()
            .success()
            .unwrap();

        LdapClient { ldap }
    }

    ///
    /// Create a new LdapClient from an existing Ldap connection.
    /// 
    pub fn from_ldap(ldap: Ldap) -> Self {
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
    pub async fn authenticate(
        &mut self,
        base: &str,
        uid: String,
        password: &String,
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
            return Err(Error::NotFound(format!("No user found {:?}", uid)));
        }

        if data.len() > 1 {
            return Err(Error::MultipleResults(format!(
                "Found multiple users for uid {:?}",
                uid
            )));
        }

        let user_record = data.get(0).unwrap().to_owned();
        let user_record = SearchEntry::construct(user_record);
        let result: HashMap<&str, String> = user_record
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
                format!("Error searching for user: {:?}", error),
                error,
            ));
        }
        let result = search.unwrap().success();
        if let Err(error) = result {
            return Err(Error::Query(
                format!("Error searching for user: {:?}", error),
                error,
            ));
        }

        let records = result.unwrap().0;

        if records.len() > 0 {
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
                format!("Error searching for user: {:?}", error),
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
    /// base = "ou=people,dc=abc,dc=com"
    ///
    pub async fn create<T: for<'a> serde::Deserialize<'a>>(
        &mut self,
        uid: &str,
        base: &str,
        data: Vec<(&str, HashSet<&str>)>,
    ) -> Result<(), Error> {
        let dn = format!("uid={},{}", uid, base);
        let save = self.ldap.add(dn.as_str(), data).await;
        if let Err(err) = save {
            return Err(Error::Create(format!("Error saving user: {:?}", err), err));
        }
        let save = save.unwrap().success();

        if let Err(err) = save {
            return Err(Error::Create(format!("Error saving user: {:?}", err), err));
        }
        let res = save.unwrap();
        debug!("Sucessfully created record result: {:?}", res);
        Ok(())
    }

    pub async fn update(
        &mut self,
        uid: &str,
        base: &str,
        data: Vec<Mod<&str>>,
        new_udid: Option<&str>,
    ) -> Result<(), Error> {
        let dn = format!("uid={},{}", uid, base);

        let res = self.ldap.modify(dn.as_str(), data).await;
        if let Err(err) = res {
            return Err(Error::Update(
                format!("Error updating user: {:?}", err),
                err,
            ));
        }

        let res = res.unwrap().success();
        if let Err(err) = res {
            return Err(Error::Update(
                format!("Error updating user: {:?}", err),
                err,
            ));
        }

        if new_udid.is_none() {
            return Ok(());
        }

        let new_udid = new_udid.unwrap();
        if !uid.eq_ignore_ascii_case(new_udid) {
            let new_dn = format!("uid={}", new_udid);
            let dn_update = self
                .ldap
                .modifydn(dn.as_str(), new_dn.as_str(), true, None)
                .await;
            if let Err(err) = dn_update {
                error!("Failed to update dn for user {:?} error {:?}", uid, err);
                return Err(Error::Update(
                    format!("Failed to update dn for user {:?}", uid),
                    err,
                ));
            }

            let dn_update = dn_update.unwrap().success();
            if let Err(err) = dn_update {
                error!("Failed to update dn for user {:?} error {:?}", uid, err);
                return Err(Error::Update(
                    format!("Failed to update dn for user {:?}", uid),
                    err,
                ));
            }

            let res = dn_update.unwrap();
            debug!("Sucessfully updated dn result: {:?}", res);
        }

        Ok(())
    }

    pub async fn delete(&mut self, uid: &str, base: &str) -> Result<(), Error> {
        let dn = format!("uid={},{}", uid, base);
        let delete = self.ldap.delete(dn.as_str()).await;

        if let Err(err) = delete {
            return Err(Error::Delete(
                format!("Error deleting user: {:?}", err),
                err,
            ));
        }
        let delete = delete.unwrap().success();
        if let Err(err) = delete {
            return Err(Error::Delete(
                format!("Error deleting user: {:?}", err),
                err,
            ));
        }
        let delete = delete.unwrap();
        debug!("Sucessfully deleted record result: {:?}", delete);
        Ok(())
    }
}

pub trait Filter {
    fn filter(&self) -> String;
}

pub struct AndFilter {
    filters: Vec<Box<dyn Filter>>,
}

impl AndFilter {
    pub fn new() -> Self {
        AndFilter {
            filters: Vec::new(),
        }
    }

    pub fn add(&mut self, filter: Box<dyn Filter>) {
        self.filters.push(filter);
    }
}

impl Filter for AndFilter {
    fn filter(&self) -> String {
        let mut filter = String::from("(&");
        for f in &self.filters {
            filter.push_str(&f.filter());
        }
        filter.push(')');
        filter
    }
}

pub struct OrFilter {
    filters: Vec<Box<dyn Filter>>,
}

impl OrFilter {
    pub fn new() -> Self {
        OrFilter {
            filters: Vec::new(),
        }
    }

    pub fn add(&mut self, filter: Box<dyn Filter>) {
        self.filters.push(filter);
    }
}

impl Filter for OrFilter {
    fn filter(&self) -> String {
        let mut filter = String::from("(|");
        for f in &self.filters {
            filter.push_str(&f.filter());
        }
        filter.push(')');
        filter
    }
}

pub struct EqFilter {
    attribute: String,
    value: String,
}

impl Filter for EqFilter {
    fn filter(&self) -> String {
        format!("({}={})", self.attribute, self.value)
    }
}

pub struct NotFilter {
    filter: Box<dyn Filter>,
}

impl NotFilter {
    pub fn new(filter: Box<dyn Filter>) -> Self {
        NotFilter { filter }
    }
}

impl Filter for NotFilter {
    fn filter(&self) -> String {
        format!("(!{})", self.filter.filter())
    }
}

pub struct LikeFilter {
    attribute: String,
    value: String,
}

impl Filter for LikeFilter {
    fn filter(&self) -> String {
        format!("({}~={})", self.attribute, self.value)
    }
}

#[derive(Debug)]
pub enum Error {
    Query(String, LdapError),
    NotFound(String),
    MultipleResults(String),
    AuthenticationFailed(String),
    Create(String, LdapError),
    Update(String, LdapError),
    Delete(String, LdapError),
    Mapping(String),
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

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
}
