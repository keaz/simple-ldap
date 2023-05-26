use std::collections::HashMap;

use ldap3::{Ldap, LdapConnAsync, SearchEntry, Scope};

const LDAP_ENTRY_DN: [&str; 1] = ["entryDN"];

pub struct LdapClient {
    pub ldap: Ldap,
}

impl LdapClient {
    
    pub async fn from(url: &str, bind_dn: &str, bind_pw: &str) -> Self{
        let (conn, mut ldap) = LdapConnAsync::new(url)
            .await
            .unwrap();

        ldap3::drive!(conn);
        ldap.simple_bind(bind_dn, bind_pw)
            .await
            .unwrap()
            .success()
            .unwrap();

        LdapClient { ldap }
    }


    pub async fn authenticate(
        &mut self,
        base: &str,
        uid: String,
        password: &String,
        filter: Box<dyn Filter>
    ) -> Result<(), LdapError> {

        let rs = self
            .ldap
            .search(base, Scope::OneLevel, filter.filter().as_str(), LDAP_ENTRY_DN)
            .await
            .unwrap();
        let (data, _rs) = rs.success().unwrap();
        if data.is_empty() {
            return Err(LdapError::NotFound(format!("No user found {:?}", uid)));
        }

        if data.len() > 1 {
            return Err(LdapError::MultipleResults(format!(
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
        if let Err(_) = result {
            return Err(LdapError::AuthenticationFailed(format!(
                "Error authenticating user: {:?}",
                uid
            )));
        }

        let result = result.unwrap().success();
        if let Err(_) = result {
            return Err(LdapError::AuthenticationFailed(format!(
                "Error authenticating user: {:?}",
                uid
            )));
        }

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
pub enum LdapError {
    Query(String),
    NotFound(String),
    MultipleResults(String),
    AuthenticationFailed(String),
    Create(String),
    Update(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        // let result = add(2, 2);
        // assert_eq!(result, 4);
    }
}
