//! Just some test code I used to checkt that it compiles.
//! Should be removed before release.

use simple_ldap::{
    filter::EqFilter,
    ldap3::Scope,
    Error, LdapClient, LdapConfig, Record
};
use url::Url;
use serde::Deserialize;
use futures::{Stream, StreamExt};
#[derive(Deserialize, Debug)]
struct User {
    uid: String,
    cn: String,
    sn: String,
}

#[tokio::main]
async fn main(){
    let ldap_config = LdapConfig {
        bind_dn: String::from("cn=manager"),
        bind_password: String::from("password"),
        ldap_url: Url::parse("ldaps://localhost:1389/dc=example,dc=com").unwrap(),
        dn_attribute: None,
        connection_settings: None
    };
    let mut client = LdapClient::new(ldap_config).await.unwrap();

    let stream = return_stream(&mut client).await;

    // The returned stream is not Unpin, so you may need to pin it to use certain operations,
    // such as next() below.
    let mut pinned_steam = Box::pin(stream);
    while let Some(result) = pinned_steam.next().await {
        match result {
            Ok(element) => {
                let user: User = element.to_record().unwrap();
                println!("User: {user:?}");
            }
            Err(err) => {
                println!("Error: {err:?}");
            }
        }
    }
}


/// With the arguments being `AsRef` it's easy to write functions like this,
/// where the arguments are neatly packaged in the return object.
async fn return_stream<'a>(client: &'a mut LdapClient) -> impl Stream<Item = Result<Record, Error>> + use<'a>
{
  let local_base = String::from("dog");
  let name_filter = EqFilter::from(String::from("cn"), String::from("Sam"));
  let local_attrs = vec!["cn"];

  client.streaming_search(
      local_base,
      Scope::OneLevel,
      name_filter,
      local_attrs
  ).await.unwrap()
}
