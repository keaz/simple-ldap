//! A type representing a simple Distinguished Name.
//!
//! E.g. "CN=Tea,OU=Leaves,OU=Are,DC=Great,DC=Org"
//!
//! The LDAP spec formally allows you to include almost anything in a DN, but these features are
//! rarely used. This simple DN representation covers the common cases, and is easy to work with.
//!

use chumsky::{
    error::Rich,
    extra,
    prelude::{any, just, none_of},
    IterParser, Parser,
};
use itertools::{EitherOrBoth, Itertools};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::{cmp::Ordering, fmt::Display, str::FromStr};
use thiserror::Error;

/// LDAP Distinguished Name
///
/// Only deals with the common DNs of the form:
/// "CN=Tea,OU=Leaves,OU=Are,DC=Great,DC=Org"
///
/// Multivalued relative DNs and unprintable characters are not supported,
/// and neither is the empty DN.
///
/// ```
/// use simple_ldap::SimpleDN;
/// use std::str::FromStr;
///
/// // Create a new DN from a string slice
/// let dn = SimpleDN::from_str("CN=hong,OU=cha,DC=tea").unwrap();
/// ```
///
/// If you do need to handle more exotic DNs, have a look at the crate [`ldap_types`](https://docs.rs/ldap-types/latest/ldap_types/basic/struct.DistinguishedName.html).
#[derive(Debug, DeserializeFromStr, SerializeDisplay, Clone, PartialEq, Eq)]
pub struct SimpleDN {
    /// The relative distinguished names of this DN.
    /// I.e. the individual key-value pairs.
    ///
    /// The ordering is that of the print representation.
    /// I.e. the leftmost element gets index 0.
    ///
    /// **Invariant: This is never empty.**
    rdns: Vec<SimpleRDN>,
}

impl Display for SimpleDN {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Just interspacing formatted rdns with commas.
        write!(f, "{}", self.rdns.iter().format(","))
    }
}

impl FromStr for SimpleDN {
    type Err = SimpleDnParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match simple_dn_parser().parse(s).into_result() {
            Ok(simple_rdn) => Ok(simple_rdn),
            Err(rich_errors) => Err(SimpleDnParseError {
                errors: rich_errors
                    .into_iter()
                    // This step gets rid of the lifetime parameters.
                    .map(|rich_err| ToString::to_string(&rich_err))
                    .collect(),
            }),
        }
    }
}

/// Partial ordering is implemented according to DN ancestry.
/// I.e. A DN being "bigger" than another means that it is the ancestor of the other.
impl PartialOrd for SimpleDN {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let most_significant_differing_rdn = self
            .rdns
            .iter()
            .rev()
            .zip_longest(other.rdns.iter().rev())
            .find(
                |maybe_both| !matches!(maybe_both, EitherOrBoth::Both(this, that) if this == that),
            );

        match most_significant_differing_rdn {
            // There were no differences.
            None => Some(Ordering::Equal),
            Some(maybe_both) => match maybe_both {
                // DNs branch, and aren't comparable.
                EitherOrBoth::Both(_, _) => None,
                // DNs are equal, except this one is longer.
                // Thus this is a child of the other.
                EitherOrBoth::Left(_) => Some(Ordering::Less),
                EitherOrBoth::Right(_) => Some(Ordering::Greater),
            },
        }
    }
}

fn simple_dn_parser<'src>() -> impl Parser<'src, &'src str, SimpleDN, extra::Err<Rich<'src, char>>>
{
    simple_rdn_parser()
        // Just parsing a list of RDNs.
        .separated_by(just(','))
        .collect::<Vec<SimpleRDN>>()
        .map(|rdns| SimpleDN { rdns })
}

/// Convenience operations for DNs.
impl SimpleDN {
    /// Get the value of the first occurrance of the argument RDN key.
    ///
    /// E.g. Getting "OU" from "CN=Teas,OU=Are,OU=Really,DC=Awesome" results in "Are".
    ///
    /// Probably this only makes sense in keys like "CN" that are expected to be unique.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.rdns
            .iter()
            .find(|rdn| rdn.key == key)
            .map(|rdn| rdn.value.as_str())
    }

    /// Like `get()` but returns all the RDNs starting from the asked key.
    pub fn get_starting_from(&self, key: &str) -> Option<SimpleDN> {
        self.rdns
            .iter()
            .position(|rdn| rdn.key == key)
            .map(|position| {
                let (_, tail) = self.rdns.as_slice().split_at(position);

                SimpleDN {
                    rdns: tail.to_owned(),
                }
            })
    }

    /// Get the type of this DN.
    /// The kind of object it denominates.
    /// I.e. the key of the first RDN.
    ///
    /// E.g. the type of "OU=Tea,DC=Drinker" is "OU".
    ///
    /// If you want the value too, you can follow this up with `get()`.
    pub fn get_type(&self) -> &str {
        #[allow(clippy::expect_used, reason = "Relying on struct invariant.")]
        &self
            .rdns
            .first()
            .expect("Invariant violation. SimpleDN should never be empty.")
            .key
    }

    /// Get the parent DN of this one, if there is one.
    ///
    /// E.g. The parent "OU=Puerh,DC=Tea" is "DC=Tea".
    pub fn parent(&self) -> Option<SimpleDN> {
        match self.rdns.as_slice() {
            [_, rest @ ..] if !rest.is_empty() => Some(SimpleDN {
                rdns: rest.to_owned(),
            }),
            _ => None,
        }
    }
}

/// LDAP Relative Distinguished Name
///
/// I.e. a single key-value pair like "OU=Matcha" in DN "CN=Whisk,OU=Matcha,DC=Tea".
///
/// Only deals with RDN's with a single printable key-value pair.
///
/// <https://ldapwiki.com/wiki/Wiki.jsp?page=Relative%20Distinguished%20Name>
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
#[display("{key}={value}")]
struct SimpleRDN {
    /// Common examples include: CN, OU, DC
    ///
    /// OIDs are not supported here.
    //  (Though we arent' doing anything to prevent them either.)
    pub key: String,
    pub value: String,
}

/// Parse a single RDN.
/// This isn't a faithfull reproduction of the LDAP spec,
/// just dealing with the common case like this:
///
/// "CN=Tea Drinker"
fn simple_rdn_parser<'src>() -> impl Parser<'src, &'src str, SimpleRDN, extra::Err<Rich<'src, char>>>
{
    let rdn_key = any()
        // This probably doesn't quite conform to the spec.
        .filter(|c: &char| c.is_ascii_alphanumeric())
        .repeated()
        .at_least(1)
        .collect::<String>()
        // Consume the delimiting equals here too.
        .then_ignore(just('='));

    // Just making sure that this is not a multivalued rdn.
    // These we don't support.
    let rdn_value = none_of("+=,").repeated().at_least(1).collect::<String>();

    // Finally combine the RDN
    rdn_key
        .then(rdn_value)
        .map(|(key, value)| SimpleRDN { key, value })
}

#[derive(Error, Debug)]
#[error("Couldn't parse DN: {:?}", self.errors)]
pub struct SimpleDnParseError {
    // Have to store these here as strings, because the actuly `Rich`
    // type has a lifetime parameter, which we don't want to propagate upwards.
    errors: Vec<String>,
}

#[cfg(test)]
mod tests {

    use super::*;
    use serde::{Deserialize, Serialize};

    static EXAMPLE_DN: &str = "CN=Yabukita,OU=Green,OU=Tea,DC=Japan";

    static EXAMPLE_DN_QUOTED: &str = "\"CN=Yabukita,OU=Green,OU=Tea,DC=Japan\"";

    /// Get a SimpleDN corresponding to `EXAMPLE_DN` above.
    fn example_simple_dn() -> SimpleDN {
        SimpleDN {
            rdns: vec![
                SimpleRDN {
                    key: String::from("CN"),
                    value: String::from("Yabukita"),
                },
                SimpleRDN {
                    key: String::from("OU"),
                    value: String::from("Green"),
                },
                SimpleRDN {
                    key: String::from("OU"),
                    value: String::from("Tea"),
                },
                SimpleRDN {
                    key: String::from("DC"),
                    value: String::from("Japan"),
                },
            ],
        }
    }

    #[test]
    fn parse_simple_rdn_ok() {
        let key = "CN";
        let value = "Tea Drinker";

        let unstructured = String::new() + key + "=" + value;

        let rdn = simple_rdn_parser()
            .parse(&unstructured)
            .into_result()
            .unwrap();

        assert_eq!(key, rdn.key);
        assert_eq!(value, rdn.value);
    }

    #[test]
    fn parse_simple_rdn_fail() {
        let key = "CN";
        let value = "Tea Drinker";

        let unstructured = String::new() + key + "=" + value + "+ANOTHER=5";

        let parse_result = simple_rdn_parser().parse(&unstructured).into_result();

        let errors = parse_result.unwrap_err();

        println!("{errors:#?}");
    }

    #[test]
    fn parse_sipmle_dn_ok() {
        let parsed_dn = simple_dn_parser().parse(EXAMPLE_DN).into_result().unwrap();

        assert_eq!(parsed_dn, example_simple_dn());
    }

    #[test]
    fn dispaly_simple_dn() {
        let displayed = example_simple_dn().to_string();
        assert_eq!(displayed, EXAMPLE_DN);
    }

    /// For testing serde implementations.
    #[derive(Debug, Deserialize, Serialize)]
    #[serde(transparent)]
    struct DnStruct {
        pub dn: SimpleDN,
    }

    impl DnStruct {
        fn example() -> Self {
            DnStruct {
                dn: example_simple_dn(),
            }
        }
    }

    #[test]
    fn serialize() -> anyhow::Result<()> {
        let serialized = serde_json::to_string(&DnStruct::example())?;
        assert_eq!(serialized, EXAMPLE_DN_QUOTED);
        Ok(())
    }

    #[test]
    fn deserialize() -> anyhow::Result<()> {
        let deserialized: DnStruct = serde_json::from_str(EXAMPLE_DN_QUOTED)?;
        assert_eq!(deserialized.dn, DnStruct::example().dn);
        Ok(())
    }

    #[test]
    fn get() {
        let example_dn = example_simple_dn();

        assert_eq!(example_dn.get("OU"), Some("Green"));
        assert_eq!(example_dn.get("CN"), Some("Yabukita"));
        assert_eq!(example_dn.get("Nonsense"), None);
    }

    #[test]
    fn get_type() {
        assert_eq!(example_simple_dn().get_type(), "CN");
    }

    #[test]
    fn get_parent() {
        let parent = example_simple_dn().parent();
        let correct_parent = SimpleDN {
            rdns: vec![
                SimpleRDN {
                    key: String::from("OU"),
                    value: String::from("Green"),
                },
                SimpleRDN {
                    key: String::from("OU"),
                    value: String::from("Tea"),
                },
                SimpleRDN {
                    key: String::from("DC"),
                    value: String::from("Japan"),
                },
            ],
        };

        assert_eq!(parent, Some(correct_parent.clone()));

        let no_parents = SimpleDN {
            rdns: vec![SimpleRDN {
                key: String::from("DC"),
                value: String::from("Tea"),
            }],
        };

        assert_eq!(no_parents.parent(), None);
    }

    #[test]
    fn get_starting_from() {
        let example_dn = example_simple_dn();

        let got = example_dn.get_starting_from("OU");
        let correct = example_dn.parent();

        assert!(got.is_some());
        assert_eq!(got, correct);

        let non_existent = example_dn.get_starting_from("Coffee");
        assert_eq!(non_existent, None);
    }

    #[test]
    fn get_type_starting_from() {
        let example_dn = example_simple_dn();

        let dn_type = example_dn.get_type();
        let starting_from = example_dn.get_starting_from(dn_type);

        // This should always be true.
        assert_eq!(starting_from, Some(example_dn));
    }

    #[test]
    fn partial_compare() {
        let reflexivity = example_simple_dn().partial_cmp(&example_simple_dn());
        assert_eq!(reflexivity, Some(Ordering::Equal));

        let great = SimpleDN {
            rdns: vec![SimpleRDN {
                key: String::from("DC"),
                value: String::from("Big"),
            }],
        };

        let lesser = SimpleDN {
            rdns: vec![
                SimpleRDN {
                    key: String::from("OU"),
                    value: String::from("Medium"),
                },
                SimpleRDN {
                    key: String::from("DC"),
                    value: String::from("Big"),
                },
            ],
        };

        assert_eq!(great.partial_cmp(&lesser), Some(Ordering::Greater));
        assert_eq!(lesser.partial_cmp(&great), Some(Ordering::Less));

        // To lesser
        let incomparable = SimpleDN {
            rdns: vec![
                SimpleRDN {
                    key: String::from("OU"),
                    value: String::from("Else"),
                },
                SimpleRDN {
                    key: String::from("DC"),
                    value: String::from("Big"),
                },
            ],
        };

        assert!(lesser.partial_cmp(&incomparable).is_none());
        assert!(incomparable.partial_cmp(&lesser).is_none());
    }
}
