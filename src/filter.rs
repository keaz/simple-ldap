//! # Filter
//!
//! This module contains the implementation of the LDAP filter.
//!

/// The `Filter` trait is implemented by all the filters.
pub trait Filter: Send {
    fn filter(&self) -> String;
}

/// The `AndFilter` struct represents an AND filter.
#[derive(Default)]
pub struct AndFilter {
    filters: Vec<Box<dyn Filter>>,
}

impl AndFilter {
    /// Creates a new `AndFilter`.
    ///
    /// # Examples
    ///
    /// ```
    /// use simple_ldap::filter::AndFilter;
    ///
    /// let filter = AndFilter::new();
    /// ```
    #[deprecated(
        since = "1.3.2",
        note = "Please use the `Default` trait instead of this method."
    )]
    pub fn new() -> Self {
        AndFilter {
            filters: Vec::new(),
        }
    }

    /// Adds a filter to the `AndFilter`.
    ///
    /// # Arguments
    /// * `filter` - The filter to add.
    ///
    /// # Examples
    ///
    /// ```
    /// use simple_ldap::filter::{AndFilter, EqFilter};
    ///
    /// let mut filter = AndFilter::new();
    /// filter.add(Box::new(EqFilter::from("cn".to_string(), "test".to_string())));
    /// ```
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

/// The `OrFilter` struct represents an OR filter.
#[derive(Default)]
pub struct OrFilter {
    filters: Vec<Box<dyn Filter>>,
}

impl OrFilter {
    /// Creates a new `OrFilter`.
    ///
    /// # Examples
    ///
    /// ```
    /// use simple_ldap::filter::OrFilter;
    ///
    /// let filter = OrFilter::new();
    /// ```
    #[deprecated(
        since = "1.3.2",
        note = "Please use the `Default` trait instead of this method."
    )]
    pub fn new() -> Self {
        OrFilter {
            filters: Vec::new(),
        }
    }

    /// Adds a filter to the `OrFilter`.
    ///
    /// # Arguments
    /// * `filter` - The filter to add.
    ///
    /// # Examples
    ///
    /// ```
    /// use simple_ldap::filter::{OrFilter, EqFilter};
    ///
    /// let mut filter = OrFilter::new();
    /// filter.add(Box::new(EqFilter::from("cn".to_string(), "test".to_string())));
    /// ```
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

/// The `EqFilter` struct represents an equality filter.
pub struct EqFilter {
    attribute: String,
    value: String,
}

impl EqFilter {
    /// Creates a new `EqFilter`.
    ///
    /// # Arguments
    /// * `attribute` - The attribute to filter.
    /// * `value` - The value of the attribute.
    ///
    /// # Examples
    ///
    /// ```
    /// use simple_ldap::filter::EqFilter;
    ///
    /// let filter = EqFilter::from("cn".to_string(), "test".to_string());
    /// ```
    pub fn from(attribute: String, value: String) -> Self {
        EqFilter { attribute, value }
    }
}

impl Filter for EqFilter {
    fn filter(&self) -> String {
        format!("({}={})", self.attribute, self.value)
    }
}

/// The `NotFilter` struct represents a NOT filter.
/// This filter represents the negation of another filter. This is equal to LDAP `!` operator.
pub struct NotFilter {
    filter: Box<dyn Filter>,
}

impl NotFilter {
    /// Creates a new `NotFilter`.
    ///
    /// # Arguments
    /// * `filter` - The filter to negate.
    ///
    /// # Examples
    ///
    /// ```
    /// use simple_ldap::filter::{NotFilter, EqFilter};
    ///
    /// let filter = NotFilter::from(Box::new(EqFilter::from("cn".to_string(), "test".to_string())));
    /// ```
    pub fn from(filter: Box<dyn Filter>) -> Self {
        NotFilter { filter }
    }
}

impl Filter for NotFilter {
    fn filter(&self) -> String {
        format!("(!{})", self.filter.filter())
    }
}

/// The `LikeFilter` struct represents a LIKE filter.
/// This generates a ldap filter with a wildcard on the left or on the right of the value.
pub struct LikeFilter {
    attribute: String,
    value: String,
    wildcard_on: WildardOn,
}

/// The `WildardOn` enum represents the wildcard position.
pub enum WildardOn {
    /// The wildcard is on the left of the value.
    Pre,
    /// The wildcard is on the right of the value.
    Post,
}

impl LikeFilter {
    /// Creates a new `LikeFilter`.
    ///
    /// # Arguments
    /// * `attribute` - The attribute to filter.
    /// * `value` - The value of the attribute.
    /// * `wildcard_on` - The wildcard position.
    ///
    /// # Examples
    ///
    /// ```
    /// use simple_ldap::filter::{LikeFilter, WildardOn};
    ///
    /// let filter = LikeFilter::from("cn".to_string(), "test".to_string(), WildardOn::Pre);
    /// ```
    pub fn from(attribute: String, value: String, wildcard_on: WildardOn) -> Self {
        LikeFilter {
            attribute,
            value,
            wildcard_on,
        }
    }
}

impl Filter for LikeFilter {
    fn filter(&self) -> String {
        match self.wildcard_on {
            WildardOn::Pre => format!("({}=*{})", self.attribute, self.value),
            WildardOn::Post => format!("({}={}*)", self.attribute, self.value),
        }
    }
}

/// The `ContainsFilter` struct represents a CONTAINS filter.
/// This generates a ldap filter that checks if the value is contained in the attribute.
pub struct ContainsFilter {
    attribute: String,
    value: String,
}

impl ContainsFilter {
    /// Creates a new `ContainsFilter`.
    ///
    /// # Arguments
    /// * `attribute` - The attribute to filter.
    /// * `value` - The value of the attribute.
    ///
    /// # Examples
    ///
    /// ```
    /// use simple_ldap::filter::ContainsFilter;
    ///
    /// let filter = ContainsFilter::from("cn".to_string(), "test".to_string());
    /// ```
    pub fn from(attribute: String, value: String) -> Self {
        ContainsFilter { attribute, value }
    }
}

impl Filter for ContainsFilter {
    fn filter(&self) -> String {
        format!("({}=*{}*)", self.attribute, self.value)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_eq_filter() {
        let filter = EqFilter {
            attribute: "cn".to_string(),
            value: "test".to_string(),
        };
        assert_eq!(filter.filter(), "(cn=test)");
    }

    #[test]
    fn test_not_eq_filter() {
        let filter = NotFilter::from(Box::new(EqFilter {
            attribute: "cn".to_string(),
            value: "test".to_string(),
        }));
        assert_eq!(filter.filter(), "(!(cn=test))");
    }

    #[test]
    fn test_pre_like_filter() {
        let filter = LikeFilter::from("cn".to_string(), "test".to_string(), WildardOn::Pre);
        assert_eq!(filter.filter(), "(cn=*test)");
    }

    #[test]
    fn test_post_like_filter() {
        let filter = LikeFilter::from("cn".to_string(), "test".to_string(), WildardOn::Post);
        assert_eq!(filter.filter(), "(cn=test*)");
    }

    #[test]
    fn test_or_filter() {
        let mut or_filter = OrFilter::default();
        or_filter.add(Box::new(EqFilter {
            attribute: "cn".to_string(),
            value: "test".to_string(),
        }));
        or_filter.add(Box::new(EqFilter {
            attribute: "cn".to_string(),
            value: "test2".to_string(),
        }));
        assert_eq!(or_filter.filter(), "(|(cn=test)(cn=test2))");
    }

    #[test]
    fn test_and_filter() {
        let mut and_filter = AndFilter::default();
        and_filter.add(Box::new(EqFilter {
            attribute: "cn".to_string(),
            value: "test".to_string(),
        }));
        and_filter.add(Box::new(EqFilter {
            attribute: "cn".to_string(),
            value: "test2".to_string(),
        }));
        assert_eq!(and_filter.filter(), "(&(cn=test)(cn=test2))");
    }

    #[test]
    fn test_contains_filter() {
        let filter = ContainsFilter::from("cn".to_string(), "test".to_string());
        assert_eq!(filter.filter(), "(cn=*test*)");
    }
}
