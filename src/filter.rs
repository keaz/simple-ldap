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

impl EqFilter {
    pub fn from(attribute: String, value: String) -> Self {
        EqFilter { attribute, value }
    }
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
    pre: bool,
}

impl Filter for LikeFilter {
    fn filter(&self) -> String {
        if self.pre {
            format!("({}=*{})", self.attribute, self.value)
        } else {
            format!("({}={}*)", self.attribute, self.value)
        }
    }
}

pub struct ContainsFilter {
    attribute: String,
    value: String,
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
        let filter = NotFilter::new(Box::new(EqFilter {
            attribute: "cn".to_string(),
            value: "test".to_string(),
        }));
        assert_eq!(filter.filter(), "(!(cn=test))");
    }

    #[test]
    fn test_pre_like_filter() {
        let filter = LikeFilter {
            attribute: "cn".to_string(),
            value: "test".to_string(),
            pre: true,
        };

        assert_eq!(filter.filter(), "(cn=*test)");
    }

    #[test]
    fn test_post_like_filter() {
        let filter = LikeFilter {
            attribute: "cn".to_string(),
            value: "test".to_string(),
            pre: false,
        };

        assert_eq!(filter.filter(), "(cn=test*)");
    }

    #[test]
    fn test_or_filter() {
        let mut or_filter = OrFilter::new();
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
        let mut and_filter = AndFilter::new();
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
        let filter = ContainsFilter {
            attribute: "cn".to_string(),
            value: "test".to_string(),
        };

        assert_eq!(filter.filter(), "(cn=*test*)");
    }
}
