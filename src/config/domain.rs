use crate::libdns::proto::rr::Name;
use std::ops::Deref;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WildcardName {
    /// Match domain suffix, include itself.
    ///
    /// examples:
    ///   /example.com/      => match: a.example.com, b.a.example.com;
    Default(Name),

    /// The + wildcard can match domain suffix.
    ///
    /// examples:
    ///   /+.example.com/    => match: a.example.com, b.a.example.com; but not match: example.com
    ///   /.example.com/
    Suffix(Name),

    /// The * wildcard can only match one-level domains.
    /// examples:
    ///   /*.example.com/    => match: a.example.com, b.example.com; but not match: example.com, b.a.example.com
    Sub(Name),

    /// Match full domain.
    ///
    /// examples:
    /// /-.example.com/     => match: example.com
    Full(Name),
}

impl WildcardName {
    pub fn is_match(&self, name: &Name) -> bool {
        match self {
            WildcardName::Default(n) => n.zone_of(name),
            WildcardName::Suffix(n) => !n.eq_ignore_root_case(name) && n.zone_of(name),
            WildcardName::Sub(n) => n.eq_ignore_root_case(&name.base_name()),
            WildcardName::Full(n) => n.eq_ignore_root_case(name),
        }
    }
}

impl std::cmp::PartialOrd for WildcardName {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for WildcardName {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering::*;
        match self.deref().cmp(other.deref()) {
            Less => Less,
            Greater => Greater,
            Equal => {
                let ord = |w: &WildcardName| match w {
                    WildcardName::Default(_) => 3u8,
                    WildcardName::Suffix(_) => 2,
                    WildcardName::Sub(_) => 1,
                    WildcardName::Full(_) => 0,
                };
                let a = ord(self);
                let b = ord(other);
                a.cmp(&b)
            }
        }
    }
}

impl std::ops::Deref for WildcardName {
    type Target = Name;

    fn deref(&self) -> &Self::Target {
        match self {
            WildcardName::Default(n) => n,
            WildcardName::Suffix(n) => n,
            WildcardName::Sub(n) => n,
            WildcardName::Full(n) => n,
        }
    }
}

impl std::ops::DerefMut for WildcardName {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            WildcardName::Default(n) => n,
            WildcardName::Suffix(n) => n,
            WildcardName::Sub(n) => n,
            WildcardName::Full(n) => n,
        }
    }
}

impl std::fmt::Display for WildcardName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WildcardName::Default(n) => write!(f, "{n}"),
            WildcardName::Suffix(n) => write!(f, "+.{n}"),
            WildcardName::Sub(n) => write!(f, "*.{n}"),
            WildcardName::Full(n) => write!(f, "-.{n}"),
        }
    }
}

impl std::convert::From<Name> for WildcardName {
    fn from(value: Name) -> Self {
        if value.is_wildcard() {
            Self::Sub(value.base_name())
        } else {
            Self::Default(value)
        }
    }
}

impl From<WildcardName> for Name {
    fn from(val: WildcardName) -> Self {
        match val {
            WildcardName::Default(n) => n,
            WildcardName::Suffix(n) => n,
            WildcardName::Sub(n) => n,
            WildcardName::Full(n) => n,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Domain {
    Name(WildcardName),
    Set(String),
}

impl std::fmt::Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Domain::Name(n) => write!(f, "{n}"),
            Domain::Set(n) => write!(f, "domain-set:{n}"),
        }
    }
}

impl From<Domain> for String {
    fn from(value: Domain) -> Self {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::WildcardName;

    #[test]
    fn test_wildcard_name_default() {
        let wildcard_name = WildcardName::from_str("example.com").unwrap();

        assert!(wildcard_name.is_match(&"example.com".parse().unwrap()));
        assert!(wildcard_name.is_match(&"a.example.com".parse().unwrap()));
        assert!(wildcard_name.is_match(&"b.a.example.com".parse().unwrap()));
    }

    #[test]
    fn test_wildcard_name_suffix() {
        let wildcard_name = WildcardName::from_str("+.example.com").unwrap();

        assert!(!wildcard_name.is_match(&"example.com".parse().unwrap()));
        assert!(wildcard_name.is_match(&"a.example.com".parse().unwrap()));
        assert!(wildcard_name.is_match(&"b.a.example.com".parse().unwrap()));
    }

    #[test]
    fn test_wildcard_name_sub() {
        let wildcard_name = WildcardName::from_str("*.example.com").unwrap();

        assert!(!wildcard_name.is_match(&"example.com".parse().unwrap()));
        assert!(wildcard_name.is_match(&"a.example.com".parse().unwrap()));
        assert!(!wildcard_name.is_match(&"b.a.example.com".parse().unwrap()));
    }

    #[test]
    fn test_wildcard_name_full() {
        let wildcard_name = WildcardName::from_str("-.example.com").unwrap();

        assert!(wildcard_name.is_match(&"example.com".parse().unwrap()));
        assert!(!wildcard_name.is_match(&"a.example.com".parse().unwrap()));
        assert!(!wildcard_name.is_match(&"b.a.example.com".parse().unwrap()));
    }
}
