use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub mod serde_str {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::str::FromStr;

    pub fn serialize<S, T: ToString>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = data.to_string();
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D, T: FromStr>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        T::from_str(&s).map_err(|_| serde::de::Error::custom(format!("{s:?}")))
    }
}

pub mod serde_opt_str {
    use super::serde_str;
    use serde::{
        self, Deserialize, Deserializer, Serialize, Serializer,
        de::{self, Visitor},
    };
    use std::fmt;
    use std::marker::PhantomData;
    use std::str::FromStr;

    pub fn serialize<S, T: ToString>(data: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match data {
            Some(data) => serde_str::serialize(data, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D, T: FromStr>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        D: Deserializer<'de>,
    {
        serde_str::deserialize(deserializer)
            .map(Some)
            .or_else(|err| {
                if err.to_string().contains("invalid type: null") {
                    Ok(None)
                } else {
                    Err(err)
                }
            })
    }
}

pub struct Stringable<T>(T);

impl<'de, T: FromStr> Deserialize<'de> for Stringable<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        T::from_str(&s)
            .map_err(|_| serde::de::Error::custom(format!("{s:?}")))
            .map(Self)
    }
}

impl<T: ToString> Serialize for Stringable<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = self.0.to_string();
        serializer.serialize_str(&s)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use serde::{Deserialize, Serialize};

    #[test]
    fn test_serde_str() {
        #[derive(Debug, Serialize, Deserialize)]
        struct A {
            #[serde(with = "serde_opt_str")]
            b: Option<B>,

            #[serde(with = "serde_opt_str")]
            b2: Option<B>,
        }

        #[derive(Debug, PartialEq, Eq)]
        pub struct B(usize);

        impl FromStr for B {
            type Err = ();

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                usize::from_str(s).map(B).map_err(|_| ())
            }
        }

        impl std::fmt::Display for B {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        let a = r#"
        { "b": "100", "b2": null }
        "#;

        let a: A = serde_json::from_str(a).unwrap();

        assert_eq!(a.b, Some(B(100)));

        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            "{\"b\":\"100\",\"b2\":null}"
        );
    }
}
