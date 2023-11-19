use crate::libdns::proto::rr::Name;
use enum_dispatch::enum_dispatch;
use std::{collections::HashSet, path::PathBuf, str::FromStr};
use url::Url;

use anyhow::Result;

#[enum_dispatch(IDomainSetProvider)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainSetProvider {
    File(DomainSetFileProvider),
    Http(DomainSetHttpProvider),
}

#[enum_dispatch]
pub trait IDomainSetProvider {
    fn name(&self) -> &str;

    fn get_domain_set(&self) -> Result<HashSet<Name>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainSetFileProvider {
    pub name: String,
    pub file: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainSetHttpProvider {
    pub name: String,
    pub url: Url,
    pub interval: Option<usize>,
}

impl IDomainSetProvider for DomainSetFileProvider {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn get_domain_set(&self) -> Result<HashSet<Name>> {
        let mut domain_set = HashSet::new();

        if self.file.exists() {
            let text = std::fs::read_to_string(&self.file)?;
            read_to_domain_set(&text, &mut domain_set);
        }

        Ok(domain_set)
    }
}

impl IDomainSetProvider for DomainSetHttpProvider {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn get_domain_set(&self) -> Result<HashSet<Name>> {
        use reqwest::blocking as http;

        let mut domain_set = HashSet::new();
        let res = http::get(self.url.clone())?;

        let text = res.text()?;
        read_to_domain_set(&text, &mut domain_set);
        Ok(domain_set)
    }
}

fn read_to_domain_set(s: &str, domain_set: &mut HashSet<Name>) {
    for line in s.lines() {
        let line = line.trim_start();
        if line.starts_with('#') {
            continue;
        }
        let mut parts = line.split(' ');

        if let Some(n) = parts.next().and_then(|n| Name::from_str(n).ok()) {
            domain_set.insert(n);
        }
    }
}
