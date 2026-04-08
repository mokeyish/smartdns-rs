use enum_dispatch::enum_dispatch;
use std::{
    collections::HashSet,
    hash::{DefaultHasher, Hash, Hasher},
    path::{Path, PathBuf},
    str::FromStr,
};
use url::Url;

use anyhow::Result;

use super::WildcardName;

#[enum_dispatch(IDomainSetProvider)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainSetProvider {
    File(DomainSetFileProvider),
    Http(DomainSetHttpProvider),
}

#[enum_dispatch]
pub trait IDomainSetProvider {
    fn name(&self) -> &str;

    fn get_domain_set(&self) -> Result<HashSet<WildcardName>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainSetFileProvider {
    pub name: String,
    pub file: PathBuf,
    pub content_type: DomainSetContentType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainSetHttpProvider {
    pub name: String,
    pub url: Url,
    pub interval: Option<usize>,
    pub content_type: DomainSetContentType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DomainSetHttpLoadSource {
    Remote,
    Cache,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DomainSetContentType {
    #[default]
    List,
}

impl IDomainSetProvider for DomainSetFileProvider {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn get_domain_set(&self) -> Result<HashSet<WildcardName>> {
        let mut domain_set = HashSet::new();
        let text = std::fs::read_to_string(&self.file)?;
        read_to_domain_set(&text, &mut domain_set);
        Ok(domain_set)
    }
}

impl IDomainSetProvider for DomainSetHttpProvider {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn get_domain_set(&self) -> Result<HashSet<WildcardName>> {
        use crate::infra::http_client::{self, HttpResponse};

        let mut domain_set = HashSet::new();
        let res = http_client::get(self.url.to_string())?;

        let text = res.text()?;
        read_to_domain_set(&text, &mut domain_set);
        Ok(domain_set)
    }
}

impl DomainSetHttpProvider {
    pub(crate) fn cache_file_path(&self, set_name: &str, cache_dir: &Path) -> PathBuf {
        cache_dir.join(make_cache_file_name(set_name, self.url.as_str()))
    }

    pub(crate) fn load_with_cache(
        &self,
        set_name: &str,
        cache_dir: Option<&Path>,
    ) -> Result<(HashSet<WildcardName>, DomainSetHttpLoadSource)> {
        match self.get_domain_set() {
            Ok(domain_set) => {
                if let Some(cache_dir) = cache_dir {
                    let cache_file = self.cache_file_path(set_name, cache_dir);
                    if let Err(err) = write_cache_file(cache_file.as_path(), &domain_set) {
                        crate::log::warn!(
                            "DomainSet cache write failed {} {}: {}",
                            set_name,
                            self.url,
                            err
                        );
                    }
                }
                Ok((domain_set, DomainSetHttpLoadSource::Remote))
            }
            Err(err) => {
                let Some(cache_dir) = cache_dir else {
                    return Err(err);
                };

                let cache_file = self.cache_file_path(set_name, cache_dir);
                if !cache_file.is_file() {
                    return Err(err);
                }

                let domain_set = read_cache_file(cache_file.as_path())?;
                Ok((domain_set, DomainSetHttpLoadSource::Cache))
            }
        }
    }

    pub(crate) fn refresh_and_persist(
        &self,
        set_name: &str,
        cache_file: Option<&Path>,
    ) -> Result<HashSet<WildcardName>> {
        let domain_set = self.get_domain_set()?;
        if let Some(cache_file) = cache_file
            && let Err(err) = write_cache_file(cache_file, &domain_set)
        {
            crate::log::warn!(
                "DomainSet cache write failed {} {}: {}",
                set_name,
                self.url,
                err
            );
        }
        Ok(domain_set)
    }
}

fn make_cache_file_name(set_name: &str, url: &str) -> String {
    let mut hasher = DefaultHasher::new();
    url.hash(&mut hasher);
    let hash = hasher.finish();
    let normalized_name = normalize_set_name(set_name);
    format!("{normalized_name}-{hash:016x}.list")
}

fn normalize_set_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len().max(1));
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("domain-set");
    }
    out
}

fn read_cache_file(path: &Path) -> Result<HashSet<WildcardName>> {
    let mut domain_set = HashSet::new();
    let text = std::fs::read_to_string(path)?;
    read_to_domain_set(&text, &mut domain_set);
    Ok(domain_set)
}

fn write_cache_file(path: &Path, domain_set: &HashSet<WildcardName>) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }

    let mut lines = domain_set
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    lines.sort_unstable();

    if lines.is_empty() {
        std::fs::write(path, "")?;
    } else {
        std::fs::write(path, format!("{}\n", lines.join("\n")))?;
    }
    Ok(())
}

fn read_to_domain_set(s: &str, domain_set: &mut HashSet<WildcardName>) {
    for line in s.lines() {
        let line = line.trim_start();
        if line.starts_with('#') {
            continue;
        }
        let mut parts = line.split(' ');

        if let Some(n) = parts.next().and_then(|n| WildcardName::from_str(n).ok()) {
            domain_set.insert(n);
        }
    }
}
