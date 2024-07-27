use std::{collections::HashMap, fmt::Debug};

use crate::{config::WildcardName, libdns::proto::rr::Name};

#[derive(Debug)]
pub struct DomainMap<T: Debug>(HashMap<WildcardName, T>);

impl<T: Debug> DomainMap<T> {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn find(&self, name: &Name) -> Option<&T> {
        if self.0.is_empty() {
            return None;
        }
        let mut name = if name.is_wildcard() {
            name.base_name()
        } else {
            name.to_owned()
        };

        let mut lvl = 0;
        loop {
            {
                if lvl == 0 {
                    let wildcard_name = WildcardName::Full(name);
                    if let Some(v) = self.0.get(&wildcard_name) {
                        return Some(v);
                    }
                    name = wildcard_name.into();
                }

                if lvl == 1 {
                    let wildcard_name = WildcardName::Sub(name);
                    if let Some(v) = self.0.get(&wildcard_name) {
                        return Some(v);
                    }
                    name = wildcard_name.into();
                }

                if lvl >= 1 {
                    let wildcard_name = WildcardName::Suffix(name);
                    if let Some(v) = self.0.get(&wildcard_name) {
                        return Some(v);
                    }
                    name = wildcard_name.into();
                }

                let wildcard_name = WildcardName::Default(name);
                if let Some(v) = self.0.get(&wildcard_name) {
                    return Some(v);
                }
                name = wildcard_name.into();
            }

            if !name.is_fqdn() {
                name.set_fqdn(true);
                continue;
            }

            if name.is_root() {
                break;
            }

            name = name.base_name();
            lvl += 1;
        }

        None
    }

    #[inline]
    pub fn contains(&self, domain: &Name) -> bool {
        self.find(domain).is_some()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    pub fn insert(&mut self, name: impl Into<WildcardName>, value: T) -> Option<T> {
        let mut name = name.into();
        name.set_fqdn(true);
        self.0.insert(name, value)
    }

    #[inline]
    pub fn remove(&mut self, name: &WildcardName) -> Option<T> {
        self.0.remove(name)
    }
}

impl<T: Debug> Default for DomainMap<T> {
    #[inline]
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<T: Debug> From<HashMap<WildcardName, T>> for DomainMap<T> {
    #[inline]
    fn from(value: HashMap<WildcardName, T>) -> Self {
        Self(value)
    }
}

#[derive(Default)]
pub struct DomainSet(DomainMap<()>);

impl DomainSet {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn contains(&self, domain: &Name) -> bool {
        self.0.contains(domain)
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn insert(&mut self, domain: impl Into<WildcardName>) -> bool {
        self.0.insert(domain, ()).is_none()
    }

    #[inline]
    pub fn remove(&mut self, domain: &WildcardName) -> bool {
        self.0.remove(domain).is_some()
    }
}

impl FromIterator<WildcardName> for DomainSet {
    fn from_iter<T: IntoIterator<Item = WildcardName>>(iter: T) -> Self {
        DomainSet(DomainMap(HashMap::from_iter(
            iter.into_iter().map(|item| (item, ())),
        )))
    }
}

#[cfg(feature = "experimental-trie")]
mod trie {
    use crate::third_ext::AsSlice;
    use std::{
        collections::{hash_map::RandomState, HashMap},
        hash::{BuildHasher, Hash},
    };

    #[derive(Default)]
    pub struct TrieMap<K, V, S = RandomState>(HashMap<K, TrieNode<K, V, S>>);

    impl<K, V, S> TrieMap<K, V, S> {
        pub fn insert(&mut self, trie_key: impl Into<TrieKey<K>>, v: V) -> Option<V>
        where
            K: Eq + Hash,
            S: BuildHasher + Default,
        {
            let mut keys = Into::<TrieKey<K>>::into(trie_key);
            if let Some(key) = keys.pop() {
                self.0.entry(key).or_default().insert(keys, v)
            } else {
                Some(v)
            }
        }

        pub fn get(&self, trie_key: impl AsSlice<K>) -> Option<&V>
        where
            K: Eq + Hash,
            S: BuildHasher + Default,
        {
            let keys = trie_key.as_slice();
            keys.last()
                .and_then(|key| self.0.get(key))
                .and_then(|n| n.get(&keys[..keys.len() - 1]))
        }

        pub fn get_mut(&mut self, trie_key: impl AsSlice<K>) -> Option<&mut V>
        where
            K: Eq + Hash,
            S: BuildHasher + Default,
        {
            let keys = trie_key.as_slice();
            keys.last()
                .and_then(|key| self.0.get_mut(key))
                .and_then(|n| n.get_mut(&keys[..keys.len() - 1]))
        }

        pub fn contains(&self, trie_key: impl AsSlice<K>) -> bool
        where
            K: Eq + Hash,
            S: BuildHasher + Default,
        {
            self.get(trie_key).is_some()
        }

        pub fn degree(&self) -> usize {
            self.0
                .values()
                .map(|c| c.degree())
                .max()
                .unwrap_or_default()
        }

        pub fn len(&self) -> usize {
            self.0.values().map(|n| n.len()).sum()
        }
    }

    impl<K, V> TrieMap<K, V> {
        pub fn new() -> Self {
            Self(Default::default())
        }
    }

    pub struct TrieNode<K, V, S = RandomState> {
        value: Option<V>,
        children: HashMap<K, TrieNode<K, V, S>, S>,
    }

    impl<K, V, S: Default> Default for TrieNode<K, V, S> {
        fn default() -> Self {
            Self {
                value: Default::default(),
                children: HashMap::<K, TrieNode<K, V, S>, S>::default(),
            }
        }
    }

    impl<K, V, S> TrieNode<K, V, S> {
        pub fn insert(&mut self, trie_key: TrieKey<K>, v: V) -> Option<V>
        where
            K: Eq + Hash,
            S: BuildHasher + Default,
        {
            let mut keys = trie_key;
            if let Some(key) = keys.pop() {
                self.children.entry(key).or_default().insert(keys, v)
            } else {
                self.value.replace(v)
            }
        }

        pub fn get_node(&self, keys: &[K]) -> Option<&Self>
        where
            K: Eq + Hash,
            S: BuildHasher + Default,
        {
            if let Some(key) = keys.last() {
                self.children
                    .get(key)
                    .and_then(|n| n.get_node(&keys[..keys.len() - 1]))
            } else {
                Some(self)
            }
        }

        pub fn get_node_mut(&mut self, keys: &[K]) -> Option<&mut Self>
        where
            K: Eq + Hash,
            S: BuildHasher + Default,
        {
            if let Some(key) = keys.last() {
                self.children
                    .get_mut(key)
                    .and_then(|n| n.get_node_mut(&keys[..keys.len() - 1]))
            } else {
                Some(self)
            }
        }

        pub fn get(&self, keys: &[K]) -> Option<&V>
        where
            K: Eq + Hash,
            S: BuildHasher + Default,
        {
            self.get_node(keys).and_then(|n| n.value.as_ref())
        }

        pub fn get_mut(&mut self, keys: &[K]) -> Option<&mut V>
        where
            K: Eq + Hash,
            S: BuildHasher + Default,
        {
            self.get_node_mut(keys).and_then(|n| n.value.as_mut())
        }

        pub fn contains(&self, keys: &[K]) -> bool
        where
            K: Eq + Hash,
            S: BuildHasher + Default,
        {
            self.get(keys).is_some()
        }

        pub fn degree(&self) -> usize {
            1 + self
                .children
                .values()
                .map(|c| c.degree())
                .max()
                .unwrap_or_default()
        }

        pub fn len(&self) -> usize {
            (if self.value.is_some() { 1 } else { 0 })
                + self.children.values().map(|n| n.len()).sum::<usize>()
        }
    }

    /// TrieKey in reverse mode
    #[derive(Debug)]
    pub struct TrieKey<K>(pub Vec<K>);

    impl<K> std::ops::Deref for TrieKey<K> {
        type Target = Vec<K>;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
    impl<K> std::ops::DerefMut for TrieKey<K> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    impl<K> AsSlice<K> for TrieKey<K> {
        fn as_slice(&self) -> &[K] {
            self.0.as_slice()
        }
    }

    pub struct TrieSet<K, S = RandomState>(TrieMap<K, (), S>);

    impl<K> TrieSet<K> {
        #[inline]
        pub fn new() -> Self {
            Self(TrieMap::new())
        }
    }

    impl<K, S> TrieSet<K, S> {
        #[inline]
        pub fn insert(&mut self, trie_key: impl Into<TrieKey<K>>) -> bool
        where
            K: Eq + Hash,
            S: BuildHasher + Default,
        {
            self.0.insert(trie_key, ()).is_none()
        }

        #[inline]
        pub fn contains(&self, trie_key: impl AsSlice<K>) -> bool
        where
            K: Eq + Hash,
            S: BuildHasher + Default,
        {
            self.0.contains(trie_key)
        }

        #[inline]
        pub fn len(&self) -> usize {
            self.0.len()
        }
    }
}
#[cfg(feature = "experimental-trie")]
pub use trie::*;

#[cfg(feature = "experimental-phf")]
mod phf {
    use std::{collections::HashMap, fmt::Debug, hash::Hash};

    use boomphf::hashmap::BoomHashMap;

    pub fn create_from_hashmap<K: Hash + Debug + PartialEq, V: Debug>(
        map: HashMap<K, V>,
    ) -> BoomHashMap<K, V> {
        let mut keys = vec![];
        let mut values = vec![];

        for (k, v) in map {
            keys.push(k);
            values.push(v);
        }
        BoomHashMap::new(keys, values)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_set_contains() {
        let mut set = DomainSet::new();

        set.insert(WildcardName::Default("example.com".parse().unwrap()));
        assert!(set.contains(&"example.com".parse().unwrap()));
        assert!(set.contains(&"www.example.com".parse().unwrap()));
    }

    #[cfg(feature = "experimental-trie")]
    #[test]
    fn test_trie() {
        impl From<&str> for TrieKey<char> {
            fn from(value: &str) -> Self {
                Self(value.chars().rev().collect())
            }
        }
        let mut trie = TrieMap::new();
        assert_eq!(trie.insert("abc", "a"), None);
        assert_eq!(trie.get(TrieKey::from("abc").as_slice()), Some(&"a"));
        assert_eq!(trie.insert("abc", "w"), Some("a"));
        assert_eq!(trie.insert("axc", "w"), None);

        assert_eq!(trie.len(), 2);
        assert_eq!(trie.degree(), 3);

        assert_eq!(trie.get(TrieKey::from("ab")), None);
        assert_eq!(trie.get(TrieKey::from("abc")), Some(&"w"));
    }

    #[cfg(feature = "experimental-trie")]
    #[test]
    fn test_trie_domain_name() {
        let mut trie = TrieMap::new();

        assert_eq!(trie.insert(Name::from_str(".").unwrap(), "a"), None);

        assert_eq!(trie.insert(Name::from_str(".").unwrap(), "b"), Some("a"));

        assert_eq!(
            trie.insert(Name::from_str("example.com").unwrap(), "a"),
            None
        );

        assert_eq!(
            trie.insert(Name::from_str("Example.com").unwrap(), "b"),
            Some("a")
        );

        assert_eq!(
            trie.get(TrieKey::from(Name::from_str("Example.com").unwrap()).as_slice()),
            Some(&"b")
        );
    }
}

#[cfg(test)]
#[cfg(nightly)]
mod benchmark {
    //! rustup override set nightly
    //! rustup override unset\
    extern crate reqwest;
    extern crate test;
    use super::*;
    use crate::libdns::proto::rr::Name;
    use std::{collections::HashSet, str::FromStr};

    fn get_domain_list() -> Vec<Name> {
        let mut domains = vec![];
        use reqwest::blocking as http;

        let text = http::get("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")
            .unwrap()
            .text()
            .unwrap();

        for mut line in text.lines() {
            line = line.trim_start();
            if line.starts_with('#') {
                continue;
            };

            if let Some(name) = line.split(' ').nth(1).and_then(|s| Name::from_str(s).ok()) {
                domains.push(name);
            }
        }

        domains
    }

    #[cfg(feature = "experimental-trie")]
    #[test]
    fn test_trie_set() {
        let domain_list = get_domain_list().into_iter().collect::<HashSet<_>>();
        let domain_count = domain_list.len();
        let mut set = TrieSet::new();
        for name in get_domain_list() {
            set.insert(name);
        }
        assert_eq!(domain_count, set.len());
    }

    #[cfg(feature = "experimental-trie")]
    #[bench]
    fn bench_trie_set(b: &mut test::Bencher) {
        let domain_list = get_domain_list();
        let mut set = TrieSet::new();
        for name in domain_list.iter() {
            set.insert(name.clone());
        }
        let set = &set;
        let domain_list = domain_list
            .into_iter()
            .map(|n| TrieKey::from(n))
            .collect::<Vec<_>>();
        let domain_list = &domain_list;
        b.iter(|| {
            for n in domain_list {
                assert!(set.contains(n.as_slice()));
            }
        })
    }

    #[bench]
    fn bench_domain_set(b: &mut test::Bencher) {
        let domain_list = get_domain_list();
        let mut set = DomainSet::new();
        for name in domain_list.iter() {
            set.insert(name.clone());
        }
        let set = &set;
        let domain_list = &domain_list;
        b.iter(|| {
            for n in domain_list {
                assert!(set.contains(&n));
            }
        })
    }

    #[cfg(feature = "experimental-phf")]
    #[bench]
    fn bench_domain_phf(b: &mut test::Bencher) {
        let domain_list = get_domain_list();
        let mut set = DomainSet::new();
        for name in domain_list.iter() {
            set.insert(name.clone());
        }
        let set = phf::create_from_hashmap(set.0 .0);
        let set = &set;

        let domain_list = &domain_list;
        b.iter(|| {
            for n in domain_list {
                assert!(set.get(&n).is_some());
            }
        })
    }
}
