use std::hash::{DefaultHasher, Hash, Hasher};

pub trait HashCode {
    fn hash_code(&self) -> u64;
}

impl<T: Hash> HashCode for T {
    fn hash_code(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}
