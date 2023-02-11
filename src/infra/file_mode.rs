use std::{fmt::Debug, num::ParseIntError, ops::Deref, str::FromStr};

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct FileMode(u32);

impl FromStr for FileMode {
    type Err = ParseIntError;

    fn from_str(mut s: &str) -> Result<Self, Self::Err> {
        s = s.trim();
        if s.starts_with("0o") {
            s = &s[2..];
        }
        if s.starts_with("o") {
            s = &s[1..];
        }
        let mode = u32::from_str_radix(s, 8)?;
        Ok(FileMode(mode))
    }
}

impl Deref for FileMode {
    type Target = u32;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq<u32> for FileMode {
    #[inline]
    fn eq(&self, other: &u32) -> bool {
        &self.0 == other
    }
}

impl Into<u32> for FileMode {
    #[inline]
    fn into(self) -> u32 {
        self.0
    }
}

impl From<u32> for FileMode {
    fn from(value: u32) -> Self {
        FileMode(value)
    }
}

impl Debug for FileMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0o{:o}", self.0)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(FileMode::from_str("644").unwrap(), 0o644u32);
        assert_eq!(FileMode::from_str("0644").unwrap(), 0o644u32);
        assert_eq!(FileMode::from_str("o644").unwrap(), 0o644u32);
        assert_eq!(FileMode::from_str("0o644").unwrap(), 0o644u32);
    }

    #[test]
    fn test_debug_display() {
        assert_eq!(format!("{:?}", FileMode::from_str("644").unwrap()), "0o644");
    }
}
