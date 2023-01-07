use std::{ffi::OsStr, path::PathBuf};

pub trait PathBufAddExtensionExt {
    /// Append `extension`
    ///
    /// Returns `false` and does nothing if [`self.file_name`] is [`None`],
    /// returns `true` and appends the extension otherwise.
    ///
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::{Path, PathBuf};
    ///
    /// let mut n = Path::new("hhh/abc").to_path_buf();
    /// n.append_extension("tar");
    /// assert_eq!(n.as_path(),  Path::new("hhh/abc.tar"));
    /// n.append_extension("gz");
    /// assert_eq!(n.as_path(),  Path::new("hhh/abc.tar.gz"));
    /// ```
    fn append_extension<S: AsRef<OsStr>>(&mut self, extension: S) -> bool;
}

impl PathBufAddExtensionExt for PathBuf {
    fn append_extension<S: AsRef<OsStr>>(&mut self, extension: S) -> bool {
        match self.extension() {
            Some(ext) => {
                let mut new_ext = ext.to_os_string();
                new_ext.push(".");
                new_ext.push(extension);
                self.set_extension(new_ext)
            }
            None => self.set_extension(extension),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_append_extension() {
        let mut n = Path::new("hhh/abc").to_path_buf();
        n.append_extension("tar");
        assert_eq!(n.as_path(), Path::new("hhh/abc.tar"));
        n.append_extension("gz");
        assert_eq!(n.as_path(), Path::new("hhh/abc.tar.gz"));
    }
}
