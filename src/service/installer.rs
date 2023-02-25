use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use crate::{
    log::{info, warn},
    third_ext::PathBufAddExtensionExt,
};

pub struct InstallerBuilder {
    items: Vec<InstallItem>,
}

impl InstallerBuilder {
    pub fn add_item<T: Into<InstallItem>>(mut self, item: T) -> Self {
        self.items.push(item.into());
        self
    }

    pub fn build(self) -> Installer {
        Installer { items: self.items }
    }
}

#[derive(Debug)]
pub struct Installer {
    items: Vec<InstallItem>,
}

impl Installer {
    pub fn builder() -> InstallerBuilder {
        InstallerBuilder {
            items: Default::default(),
        }
    }
}

#[derive(Debug)]
pub struct InstallItem {
    path: PathBuf,
    file: Option<InstallContentOrPath>,
    options: InstallOptions,
}

impl InstallItem {
    #[inline]
    pub fn is_file(&self) -> bool {
        self.file.is_some()
    }

    #[inline]
    pub fn is_directory(&self) -> bool {
        !self.is_file()
    }
}

#[derive(Debug, Default)]
pub struct InstallOptions {
    mode: Option<u32>,
    install_strategy: InstallStrategy,
    uninstall_strategy: UninstallStrategy,
}

impl<'a, 'b> From<(&'a Path, &'b [u8])> for InstallItem {
    fn from((path, content): (&'a Path, &'b [u8])) -> Self {
        Self {
            path: path.to_path_buf(),
            file: Some(content.into()),
            options: Default::default(),
        }
    }
}

impl<'a, 'b> From<(&'a Path, &'b [u8], InstallStrategy)> for InstallItem {
    fn from((path, content, strategy): (&'a Path, &'b [u8], InstallStrategy)) -> Self {
        Self {
            path: path.to_path_buf(),
            file: Some(content.into()),
            options: InstallOptions {
                install_strategy: strategy,
                ..Default::default()
            },
        }
    }
}

impl<'a, 'b> From<(&'a Path, &'b [u8], InstallStrategy, UninstallStrategy)> for InstallItem {
    fn from(
        (path, content, install_strategy, uninstall_strategy): (
            &'a Path,
            &'b [u8],
            InstallStrategy,
            UninstallStrategy,
        ),
    ) -> Self {
        Self {
            path: path.to_path_buf(),
            file: Some(content.into()),
            options: InstallOptions {
                install_strategy,
                uninstall_strategy,
                ..Default::default()
            },
        }
    }
}

impl<'a, 'b> From<(&'a Path, &'b [u8], u32)> for InstallItem {
    #[inline]
    fn from((path, content, mode): (&'a Path, &'b [u8], u32)) -> Self {
        Self {
            path: path.to_path_buf(),
            file: Some(content.into()),
            options: InstallOptions {
                mode: Some(mode),
                ..Default::default()
            },
        }
    }
}

impl<'a, 'b> From<(&'a Path, &'b [u8], u32, InstallStrategy)> for InstallItem {
    #[inline]
    fn from((path, content, mode, strategy): (&'a Path, &'b [u8], u32, InstallStrategy)) -> Self {
        Self {
            path: path.to_path_buf(),
            file: Some(content.into()),
            options: InstallOptions {
                mode: Some(mode),
                install_strategy: strategy,
                ..Default::default()
            },
        }
    }
}

impl<'a, 'b> From<(&'a Path, &'b [u8], u32, InstallStrategy, UninstallStrategy)> for InstallItem {
    #[inline]
    fn from(
        (path, content, mode, install_strategy, uninstall_strategy): (
            &'a Path,
            &'b [u8],
            u32,
            InstallStrategy,
            UninstallStrategy,
        ),
    ) -> Self {
        Self {
            path: path.to_path_buf(),
            file: Some(content.into()),
            options: InstallOptions {
                mode: Some(mode),
                install_strategy,
                uninstall_strategy,
            },
        }
    }
}

impl<'a, 'b> From<(&'a str, &'b [u8], u32)> for InstallItem {
    #[inline]
    fn from((p, c, m): (&'a str, &'b [u8], u32)) -> Self {
        (Path::new(p), c, m).into()
    }
}

impl<'a, 'b> From<(&'a str, &'b [u8], u32, InstallStrategy)> for InstallItem {
    #[inline]
    fn from((p, c, m, s): (&'a str, &'b [u8], u32, InstallStrategy)) -> Self {
        (Path::new(p), c, m, s).into()
    }
}

impl<'a, 'b> From<(&'a str, &'b [u8], InstallStrategy)> for InstallItem {
    #[inline]
    fn from((p, c, s): (&'a str, &'b [u8], InstallStrategy)) -> Self {
        (Path::new(p), c, s).into()
    }
}

impl<'a, 'b> From<(&'a str, &'b [u8], InstallStrategy, UninstallStrategy)> for InstallItem {
    #[inline]
    fn from((p, c, si, su): (&'a str, &'b [u8], InstallStrategy, UninstallStrategy)) -> Self {
        (Path::new(p), c, si, su).into()
    }
}

impl<'a, 'b> From<(&'a str, &'b str, u32)> for InstallItem {
    #[inline]
    fn from((p, c, m): (&'a str, &'b str, u32)) -> Self {
        (Path::new(p), c.as_bytes(), m).into()
    }
}

impl<'a, 'b> From<(&'a str, &'b str, u32, InstallStrategy)> for InstallItem {
    #[inline]
    fn from((p, c, m, s): (&'a str, &'b str, u32, InstallStrategy)) -> Self {
        (Path::new(p), c.as_bytes(), m, s).into()
    }
}

impl<'a, 'b> From<(&'a str, &'b str, u32, InstallStrategy, UninstallStrategy)> for InstallItem {
    #[inline]
    fn from(
        (p, c, m, si, su): (&'a str, &'b str, u32, InstallStrategy, UninstallStrategy),
    ) -> Self {
        (Path::new(p), c.as_bytes(), m, si, su).into()
    }
}

impl<'a, 'b> From<(&'a str, &'b str, InstallStrategy)> for InstallItem {
    #[inline]
    fn from((p, c, s): (&'a str, &'b str, InstallStrategy)) -> Self {
        (Path::new(p), c.as_bytes(), s).into()
    }
}

impl<'a, 'b> From<(&'a str, &'b str, InstallStrategy, UninstallStrategy)> for InstallItem {
    #[inline]
    fn from((p, c, si, su): (&'a str, &'b str, InstallStrategy, UninstallStrategy)) -> Self {
        (Path::new(p), c.as_bytes(), si, su).into()
    }
}

impl<'a, 'b> From<(&'a Path, &'b Path)> for InstallItem {
    #[inline]
    fn from((src, dest): (&'a Path, &'b Path)) -> Self {
        (src.to_path_buf(), dest.to_path_buf()).into()
    }
}

impl From<(PathBuf, PathBuf)> for InstallItem {
    fn from((src, dest): (PathBuf, PathBuf)) -> Self {
        Self {
            path: dest,
            file: Some(src.into()),
            options: Default::default(),
        }
    }
}

impl<'a> From<(PathBuf, &'a Path)> for InstallItem {
    #[inline]
    fn from((src, dest): (PathBuf, &'a Path)) -> Self {
        (src, dest.to_path_buf()).into()
    }
}

impl From<PathBuf> for InstallItem {
    #[inline]
    fn from(path: PathBuf) -> Self {
        Self {
            path,
            file: None,
            options: Default::default(),
        }
    }
}

impl From<(PathBuf, UninstallStrategy)> for InstallItem {
    #[inline]
    fn from((path, strategy): (PathBuf, UninstallStrategy)) -> Self {
        Self {
            path,
            file: None,
            options: InstallOptions {
                uninstall_strategy: strategy,
                ..Default::default()
            },
        }
    }
}

impl From<&Path> for InstallItem {
    #[inline]
    fn from(path: &Path) -> Self {
        path.to_path_buf().into()
    }
}

impl From<(&Path, UninstallStrategy)> for InstallItem {
    #[inline]
    fn from((path, strategy): (&Path, UninstallStrategy)) -> Self {
        (path.to_path_buf(), strategy).into()
    }
}

impl From<&str> for InstallItem {
    #[inline]
    fn from(path: &str) -> Self {
        Path::new(path).into()
    }
}

impl From<(&str, UninstallStrategy)> for InstallItem {
    #[inline]
    fn from((path, strategy): (&str, UninstallStrategy)) -> Self {
        (Path::new(path), strategy).into()
    }
}

#[derive(Debug)]
pub enum InstallContentOrPath {
    Content(Box<[u8]>),
    Path(PathBuf),
}

impl From<&[u8]> for InstallContentOrPath {
    fn from(value: &[u8]) -> Self {
        Self::Content(value.to_vec().into_boxed_slice())
    }
}

impl From<PathBuf> for InstallContentOrPath {
    #[inline]
    fn from(path: PathBuf) -> Self {
        Self::Path(path)
    }
}

impl From<&Path> for InstallContentOrPath {
    #[inline]
    fn from(path: &Path) -> Self {
        path.to_path_buf().into()
    }
}

impl From<&str> for InstallContentOrPath {
    #[inline]
    fn from(path: &str) -> Self {
        Path::new(path).into()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum InstallStrategy {
    Overide,
    Backup,
    Preserve,
}

impl Default for InstallStrategy {
    #[inline]
    fn default() -> Self {
        Self::Overide
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum UninstallStrategy {
    Keep,
    Remove,
    /// If directory is empty, remove it.
    RemoveIfEmpty,
}

impl Default for UninstallStrategy {
    fn default() -> Self {
        Self::Remove
    }
}

impl Installer {
    pub fn install(&self) -> io::Result<()> {
        for install_item in self.items.iter() {
            if let InstallItem {
                path: dest_path,
                file: Some(install_file),
                options:
                    InstallOptions {
                        #[cfg(unix)]
                        mode,
                        install_strategy: strategy,
                        ..
                    },
            } = install_item
            {
                let mut dest_path = dest_path.to_owned();

                if dest_path.exists() {
                    match strategy {
                        InstallStrategy::Backup => {
                            let mut path = dest_path.to_path_buf();
                            path.append_extension("old");
                            fs::copy(dest_path.as_path(), path)?;
                        }
                        InstallStrategy::Preserve => {
                            dest_path.append_extension("new");
                        }
                        InstallStrategy::Overide => (),
                    }
                }

                let dest_path = dest_path.as_path();

                // if let Some(dir) = dest_path.parent() {
                //     if !dir.exists() {
                //         fs::create_dir_all(dir)?;
                //     }
                // }

                match &install_file {
                    InstallContentOrPath::Content(bytes) => {
                        let opts = {
                            let mut opts = OpenOptions::new();
                            opts.create(true).write(true);
                            #[cfg(unix)]
                            if let Some(mode) = *mode {
                                use std::os::unix::fs::OpenOptionsExt;
                                opts.mode(mode);
                            }
                            opts
                        };
                        let mut file = opts.open(dest_path)?;
                        file.write_all(bytes.as_ref())?;

                        // Ensure that the data/metadata is synced and catch errors before dropping
                        file.sync_all()?;
                    }
                    InstallContentOrPath::Path(p) => {
                        fs::copy(p.as_path(), dest_path)?;
                    }
                };

                match dest_path.canonicalize() {
                    Ok(path) => {
                        info!("Installed to {:?}", path);
                    }
                    Err(_err) => {
                        info!("Installed to {:?}", dest_path);
                    }
                };
            } else {
                // directry
                if install_item.is_directory() && !install_item.path.exists() {
                    fs::create_dir_all(install_item.path.as_path())?;
                }
            }
        }
        Ok(())
    }

    pub fn uninstall(&self, purge: bool) -> io::Result<()> {
        for install_item in self.items.iter().rev() {
            let InstallItem {
                path,
                options:
                    InstallOptions {
                        uninstall_strategy, ..
                    },
                ..
            } = install_item;

            if !path.exists() {
                warn!("{:?} does not exist, skipping", path);
                continue;
            }

            if purge || *uninstall_strategy == UninstallStrategy::Remove {
                if path.is_file() {
                    fs::remove_file(path)?;
                    info!("file {:?} removed", path);
                } else {
                    fs::remove_dir_all(path)?;
                    info!("dir {:?} removed", path);
                }
            } else if install_item.is_directory()
                && matches!(uninstall_strategy, UninstallStrategy::RemoveIfEmpty if path.read_dir().map(|mut i| i.next().is_none()).unwrap_or(false))
            {
                fs::remove_dir_all(path)?;
                info!("dir {:?} removed", path);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use chrono::Local;
    use std::path::Path;

    use super::*;

    #[test]
    fn test_install_success() {
        let file_path = format!("./logs/installer-abc-{:#x}.txt", Local::now().timestamp());
        let file_path = Path::new(file_path.as_str());

        assert!(!file_path.exists());

        let installer = Installer::builder()
            .add_item((file_path, b"hi123".as_ref(), 0o755))
            .build();
        installer.install().unwrap();
        assert!(file_path.exists());
        installer.uninstall(true).unwrap();
        assert!(!file_path.exists());
    }
}
