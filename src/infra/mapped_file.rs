use std::ffi::OsStr;
use std::fs;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::Local;

const DATE_FMT: &str = "%Y%m%d-%H%M%S%f";

pub struct MappedFile {
    num: Option<usize>,
    size: u64,
    path: PathBuf,
    file: Option<File>,
    len: u64,
    mode: Option<u32>,
    peamble_bytes: Option<Box<[u8]>>,
}

impl MappedFile {
    pub fn open<P: AsRef<Path>>(path: P, size: u64, num: Option<usize>, mode: Option<u32>) -> Self {
        let path = path.as_ref().to_path_buf();
        Self {
            path,
            size,
            num,
            file: None,
            len: 0,
            mode,
            peamble_bytes: None,
        }
    }

    pub fn peamble(&self) -> Option<&[u8]> {
        self.peamble_bytes.as_ref().map(|x| &x[..])
    }

    pub fn set_peamble(&mut self, bytes: Option<Box<[u8]>>) {
        self.peamble_bytes = bytes;
    }

    #[inline]
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    #[inline]
    pub fn extension(&self) -> Option<&OsStr> {
        self.path.extension()
    }

    #[inline]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    #[inline]
    pub fn len(&self) -> u64 {
        if self.len > 0 || self.file.is_some() {
            self.len
        } else {
            fs::metadata(self.path.as_path())
                .map(|m| m.len())
                .unwrap_or_default()
        }
    }

    #[inline]
    pub fn touch(&mut self) -> io::Result<()> {
        if !self.path().exists() {
            let dir = self
                .path()
                .parent()
                .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
            fs::create_dir_all(dir)?;
        }
        let file = self.get_active_file()?;
        file.sync_all()?;
        Ok(())
    }

    pub fn mapped_files(&self) -> io::Result<Vec<PathBuf>> {
        match (
            self.path
                .file_stem()
                .map(|s| s.to_str().map(|s| s.to_string())),
            self.path.parent(),
        ) {
            (Some(Some(base_name)), Some(parent)) => {
                let mut files = fs::read_dir(parent)?
                .filter_map(|o| o.ok())
                .filter_map(|o| {
                    if self.path.extension() == o.path().extension() &&
                        matches!(o.file_name().to_str(), Some(s) if s.starts_with(base_name.as_str())) {
                        Some(o.path())
                    } else {
                        None
                    }
                } )
                .collect::<Vec<_>>();
                files.sort_by(|a, b| b.cmp(a));
                Ok(files)
            }
            _ => Ok(Default::default()),
        }
    }

    pub fn set_num(&mut self, num: Option<usize>) {
        self.num = num;
    }

    pub fn remove_files(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush()?;
        }

        for f in self.mapped_files()? {
            fs::remove_file(f)?;
        }

        Ok(())
    }

    fn is_full(&self) -> bool {
        self.len() >= self.size
    }

    fn get_active_file(&mut self) -> io::Result<&mut File> {
        if self.is_full() {
            self.backup_files()?;
        }

        match self.file {
            Some(ref mut file) => Ok(file),
            None => {
                match {
                    let mut opt = File::options();

                    #[cfg(unix)]
                    if let Some(mode) = self.mode {
                        use std::os::unix::fs::OpenOptionsExt;
                        opt.mode(mode);
                    }

                    opt.create(true).write(true);

                    if self.path.exists() {
                        if self.is_full() {
                            opt.truncate(true);
                        } else {
                            opt.append(true);
                        }
                    }
                    opt.open(self.path.as_path())
                } {
                    Ok(mut file) => {
                        self.len = file.metadata().unwrap().len();
                        if self.len == 0 && self.peamble_bytes.is_some() {
                            let bytes = self.peamble().unwrap();
                            self.len = file.write(bytes)? as u64;
                        }
                        self.file = Some(file);
                        Ok(self.file.as_mut().unwrap())
                    }
                    Err(err) => Err(err),
                }
            }
        }
    }

    fn backup_files(&mut self) -> io::Result<()> {
        if let (Some(base_name), Some(parent)) = (self.path.file_stem(), self.path.parent()) {
            let new_name = {
                let mut n = base_name.to_os_string();
                n.push("-");
                n.push(Local::now().format(DATE_FMT).to_string());
                n
            };
            let mut new_path = parent.join(new_name);
            if let Some(ext) = self.path.extension() {
                new_path = new_path.with_extension(ext);
            }
            fs::copy(self.path.as_path(), new_path)?;
        }

        let files = self.mapped_files()?;
        match self.num {
            Some(n) if n <= files.len() => {
                for f in &files[n..] {
                    fs::remove_file(f)?;
                }
            }
            _ => (),
        }

        Ok(())
    }
}

impl Write for MappedFile {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let file = self.get_active_file()?;
        let len = file.write(buf)?;
        self.len += len as u64;
        if self.is_full() {
            self.flush()?;
        }
        Ok(len)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush()?;
            if self.is_full() {
                drop(file)
            } else {
                self.file = Some(file);
            }
        }
        Ok(())
    }
}

pub struct MutexMappedFile(pub Mutex<MappedFile>);

impl MutexMappedFile {
    #[inline]
    pub fn open<P: AsRef<Path>>(path: P, size: u64, num: Option<usize>, mode: Option<u32>) -> Self {
        Self(Mutex::new(MappedFile::open(path, size, num, mode)))
    }
}

impl io::Write for MutexMappedFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.get_mut().unwrap().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.get_mut().unwrap().flush()
    }
}

impl io::Write for &MutexMappedFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    pub fn test_write_file() -> io::Result<()> {
        let file_path = format!("./logs/abc-{:#x}.txt", Local::now().timestamp());

        let mut file = MappedFile::open(file_path, 2, Some(3), Default::default());
        file.write_all(b"aa")?;
        assert_eq!(file.mapped_files().unwrap().len(), 1);
        file.write_all(b"bb")?;
        assert_eq!(file.mapped_files().unwrap().len(), 2);
        file.write_all(b"cc")?;
        assert_eq!(file.mapped_files().unwrap().len(), 3);
        file.write_all(b"dd")?;
        assert_eq!(file.mapped_files().unwrap().len(), 3);
        file.write_all(b"ee")?;
        assert_eq!(file.mapped_files().unwrap().len(), 3);

        file.remove_files().unwrap();

        Ok(())
    }
}
