use std::{
    fs, io,
    path::{Path, PathBuf},
    process,
};

use sysinfo::{Pid, PidExt};
use thiserror::Error;

pub struct ProcessGuard {
    id: u32,
    path: PathBuf,
}

#[derive(Error, Debug)]
pub enum ProcessGuardError {
    #[error("the process id {0} already running!!!")]
    AlreadyRunning(u32),
    #[error("io error {0}")]
    IoError(#[from] io::Error),
}

pub fn create<P: AsRef<Path>>(path: P) -> Result<ProcessGuard, ProcessGuardError> {
    let path = path.as_ref();

    let id = process::id();

    if path.exists() {
        let id_str = fs::read_to_string(path)?;
        let prev_id = id_str.as_str().parse::<u32>();
        if let Ok(prev_id) = prev_id {
            if is_process_running(prev_id) {
                return Err(ProcessGuardError::AlreadyRunning(prev_id));
            }
        }
    }

    fs::write(path, id.to_string().as_bytes())?;

    Ok(ProcessGuard {
        id,
        path: path.to_path_buf(),
    })
}

fn is_process_running(id: u32) -> bool {
    use sysinfo::{ProcessRefreshKind, RefreshKind, System, SystemExt};
    let sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    sys.process(Pid::from_u32(id)).is_some()
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if self.path.exists() {
            fs::remove_file(self.path.as_path()).unwrap_or_default()
        }
    }
}
