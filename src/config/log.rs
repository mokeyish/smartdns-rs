use std::path::PathBuf;

use byte_unit::Byte;
use serde::{Deserialize, Serialize};

use crate::{infra::file_mode::FileMode, third_ext::serde_opt_str};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct LogConfig {
    /// enable output log to console
    pub console: Option<bool>,

    /// set log level
    ///
    /// log-level [level], level=fatal, error, warn, notice, info, debug
    #[serde(with = "serde_opt_str")]
    pub level: Option<crate::log::Level>,

    /// file path of log file.
    pub file: Option<PathBuf>,

    /// size of each log file, support k,m,g
    pub size: Option<Byte>,

    /// number of logs, 0 means disable log
    pub num: Option<u64>,

    /// log file mode
    #[serde(with = "serde_opt_str")]
    pub file_mode: Option<FileMode>,

    /// log filter
    pub filter: Option<String>,
}

impl LogConfig {
    pub fn console(&self) -> bool {
        self.console.unwrap_or(true)
    }
}
