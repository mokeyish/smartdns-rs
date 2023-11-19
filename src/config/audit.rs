use std::path::PathBuf;

use byte_unit::Byte;
use serde::{Deserialize, Serialize};

use crate::{infra::file_mode::FileMode, third_ext::serde_opt_str};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuditConfig {
    /// dns audit
    ///
    /// enable or disable audit.
    pub enable: Option<bool>,

    /// audit file
    ///
    /// ```
    /// example 1:
    ///   audit-file /var/log/smartdns-audit.log
    ///
    /// example 2:
    ///   audit-file /var/log/smartdns-audit.csv
    /// ```
    pub file: Option<PathBuf>,

    /// audit-size size of each audit file, support k,m,g
    pub size: Option<Byte>,

    /// number of audit files.
    pub num: Option<usize>,

    /// audit file mode
    #[serde(with = "serde_opt_str")]
    pub file_mode: Option<FileMode>,
}
