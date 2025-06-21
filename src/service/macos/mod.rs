#[cfg(feature = "homebrew")]
#[path = "brew.rs"]
mod ctl;

#[cfg(not(feature = "homebrew"))]
#[path = "launchctl.rs"]
mod ctl;

pub use ctl::{CONF_PATH, create_service_definition};
