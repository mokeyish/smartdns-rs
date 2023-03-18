#[cfg(feature = "homebrew")]
#[path = "brew.rs"]
mod ctl;

#[cfg(not(feature = "homebrew"))]
#[path = "launchctl.rs"]
mod ctl;

pub use ctl::{create_service_definition, CONF_PATH};
