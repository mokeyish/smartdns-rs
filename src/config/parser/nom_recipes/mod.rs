#[cfg(feature = "nom-recipes-ipv4")]
mod ipv4;
#[cfg(feature = "nom-recipes-ipv4")]
pub use ipv4::ipv4;

#[cfg(feature = "nom-recipes-ipv6")]
mod ipv6;
#[cfg(feature = "nom-recipes-ipv6")]
pub use ipv6::ipv6;
