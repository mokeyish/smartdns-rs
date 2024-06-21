#[cfg(all(feature = "nft", target_os = "linux"))]
mod nftset_sys;

#[cfg(all(feature = "nft", target_os = "linux"))]
pub mod nftset;
