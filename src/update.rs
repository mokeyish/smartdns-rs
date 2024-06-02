#[cfg(feature = "self-update")]
pub fn update(assume_yes: bool) -> anyhow::Result<()> {
    let bin = env!("CARGO_BIN_NAME");
    let target = env!("CARGO_BUILD_TARGET");
    let target_dir = format!("{bin}-{target}");

    let status = self_update::backends::github::Update::configure()
        .repo_owner("mokeyish")
        .repo_name(&[bin, "-rs"].concat())
        .identifier(target)
        .bin_name(bin)
        .bin_path_in_archive(&format!("{}/{}", target_dir, "{{bin}}"))
        .show_download_progress(true)
        .no_confirm(assume_yes)
        .current_version(self_update::cargo_crate_version!())
        .build()?
        .update()?;

    println!("Update status: `{}`!", status.version());
    Ok(())
}

#[cfg(not(feature = "self-update"))]
pub fn update(_assume_yes: bool) -> anyhow::Result<()> {
    println!("self-update is not enabled");
    Ok(())
}
