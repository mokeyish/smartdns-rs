#[cfg(feature = "self-update")]
pub fn update(assume_yes: bool, ver: Option<&str>) -> anyhow::Result<()> {
    let bin = env!("CARGO_BIN_NAME");
    let target = env!("CARGO_BUILD_TARGET");
    let target_dir = format!("{bin}-{target}");

    let mut builder = self_update::backends::github::Update::configure();

    builder
        .repo_owner("mokeyish")
        .repo_name(&[bin, "-rs"].concat())
        .identifier(target)
        .bin_name(bin)
        .bin_path_in_archive(&format!("{}/{}", target_dir, "{{bin}}"))
        .show_download_progress(true)
        .no_confirm(assume_yes)
        .current_version(self_update::cargo_crate_version!());

    if let Some(ver) = ver {
        builder.target_version_tag(ver);
    }

    let status = builder.build()?.update()?;

    println!("Update status: `{}`!", status.version());
    Ok(())
}

#[cfg(not(feature = "self-update"))]
pub fn update(_assume_yes: bool) -> anyhow::Result<()> {
    println!("self-update is not enabled");
    Ok(())
}
