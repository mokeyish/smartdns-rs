#![allow(dead_code)]

use std::fs::File;
use std::io::Write;

use std::{env, path::Path};

#[cfg(target_os = "linux")]
fn build_nftset() -> anyhow::Result<()> {
    let target = env::var("TARGET")?;

    if !target.contains("linux") {
        return Ok(());
    }

    let mut build = cc::Build::new();
    build
        .file("include/nftset.c")
        .static_flag(true)
        .warnings(false);

    if target.ends_with("-musl") {
        let target_dir = env::var_os("OUT_DIR").unwrap();
        let musl_root = Path::new(&target_dir);
        let target = target.replace("unknown-linux", "linux");
        let include_dir = musl_root.join(format!("{target}-native")).join("include");
        if !musl_root.exists() {
            std::fs::create_dir_all(musl_root)?;
        }

        let file = musl_root.join(format!("{target}-native.tgz"));
        if !file.exists() {
            std::process::Command::new("curl")
                .args(["-OL", &format!("https://musl.cc/{target}-native.tgz")])
                .current_dir(musl_root)
                .output()
                .unwrap_or_else(|_| panic!("download https://musl.cc/{target}-native.tgz failed"));
        }

        if !include_dir.exists() {
            std::process::Command::new("tar")
                .args(["-xzf", &format!("{target}-native.tgz")])
                .current_dir(musl_root)
                .output()
                .unwrap_or_else(|_| panic!("untar {target}-native.tgz failed"));
        }

        build.include(include_dir.as_os_str()); // https://musl.cc/x86_64-linux-musl-native.tgz
    }

    build.compile("nftset");

    bindgen::Builder::default()
        .header("include/nftset.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("src/ffi/nftset_sys.rs")
        .unwrap();

    Ok(())
}

fn download<P: AsRef<Path> + Copy>(url: &str, file_path: P) -> bool {
    use reqwest::blocking as http;
    if Path::exists(file_path.as_ref()) {
        return false;
    }

    let rest = http::get(url).unwrap_or_else(|_| panic!("URL: {url} download failed!!!"));

    let bytes = rest.bytes().expect("read bytes from server failed!!!");

    write_all_to_file(file_path, bytes);

    true
}

fn write_all_to_file<P: AsRef<Path> + Copy, T: AsRef<[u8]>>(file_path: P, text: T) {
    let mut file = File::create(file_path)
        .unwrap_or_else(|_| panic!("Create file {:?} failed", file_path.as_ref()));
    file.write_all(text.as_ref()).unwrap();
}

fn append_text_to_file<P: AsRef<Path> + Copy, T: AsRef<[u8]>>(file_path: P, text: T) {
    let mut file = File::options()
        .append(true)
        .create(true)
        .open(file_path)
        .unwrap_or_else(|_| panic!("Create file {:?} failed", file_path.as_ref()));
    file.write_all(text.as_ref()).unwrap();
}

fn download_resources() -> anyhow::Result<()> {
    if download(
        "https://cdn.jsdelivr.net/gh/pymumu/smartdns/etc/smartdns/smartdns.conf",
        "etc/smartdns/smartdns.conf",
    ) {
        // append_text_to_file("./etc/smartdns/smartdns.conf", "\nconf-file custom.conf\n");
    }

    download(
        "https://cdn.jsdelivr.net/gh/pymumu/smartdns/package/openwrt/files/etc/init.d/smartdns",
        "src/service/linux/initd/openwrt/files/etc/init.d/smartdns-rs",
    );

    download(
        "https://cdn.jsdelivr.net/gh/mullvad/windows-service-rs/src/shell_escape.rs",
        "src/service/windows/shell_escape.rs",
    );
    Ok(())
}

fn create_build_time_vars() -> anyhow::Result<()> {
    let target_dir = env::var_os("OUT_DIR").unwrap();
    let target_dir = Path::new(&target_dir);
    let build_file = target_dir.join("build_time_vars.rs");
    let mut file = File::create(build_file)?;
    let build_timestamp = chrono::Utc::now().timestamp_millis();
    writeln!(
        file,
        r#"pub const BUILD_DATE: chrono::DateTime<chrono::Utc> = chrono::DateTime::from_timestamp_millis({build_timestamp}).unwrap();"#
    )?;

    writeln!(
        file,
        r#"pub const BUILD_TARGET: &str = "{}";"#,
        env::var("TARGET").unwrap()
    )?;

    writeln!(
        file,
        r#"pub const BUILD_VERSION: &str = "{}";"#,
        env::var("CARGO_PKG_VERSION").unwrap()
    )?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    std::fs::create_dir_all("./logs")?;

    #[cfg(target_os = "linux")]
    build_nftset()?;

    download_resources()?;

    create_build_time_vars()?;
    Ok(())
}
