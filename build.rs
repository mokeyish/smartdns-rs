#![allow(dead_code)]

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

fn download<P: AsRef<Path> + Copy>(url: &str, file_path: P) -> bool {
    use reqwest::blocking as http;
    if Path::exists(file_path.as_ref()) {
        return false;
    }

    let rest = http::get(url).unwrap_or_else(|_| panic!("URL: {} download failed!!!", url));

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

fn main() -> io::Result<()> {
    std::fs::create_dir_all("./logs")?;
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

    println!(
        "cargo:rustc-env=CARGO_BUILD_DATE={}",
        chrono::Utc::now().format("🕙 %a %b %d %T UTC %Y")
    );

    println!(
        "cargo:rustc-env=CARGO_BUILD_TARGET={}",
        std::env::var("TARGET").unwrap()
    );
    Ok(())
}
