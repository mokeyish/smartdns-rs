#![allow(dead_code)]


use std::fs::File;
use std::io::Write;
use std::path::Path;

fn download<P: AsRef<Path> + Copy>(url: &str, file_path: P) -> bool {
    use reqwest::blocking as http;
    if Path::exists(file_path.as_ref()) {
        return false;
    }

    let rest = http::get(url).expect(&["URL:", url, " download failed!!!"].concat());

    let bytes = rest.bytes().expect("read bytes from server failed!!!");

    write_all_to_file(file_path, bytes);

    true
}

fn write_all_to_file<P: AsRef<Path> + Copy, T: AsRef<[u8]>>(file_path: P, text: T) {
    let mut file = File::create(file_path)
        .expect(
            &[
                "Create file ",
                file_path.as_ref().to_str().expect("<>"),
                "failed",
            ]
            .concat(),
        );
    file.write_all(text.as_ref()).unwrap();
}

fn append_text_to_file<P: AsRef<Path> + Copy, T: AsRef<[u8]>>(file_path: P, text: T) {
    let mut file = File::options()
        .write(true)
        .append(true)
        .create(true)
        .open(file_path)
        .expect(
            &[
                "Create file ",
                file_path.as_ref().to_str().expect("<>"),
                "failed",
            ]
            .concat(),
        );
    file.write_all(text.as_ref()).unwrap();
}

fn main() {
    if download(
        "https://cdn.jsdelivr.net/gh/pymumu/smartdns/etc/smartdns/smartdns.conf",
        "./etc/smartdns/smartdns.conf",
    ) {
        // append_text_to_file("./etc/smartdns/smartdns.conf", "\nconf-file custom.conf\n");
    }
}
