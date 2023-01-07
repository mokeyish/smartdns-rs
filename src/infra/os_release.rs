use std::{io, str::FromStr};

#[cfg(target_os = "linux")]
pub fn get() -> io::Result<OsRelease> {
    use std::fs;
    let desc = fs::read_to_string("/etc/os-release")?;
    OsRelease::from_str(desc.as_str())
}

#[cfg(target_os = "macos")]
pub fn get() -> io::Result<OsRelease> {
    Ok(OsRelease {
        id: "macos".to_string(),
        name: "macos".to_string(),
        pretty_name: "macos".to_string(),
        id_like: None,
    })
}

#[cfg(target_os = "windows")]
pub fn get() -> io::Result<OsRelease> {
    Ok(OsRelease {
        id: "windows".to_string(),
        name: "windows".to_string(),
        pretty_name: "windows".to_string(),
        id_like: None,
    })
}

#[derive(Debug)]
pub struct OsRelease {
    id: String,
    name: String,
    pretty_name: String,
    id_like: Option<String>,
}

impl FromStr for OsRelease {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut id = String::new();
        let mut name = String::new();
        let mut pretty_name = String::new();

        let mut id_like = None;

        for line in s.lines() {
            let eq_idx = match line.find("=") {
                Some(idx) => idx,
                None => continue,
            };

            let p = line[0..eq_idx].trim();
            let v = line[eq_idx + 1..].trim();

            match p.to_lowercase().as_str() {
                stringify!(id) => id.push_str(v),
                stringify!(name) => name.push_str(v),
                stringify!(pretty_name) => pretty_name.push_str(v),
                stringify!(id_like) => id_like = Some(v.to_string()),
                _ => (),
            }
        }

        Ok(Self {
            id,
            name,
            pretty_name,
            id_like,
        })
    }
}

impl OsRelease {
    #[inline]
    pub fn is_kali(&self) -> bool {
        self.id.contains("kali")
    }

    #[inline]
    pub fn is_debian(&self) -> bool {
        self.id_contains("debian") || self.is_deepin()
    }

    #[inline]
    pub fn is_centos(&self) -> bool {
        self.id_contains("centos")
    }

    #[inline]
    pub fn is_fedora(&self) -> bool {
        self.id_contains("fedora")
    }

    #[inline]
    pub fn is_openwrt(&self) -> bool {
        self.id.contains("openwrt")
    }

    #[inline]
    pub fn is_deepin(&self) -> bool {
        self.id_contains("Deepin")
    }

    #[inline]
    pub fn is_linux(&self) -> bool {
        cfg!(target_os = "linux")
    }

    #[inline]
    pub fn is_macos(&self) -> bool {
        cfg!(target_os = "macos")
    }

    #[inline]
    pub fn is_windows(&self) -> bool {
        cfg!(target_os = "windows")
    }

    fn id_contains(&self, search: &str) -> bool {
        self.id.contains(search)
            || self
                .id_like
                .as_ref()
                .map(|id| id.contains(search))
                .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    pub fn test_linux_kali() {
        let kali = r#"
        PRETTY_NAME="Kali GNU/Linux Rolling"
        NAME="Kali GNU/Linux"
        VERSION="2022.4"
        VERSION_ID="2022.4"
        VERSION_CODENAME="kali-rolling"
        ID=kali
        ID_LIKE=debian
        HOME_URL="https://www.kali.org/"
        SUPPORT_URL="https://forums.kali.org/"
        BUG_REPORT_URL="https://bugs.kali.org/"
        ANSI_COLOR="1;31"
        "#;
        let os_release: OsRelease = kali.parse().unwrap();
        assert_eq!(os_release.id, "kali");
        assert!(os_release.is_kali());
        assert!(os_release.is_debian());
    }

    #[test]
    #[cfg(target_os = "linux")]
    pub fn test_linux_openwrt() {
        let kali = r#"
        NAME="OpenWrt"
        VERSION="22.03.0"
        ID="openwrt"
        ID_LIKE="lede openwrt"
        PRETTY_NAME="OpenWrt 22.03.0"
        VERSION_ID="22.03.0"
        HOME_URL="https://openwrt.org/"
        BUG_URL="https://bugs.openwrt.org/"
        SUPPORT_URL="https://forum.openwrt.org/"
        BUILD_ID="r19685-512e76967f"
        OPENWRT_BOARD="x86/64"
        OPENWRT_ARCH="x86_64"
        OPENWRT_TAINTS=""
        OPENWRT_DEVICE_MANUFACTURER="OpenWrt"
        OPENWRT_DEVICE_MANUFACTURER_URL="https://openwrt.org/"
        OPENWRT_DEVICE_PRODUCT="Generic"
        OPENWRT_DEVICE_REVISION="v0"
        OPENWRT_RELEASE="OpenWrt 22.03.0 r19685-512e76967f"
        "#;
        let os_release: OsRelease = kali.parse().unwrap();
        assert!(os_release.is_openwrt());
    }

    #[test]
    fn is_target_os() {
        #[cfg(target_os = "windows")]
        assert!(get().unwrap().is_windows());

        #[cfg(target_os = "macos")]
        assert!(get().unwrap().is_macos());

        #[cfg(target_os = "linux")]
        assert!(get().unwrap().is_linux());
    }
}
