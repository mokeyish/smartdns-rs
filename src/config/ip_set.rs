use std::path::PathBuf;

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpSetProvider {
    pub name: String,
    pub file: PathBuf,
    pub content_type: IpSetContentType,
    pub match_tag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum IpSetContentType {
    #[default]
    List,
    #[cfg(feature = "geodata")]
    GeoIp,
    #[cfg(feature = "geodata")]
    Mmdb,
}

pub fn parse_ip_set_file(text: &str) -> impl Iterator<Item = IpNet> + '_ {
    text.lines()
        .filter_map(|line| Some(IpNet::parse(line.trim_start()).ok()?.1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let file = "
1.2.3.4
asdfghjkl

2.3.4.5/16qwertyuiop
";

        assert_eq!(
            parse_ip_set_file(file).collect::<Vec<_>>(),
            ["1.2.3.4/32", "2.3.4.5/16"].map(|net| net.parse().unwrap())
        );
    }
}
