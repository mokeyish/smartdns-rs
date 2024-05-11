use std::{ffi::OsStr, io, path::PathBuf};

const B_NAME: &str = "nft";

#[derive(Debug)]
pub struct Nft {
    path: PathBuf,
    available: bool,
}

impl Nft {
    pub fn new() -> Self {
        let mut nft = Self {
            path: B_NAME.into(),
            available: false,
        };

        use which::{which, which_in_global};
        if let Ok(path) = which(B_NAME).or_else(|_| {
            which_in_global(B_NAME, Some("/usr/sbin"))
                .and_then(|mut s| s.next().ok_or(which::Error::CannotFindBinaryPath))
        }) {
            nft.path = path;
        }
        nft.available = nft.list_tables().is_ok();

        nft
    }

    pub fn available(&self) -> bool {
        self.available
    }

    pub fn add_ipv4_set(&self, family: &'static str, table: &str, name: &str) -> io::Result<()> {
        self.add_table(family, table)?;
        self.exec(["add", "set", family, table, name, "{type ipv4_addr;}"])?;
        Ok(())
    }
    pub fn add_ipv6_set(&self, family: &'static str, table: &str, name: &str) -> io::Result<()> {
        self.add_table(family, table)?;
        self.exec(["add", "set", family, table, name, "{type ipv6_addr;}"])?;
        Ok(())
    }

    pub fn add_table(&self, family: &'static str, table: &str) -> io::Result<()> {
        self.exec(["add", "table", family, table])?;
        Ok(())
    }

    pub fn add_ip_element<I, S>(
        &self,
        family: &'static str,
        table: &str,
        name: &str,
        ips: I,
    ) -> io::Result<()>
    where
        I: IntoIterator<Item = S>,
        S: ToString,
    {
        let ips = ips.into_iter().map(|ip| ip.to_string()).collect::<Vec<_>>();

        let elements = format!("{{{}}}", ips.join(","));

        self.exec(["add", "element", family, table, name, &elements])?;
        Ok(())
    }

    pub fn list_tables(&self) -> io::Result<Vec<NftTable>> {
        let output = self.exec(["list", "tables"])?;

        let mut tables = vec![];

        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines() {
                let mut parts = line.split(' ').map(|p| p.trim());

                if let Some(t) = parts.next() {
                    if t != "table" {
                        continue;
                    }
                    if let Some(family) = parts.next().and_then(|family| match family {
                        "inet" => Some("inet"),
                        "ip6" => Some("ip6"),
                        "ip" => Some("ip"),
                        _ => None,
                    }) {
                        if let Some(name) = parts.next() {
                            tables.push(NftTable {
                                family,
                                name: name.to_string(),
                            });
                        }
                    }
                }
            }
        }

        Ok(tables)
    }

    fn exec<I, S>(&self, args: I) -> io::Result<std::process::Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut cmd = std::process::Command::new(&self.path);
        cmd.args(args);

        let output = cmd.output()?;

        if !output.status.success() {
            return match String::from_utf8(output.stderr) {
                Ok(err) => Err(if err.contains("not permitted") {
                    io::Error::new(io::ErrorKind::PermissionDenied, err)
                } else if err.contains("No such") {
                    io::Error::new(io::ErrorKind::NotFound, err)
                } else {
                    io::Error::new(io::ErrorKind::Other, err)
                }),
                _ => Err(io::ErrorKind::Other.into()),
            };
        }

        Ok(output)
    }
}

#[derive(Debug)]
pub struct NftTable {
    pub family: &'static str,
    pub name: String,
}
