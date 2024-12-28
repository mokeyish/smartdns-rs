use std::collections::HashMap;
use std::ffi::OsString;
use std::path::Path;
use std::{ops::Deref, str::FromStr, time::Duration};

use clap::Parser;
use console::Style;
use console::{style, StyledObject};

use crate::libdns::proto::{
    op::Message,
    rr::{DNSClass, DNSClass as QueryClass, Name as Domain, Record, RecordData, RecordType},
    xfer::Protocol as DnsOverProtocol,
};

use crate::dns_client::{DnsClient, GenericResolver, LookupOptions};
use crate::dns_url::DnsUrl;

impl ResolveCommand {
    pub fn execute(self) {
        let proto = self.proto();
        let mut server = match self.global_server() {
            Some(s) => DnsUrl::from_str(s).ok(),
            None => None,
        };
        if let Some(proto) = proto {
            if let Some(s) = server.as_mut() {
                s.set_proto(proto)
            }
        }
        let domains = self.domains();
        let query_types = self.q_type();

        let palette = Colours::pretty();

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let dns_client = if let Some(server) = server {
                    println!(
                        "{} {}",
                        palette.authority.apply_to("SERVER:"),
                        palette.authority.apply_to(&server)
                    );
                    DnsClient::builder().add_server(server).build().await
                } else {
                    DnsClient::builder().build().await
                };

                for domain in domains {
                    for query_type in query_types {
                        let options = LookupOptions {
                            record_type: *query_type,
                            ..Default::default()
                        };

                        match dns_client.lookup(domain.clone(), options).await {
                            Ok(res) => {
                                print(&res, &palette);
                            }
                            Err(err) => {
                                println!("{}", err);
                            }
                        }
                    }
                }
            });
    }
}

#[derive(Parser, Debug, Default, PartialEq, Eq)]
#[command(after_help=include_str!("../RESOLVE_EXAMPLES.txt"))]
pub struct ResolveCommand {
    #[command(flatten)]
    proto: ProtocolType,

    #[arg(short = 'J', long)]
    json: bool,

    #[arg(short = '1', long)]
    short: bool,

    /// is in the Domain Name System
    #[arg(value_name = "domain", num_args = 1, value_parser = Variant::parse::<Domain>)]
    domains: Vec<Domain>,

    /// is one of (a,any,mx,ns,soa,hinfo,axfr,txt,...)
    #[arg(value_name = "q-type", num_args = 1, value_parser = Variant::parse::<RecordType>)]
    record_types: Vec<RecordType>,

    /// is one of (in,hs,ch,...)
    #[arg(value_name = "q-class", value_parser = Variant::parse::<DNSClass>)]
    q_class: Option<DNSClass>,

    /// is the global nameserver
    #[arg(value_name = "@global-server", last = true, value_parser = Variant::parse::<String>)]
    global_server: Option<String>,
}

#[derive(Parser, Debug, Default, PartialEq, Eq)]
struct ProtocolType {
    /// Use the DNS protocol over UDP
    #[arg(short = 'U', long, group = "proto")]
    udp: bool,

    /// Use the DNS protocol over TCP
    #[arg(short = 'T', long, group = "proto")]
    tcp: bool,

    /// Use the DNS-over-TLS protocol
    #[arg(short = 'S', long, group = "proto")]
    tls: bool,

    /// Use the DNS-over-QUIC protocol
    #[arg(short = 'Q', long, group = "proto")]
    quic: bool,

    /// Use the DNS-over-HTTPS protocol
    #[arg(short = 'H', long, group = "proto")]
    https: bool,

    /// Use the DNS-over-HTTPS/3 protocol
    #[arg(long, group = "proto")]
    h3: bool,
}

impl ResolveCommand {
    pub fn parse() -> Self {
        match Parser::try_parse() {
            Ok(cli) => cli,
            Err(e) => {
                if let Ok(resolve_command) = ResolveCommand::try_parse() {
                    return resolve_command;
                }
                e.exit()
            }
        }
    }

    pub fn try_parse() -> Result<Self, String> {
        Self::try_parse_from(std::env::args())
    }

    pub fn try_parse_from<I, T>(itr: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        use DnsOverProtocol::*;
        let mut proto = None;
        let mut q_types = vec![];
        let mut q_class = None;
        let mut domain = None;
        let mut global_server = None;

        for arg in itr.into_iter().skip(1).map(Into::<OsString>::into) {
            let arg = arg
                .into_string()
                .expect("Failed to convert OsString to String");
            if arg == "resolve" {
                continue;
            }
            if arg.starts_with('-') && proto.is_none() {
                match arg.as_str() {
                    "-U" | "--udp" => {
                        proto = Some(Udp);
                        continue;
                    }
                    "-T" | "--tcp" => {
                        proto = Some(Tcp);
                        continue;
                    }
                    "-S" | "--tls" => {
                        proto = Some(Tls);
                        continue;
                    }
                    "-Q" | "--quic" => {
                        proto = Some(Quic);
                        continue;
                    }
                    "-H" | "--https" => {
                        proto = Some(Https);
                        continue;
                    }
                    "-H3" | "--h3" => {
                        proto = Some(H3);
                        continue;
                    }
                    _ => (),
                }
            }

            if let Some(s) = arg.strip_prefix('@') {
                global_server = Some(s.to_string());
                continue;
            }

            if arg.contains('+') {
                let record_types = arg
                    .split('+')
                    .map(|p| p.to_uppercase())
                    .flat_map(|s| RecordType::from_str(&s))
                    .collect::<Vec<RecordType>>();
                if !record_types.is_empty() {
                    q_types.extend(record_types);
                    continue;
                }
            }

            if let Ok(v) = Variant::from_str(&arg) {
                match v {
                    Variant::Domain(d) => {
                        domain = Some(d);
                    }
                    Variant::RecordType(t) => {
                        q_types.push(t);
                    }
                    Variant::DNSClass(c) => {
                        q_class = Some(c);
                    }
                    Variant::Server(s) => {
                        global_server = Some(s);
                    }
                }
                continue;
            }
            return Err(format!("Invalid argument {arg}"));
        }

        let Some(domain) = domain else {
            return Err("domain is required".to_string());
        };

        if q_types.is_empty() {
            q_types.push(RecordType::A);
        }

        Ok(Self {
            proto: ProtocolType {
                udp: matches!(proto, Some(Udp)),
                tcp: matches!(proto, Some(Tcp)),
                tls: matches!(proto, Some(Tls)),
                quic: matches!(proto, Some(Quic)),
                https: matches!(proto, Some(Https)),
                h3: matches!(proto, Some(H3)),
            },
            global_server,
            domains: vec![domain],
            record_types: q_types,
            q_class,
            ..Default::default()
        })
    }

    pub fn is_resolve_cli() -> bool {
        std::env::args()
            .next()
            .as_deref()
            .map(Path::new)
            .and_then(|s| s.file_stem())
            .and_then(|s| s.to_str())
            .map(|s| matches!(s, "dig" | "nslookup" | "resolve"))
            .unwrap_or_default()
    }

    pub fn proto(&self) -> Option<DnsOverProtocol> {
        use DnsOverProtocol::*;
        let proto = &self.proto;
        if proto.udp {
            Some(Udp)
        } else if proto.tcp {
            Some(Tcp)
        } else if proto.tls {
            Some(Tls)
        } else if proto.quic {
            Some(Quic)
        } else if proto.https {
            Some(Https)
        } else if proto.h3 {
            Some(H3)
        } else {
            None
        }
    }

    pub fn global_server(&self) -> Option<&str> {
        self.global_server.as_deref()
    }

    pub fn domains(&self) -> &[Domain] {
        &self.domains
    }

    pub fn q_type(&self) -> &[RecordType] {
        &self.record_types
    }

    pub fn q_class(&self) -> QueryClass {
        self.q_class.unwrap_or(QueryClass::IN)
    }
}

enum Variant {
    Domain(Domain),
    RecordType(RecordType),
    DNSClass(DNSClass),
    Server(String),
}

impl Variant {
    fn parse<T: TryFrom<Self, Error = String>>(s: &str) -> Result<T, String> {
        Self::from_str(s).and_then(|s| s.try_into())
    }
}

impl TryFrom<Variant> for Domain {
    type Error = String;
    fn try_from(s: Variant) -> Result<Self, Self::Error> {
        match s {
            Variant::Domain(domain) => Ok(domain),
            _ => Err("Expected a domain".to_string()),
        }
    }
}

impl TryFrom<Variant> for RecordType {
    type Error = String;
    fn try_from(s: Variant) -> Result<Self, Self::Error> {
        match s {
            Variant::RecordType(record_type) => Ok(record_type),
            _ => Err("Expected a record type".to_string()),
        }
    }
}

impl TryFrom<Variant> for DNSClass {
    type Error = String;
    fn try_from(s: Variant) -> Result<Self, Self::Error> {
        match s {
            Variant::DNSClass(dns_class) => Ok(dns_class),
            _ => Err("Expected a DNS class".to_string()),
        }
    }
}

impl TryFrom<Variant> for String {
    type Error = String;
    fn try_from(s: Variant) -> Result<Self, Self::Error> {
        match s {
            Variant::Server(server) => Ok(server),
            _ => Err("Expected a server".to_string()),
        }
    }
}

impl FromStr for Variant {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(s) = s.strip_prefix('@') {
            return Ok(Self::Server(s.to_string()));
        }

        let upper = s.to_uppercase();

        if let Ok(record_type) = RecordType::from_str(&upper) {
            return Ok(Self::RecordType(record_type));
        }
        if let Ok(dns_class) = DNSClass::from_str(&upper) {
            return Ok(Self::DNSClass(dns_class));
        }

        if let Ok(name) = Domain::from_str(s) {
            return Ok(Self::Domain(name));
        }

        Err(format!("Invalid query variant: {}", s))
    }
}

fn print(message: &Message, palette: &Colours) {
    for r in message.answers() {
        print_record(&r, palette);
    }
    for r in message.additionals() {
        print_record(&r, palette);
    }
}

fn print_record<D: RecordData, R: Deref<Target = Record<D>>>(r: &R, palette: &Colours) {
    println!(
        "{ty}\t{name}\t{ttl}\t{class}\t{rdata}",
        name = palette.qname.apply_to(r.name()),
        ttl = style(format_duration_hms(r.ttl())).blue(),
        class = style(r.dns_class()).blue(),
        ty = format_record_type(r.record_type(), palette),
        rdata = r.data(),
    );
}

fn format_duration_hms(ttl: u32) -> String {
    format!("{:?}", Duration::from_secs(ttl as u64))
}

fn format_record_type(typ: RecordType, palette: &Colours) -> StyledObject<RecordType> {
    palette
        .record_types
        .get(&typ)
        .unwrap_or(&palette.unknown)
        .clone()
        .apply_to(typ)
}

#[derive(Default)]
struct Colours {
    pub qname: Style,

    pub answer: Style,
    pub authority: Style,
    pub additional: Style,

    pub record_types: HashMap<RecordType, Style>,
    pub unknown: Style,
}

impl Colours {
    pub fn pretty() -> Self {
        use RecordType::*;
        let mut record_types = HashMap::new();
        record_types.insert(A, Style::new().green());
        record_types.insert(AAAA, Style::new().green());
        record_types.insert(CAA, Style::new().red());
        record_types.insert(CNAME, Style::new().yellow());
        record_types.insert(MX, Style::new().cyan());
        record_types.insert(NAPTR, Style::new().green());
        record_types.insert(NS, Style::new().red());
        record_types.insert(OPENPGPKEY, Style::new().cyan());
        record_types.insert(OPT, Style::new().magenta());
        record_types.insert(PTR, Style::new().red());
        record_types.insert(SSHFP, Style::new().cyan());
        record_types.insert(SOA, Style::new().magenta());
        record_types.insert(SRV, Style::new().cyan());
        record_types.insert(TLSA, Style::new().yellow());
        record_types.insert(TXT, Style::new().yellow());

        Self {
            qname: Style::new().blue().bold(),

            answer: Style::default(),
            authority: Style::new().cyan(),
            additional: Style::new().green(),

            record_types,
            unknown: Style::new().white().on_red(),
        }
    }

    pub fn plain() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parse() {
        assert_eq!(
            ResolveCommand::try_parse_from(["dig", "example.com", "a"]).unwrap(),
            ResolveCommand {
                domains: vec!["example.com".parse().unwrap()],
                record_types: ["A"]
                    .iter()
                    .map(|s| s.parse())
                    .collect::<Result<Vec<RecordType>, _>>()
                    .unwrap(),
                ..Default::default()
            }
        );

        assert_eq!(
            ResolveCommand::try_parse_from(["dig", "example.com", "a+aaaa"]).unwrap(),
            ResolveCommand {
                domains: vec!["example.com".parse().unwrap()],
                record_types: ["A", "AAAA"]
                    .iter()
                    .map(|s| s.parse())
                    .collect::<Result<Vec<RecordType>, _>>()
                    .unwrap(),
                ..Default::default()
            }
        );

        assert_eq!(
            ResolveCommand::try_parse_from(["dig", "example.com", "a", "aaaa", "TXT"]).unwrap(),
            ResolveCommand {
                domains: vec!["example.com".parse().unwrap()],
                record_types: ["A", "AAAA", "TXT"]
                    .iter()
                    .map(|s| s.parse())
                    .collect::<Result<Vec<RecordType>, _>>()
                    .unwrap(),
                ..Default::default()
            }
        );

        assert_eq!(
            ResolveCommand::try_parse_from(["dig", "example.com", "a", "aaaa", "in"]).unwrap(),
            ResolveCommand {
                domains: vec!["example.com".parse().unwrap()],
                record_types: ["A", "AAAA"]
                    .iter()
                    .map(|s| s.parse())
                    .collect::<Result<Vec<RecordType>, _>>()
                    .unwrap(),
                q_class: Some(DNSClass::IN),
                ..Default::default()
            }
        );

        assert_eq!(
            ResolveCommand::try_parse_from(["dig", "example.com", "a", "aaaa", "in", "@1.1.1.1"])
                .unwrap(),
            ResolveCommand {
                domains: vec!["example.com".parse().unwrap()],
                record_types: ["A", "AAAA"]
                    .iter()
                    .map(|s| s.parse())
                    .collect::<Result<Vec<RecordType>, _>>()
                    .unwrap(),
                global_server: Some("1.1.1.1".to_string()),
                q_class: Some(DNSClass::IN),
                ..Default::default()
            }
        );

        assert_eq!(
            ResolveCommand::try_parse_from(["dig", "@1.1.1.1", "example.com", "a", "aaaa", "in"])
                .unwrap(),
            ResolveCommand {
                domains: vec!["example.com".parse().unwrap()],
                record_types: ["A", "AAAA"]
                    .iter()
                    .map(|s| s.parse())
                    .collect::<Result<Vec<RecordType>, _>>()
                    .unwrap(),
                global_server: Some("1.1.1.1".to_string()),
                q_class: Some(DNSClass::IN),
                ..Default::default()
            }
        );
    }
}
