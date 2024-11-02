use std::collections::HashMap;
use std::{ops::Deref, str::FromStr, time::Duration};

use clap::Parser;
use console::Style;
use console::{style, StyledObject};

use crate::libdns::proto::{
    op::Message,
    rr::{
        DNSClass as QueryClass, Name as Domain, Record, RecordData, RecordType as QueryType,
        RecordType,
    },
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
        let domain = self.domain().clone();
        let query_type = self.q_type();

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

                let options = LookupOptions {
                    record_type: query_type,
                    ..Default::default()
                };

                match dns_client.lookup(domain, options).await {
                    Ok(res) => {
                        print(&res, &palette);
                    }
                    Err(err) => {
                        println!("{}", err);
                    }
                }
            });
    }
}

#[derive(Parser, Debug)]
#[command(after_help=include_str!("../RESOLVE_EXAMPLES.txt"))]
pub struct ResolveCommand {
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

    /// is in the Domain Name System
    #[arg(value_name = "domain")]
    domain: Domain,

    /// is one of (a,any,mx,ns,soa,hinfo,axfr,txt,...)
    #[arg(value_name = "q-type", default_value = "a", value_parser = Self::parse_query_type)]
    q_type: QueryType,

    /// is one of (in,hs,ch,...)
    #[arg(value_name = "q-class", default_value = "in", value_parser = Self::parse_query_class)]
    q_class: QueryClass,

    /// is the global nameserver
    #[arg(value_name = "@global-server")]
    global_server: Option<String>,
}

impl ResolveCommand {
    pub fn try_parse() -> Result<Self, String> {
        use DnsOverProtocol::*;
        let mut proto = None;
        let mut q_type = None;
        let mut q_class = None;
        let mut domain = None;
        let mut global_server = None;

        for arg in std::env::args().skip(1) {
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

            if q_type.is_none() {
                if let Ok(t) = Self::parse_query_type(arg.as_str()) {
                    q_type = Some(t);
                    continue;
                }
            }

            if q_class.is_none() {
                if let Ok(t) = Self::parse_query_class(arg.as_str()) {
                    q_class = Some(t);
                    continue;
                }
            }

            if domain.is_none() {
                if let Ok(t) = Domain::from_str(arg.as_str()) {
                    domain = Some(t);
                    continue;
                }
            }
            return Err(format!("Invalid argument {arg}"));
        }

        let Some(domain) = domain else {
            return Err("domain is required".to_string());
        };

        let q_type = q_type.unwrap_or(QueryType::A);
        let q_class = q_class.unwrap_or(QueryClass::IN);

        Ok(Self {
            udp: matches!(proto, Some(Udp)),
            tcp: matches!(proto, Some(Tcp)),
            tls: matches!(proto, Some(Tls)),
            quic: matches!(proto, Some(Quic)),
            https: matches!(proto, Some(Https)),
            h3: matches!(proto, Some(H3)),
            global_server,
            domain,
            q_type,
            q_class,
        })
    }

    pub fn proto(&self) -> Option<DnsOverProtocol> {
        use DnsOverProtocol::*;
        if self.udp {
            Some(Udp)
        } else if self.tcp {
            Some(Tcp)
        } else if self.tls {
            Some(Tls)
        } else if self.quic {
            Some(Quic)
        } else if self.https {
            Some(Https)
        } else if self.h3 {
            Some(H3)
        } else {
            None
        }
    }

    pub fn global_server(&self) -> Option<&str> {
        self.global_server.as_deref()
    }

    pub fn domain(&self) -> &Domain {
        &self.domain
    }

    pub fn q_type(&self) -> QueryType {
        self.q_type
    }

    pub fn q_class(&self) -> QueryClass {
        self.q_class
    }

    fn parse_global_server(s: &str) -> Result<String, String> {
        if let Some(s) = s.strip_prefix('@') {
            Ok(s.to_string())
        } else {
            Err(format!("Invalid global server: {}", s))
        }
    }
    fn parse_query_type(s: &str) -> Result<QueryType, String> {
        QueryType::from_str(s.to_uppercase().as_str()).map_err(|e| e.to_string())
    }
    fn parse_query_class(s: &str) -> Result<QueryClass, String> {
        QueryClass::from_str(s.to_uppercase().as_str()).map_err(|e| e.to_string())
    }
}

fn print(message: &Message, palette: &Colours) {
    for r in message.answers() {
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
