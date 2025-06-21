pub mod proto {
    pub use hickory_proto::*;
}

pub mod resolver {
    use super::proto::rr::Record;
    pub use hickory_resolver::*;

    pub trait TtlClip {
        fn set_max_ttl(&mut self, ttl: u32);
        fn set_min_ttl(&mut self, ttl: u32);
        fn set_ttl(&mut self, ttl: u32);
    }

    impl TtlClip for Record {
        #[inline]
        fn set_max_ttl(&mut self, max_ttl: u32) {
            if self.ttl() > max_ttl {
                self.set_ttl(max_ttl);
            }
        }

        #[inline]
        fn set_min_ttl(&mut self, min_ttl: u32) {
            if self.ttl() < min_ttl {
                self.set_ttl(min_ttl);
            }
        }

        #[inline]
        fn set_ttl(&mut self, ttl: u32) {
            Record::set_ttl(self, ttl);
        }
    }
}

pub use proto::xfer::Protocol;

pub trait ProtocolDefaultPort {
    fn default_port(&self) -> u16;
    fn is_default_port(&self, port: u16) -> bool {
        self.default_port() == port
    }
}

impl ProtocolDefaultPort for Protocol {
    fn default_port(&self) -> u16 {
        use Protocol::*;
        match *self {
            Udp => 53,
            Tcp => 53,
            Tls => 853,
            #[cfg(feature = "dns-over-https")]
            Https => 443,
            #[cfg(feature = "dns-over-h3")]
            H3 => 443,
            #[cfg(feature = "dns-over-quic")]
            Quic => 853,
            #[cfg(feature = "mdns")]
            Mdns => 5353,
            _ => unimplemented!(),
        }
    }
}
