use std::net::IpAddr;

use ipnet::IpNet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Client {
    MacAddr(String),
    IpAddr(IpNet),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRule {
    /// The client, mac address or ip address
    pub client: Client,

    /// The rule group name
    pub group: String,
}

impl ClientRule {
    pub fn match_ip(&self, ip: &IpAddr) -> bool {
        match &self.client {
            Client::MacAddr(_) => false,
            Client::IpAddr(ip_net) => ip_net.contains(ip),
        }
    }

    pub fn match_net(&self, net: &IpNet) -> bool {
        match &self.client {
            Client::MacAddr(_) => false,
            Client::IpAddr(ip_net) => ip_net.contains(net),
        }
    }

    pub fn match_mac(&self, mac: &str) -> bool {
        match &self.client {
            Client::MacAddr(mac_addr) => mac_addr == mac,
            Client::IpAddr(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_rule() {
        let rule = ClientRule {
            client: Client::IpAddr("192.168.1.0/24".parse().unwrap()),
            group: "test".to_string(),
        };

        assert!(rule.match_ip(&"192.168.1.0".parse().unwrap()));
        assert!(rule.match_ip(&"192.168.1.2".parse().unwrap()));
        assert!(rule.match_net(&"192.168.1.2/32".parse().unwrap()));
    }
}
