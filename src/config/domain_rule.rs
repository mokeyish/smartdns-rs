use crate::libdns::proto::rr::rdata::opt::ClientSubnet;

use super::*;

/// domain-rules /domain/ [-rules...]
#[derive(Debug, Clone, Default, Hash, PartialEq, Eq)]
pub struct DomainRule {
    /// The name of NameServer Group.
    pub nameserver: Option<String>,

    pub address: Option<DomainAddress>,

    pub cname: Option<CName>,

    /// The mode of speed checking.
    pub speed_check_mode: Option<SpeedCheckModeList>,

    pub dualstack_ip_selection: Option<bool>,

    pub response_mode: Option<ResponseMode>,

    pub no_cache: Option<bool>,
    pub no_serve_expired: Option<bool>,
    pub nftset: Option<Vec<ConfigForIP<NftsetConfig>>>,

    pub rr_ttl: Option<u64>,
    pub rr_ttl_min: Option<u64>,
    pub rr_ttl_max: Option<u64>,

    pub client_subnet: Option<ClientSubnet>,
}

impl std::ops::AddAssign for DomainRule {
    fn add_assign(&mut self, rhs: Self) {
        if rhs.nameserver.is_some() {
            self.nameserver = rhs.nameserver;
        }

        if rhs.address.is_some() {
            self.address = rhs.address;
        }

        if rhs.speed_check_mode.is_some() {
            self.speed_check_mode = rhs.speed_check_mode;
        }
        if rhs.dualstack_ip_selection.is_some() {
            self.dualstack_ip_selection = rhs.dualstack_ip_selection;
        }
        if rhs.no_cache.is_some() {
            self.no_cache = rhs.no_cache;
        }
        if rhs.no_serve_expired.is_some() {
            self.no_serve_expired = rhs.no_serve_expired
        }

        if rhs.rr_ttl.is_some() {
            self.rr_ttl = rhs.rr_ttl;
        }
        if rhs.rr_ttl_min.is_some() {
            self.rr_ttl_min = rhs.rr_ttl_min;
        }

        self.rr_ttl_max = rhs.rr_ttl_min.or(self.rr_ttl_max);
    }
}
