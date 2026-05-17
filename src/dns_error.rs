use crate::dns::{DefaultSOA as _, DnsResponse};
use crate::libdns::{
    net::{DnsError, NetError, NoRecords},
    proto::{
        ProtoError,
        op::{Query, ResponseCode},
        rr::{Record, rdata::SOA},
    },
};

use std::{io, sync::Arc};
use thiserror::Error;

#[allow(clippy::large_enum_variant)]
/// A query could not be fulfilled
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum LookupError {
    /// A record at the same Name as the query exists, but not of the queried RecordType
    #[error("The name exists, but not for the record requested")]
    NameExists,
    /// There was an error performing the lookup
    #[error("Error performing lookup: {0}")]
    ResponseCode(ResponseCode),
    /// An error got returned by the hickory-proto crate
    #[error("proto error: {0}")]
    Proto(#[from] ProtoError),
    /// An error got returned by the hickory-net crate
    #[error("net error: {0}")]
    Net(#[from] NetError),
    /// Semantic DNS errors
    #[error("DNS error: {0}")]
    Dns(#[from] DnsError),
    /// An underlying IO error occurred
    #[error("io error: {0}")]
    Io(Arc<io::Error>),
}

impl PartialEq for LookupError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::ResponseCode(l0), Self::ResponseCode(r0)) => l0 == r0,
            (Self::Proto(l0), Self::Proto(r0)) => l0.to_string() == r0.to_string(),
            (Self::Io(l0), Self::Io(r0)) => l0.to_string() == r0.to_string(),
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

impl LookupError {
    pub fn is_nx_domain(&self) -> bool {
        matches!(self, Self::ResponseCode(resc) if resc.eq(&ResponseCode::NXDomain))
    }

    #[inline]
    pub fn is_soa(&self) -> bool {
        if let Self::Dns(err) = self
            && let DnsError::NoRecordsFound(NoRecords { soa: Some(_), .. }) = err
        {
            return true;
        }
        false
    }

    pub fn as_soa(&self, query: &Query) -> Option<DnsResponse> {
        if let Self::Dns(err) = self
            && let DnsError::NoRecordsFound(NoRecords {
                soa: Some(record), ..
            }) = err
        {
            let mut dns_response = DnsResponse::new_with_max_ttl(query.to_owned(), Vec::new());
            dns_response.add_authority(record.as_ref().to_owned().into_record_of_rdata());
            return Some(dns_response);
        }
        None
    }

    pub fn no_records_found(query: Query, ttl: u32) -> LookupError {
        let soa = Record::from_rdata(query.name().to_owned(), ttl, SOA::default_soa());

        let mut no_records = NoRecords::new(query, ResponseCode::ServFail);
        no_records.soa = Some(Box::new(soa));

        DnsError::NoRecordsFound(no_records).into()
    }
}

impl From<ResponseCode> for LookupError {
    fn from(value: ResponseCode) -> Self {
        Self::ResponseCode(value)
    }
}

impl From<io::Error> for LookupError {
    fn from(value: io::Error) -> Self {
        Self::Io(Arc::new(value))
    }
}
