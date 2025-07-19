use crate::dns::{DefaultSOA as _, DnsResponse};
use crate::libdns::proto::{
    AuthorityData, NoRecords, ProtoError, ProtoErrorKind,
    op::{Query, ResponseCode},
    rr::{Record, rdata::SOA},
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
        if let Self::Proto(err) = self {
            if let ProtoErrorKind::NoRecordsFound(NoRecords { soa: Some(_), .. }) = err.kind() {
                return true;
            }
        }
        false
    }

    pub fn as_soa(&self, query: &Query) -> Option<DnsResponse> {
        if let Self::Proto(err) = self {
            if let ProtoErrorKind::NoRecordsFound(NoRecords {
                soa: Some(record), ..
            }) = err.kind()
            {
                let mut dns_response = DnsResponse::new_with_max_ttl(query.to_owned(), Vec::new());
                dns_response.add_authority(record.as_ref().to_owned().into_record_of_rdata());
                return Some(dns_response);
            }
        }
        None
    }

    pub fn no_records_found(query: Query, ttl: u32) -> LookupError {
        let soa = Record::from_rdata(query.name().to_owned(), ttl, SOA::default_soa());

        let no_records = AuthorityData::new(query.into(), Some(Box::new(soa)), true, true, None);
        let mut no_records: NoRecords = no_records.into();
        no_records.response_code = ResponseCode::ServFail;

        ProtoErrorKind::NoRecordsFound(no_records).into()
    }
}

impl From<ResponseCode> for LookupError {
    fn from(value: ResponseCode) -> Self {
        Self::ResponseCode(value)
    }
}

impl From<ProtoErrorKind> for LookupError {
    fn from(value: ProtoErrorKind) -> Self {
        Self::Proto(value.into())
    }
}
