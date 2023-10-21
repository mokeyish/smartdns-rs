use crate::libdns::proto::{error::ProtoError, op::ResponseCode};
use crate::libdns::resolver::{
    error::{ResolveError, ResolveErrorKind},
    lookup::Lookup,
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
    /// Resolve Error
    #[error("Forward resolution error: {0}")]
    ResolveError(#[from] ResolveError),
    /// Recursive Resolver Error
    #[cfg(feature = "hickory-recursor")]
    #[cfg_attr(docsrs, doc(cfg(feature = "recursor")))]
    #[error("Recursive resolution error: {0}")]
    RecursiveError(#[from] create::libdns::recursor::Error),
    /// An underlying IO error occurred
    #[error("io error: {0}")]
    Io(Arc<io::Error>),
}

impl LookupError {
    pub fn is_nx_domain(&self) -> bool {
        matches!(self, Self::ResponseCode(resc) if resc.eq(&ResponseCode::NXDomain))
    }

    #[inline]
    pub fn is_soa(&self) -> bool {
        self.as_soa().is_some()
    }

    pub fn as_soa(&self) -> Option<Lookup> {
        if let Self::ResolveError(err) = self {
            if let ResolveErrorKind::NoRecordsFound {
                query,
                soa: Some(record),
                ..
            } = err.kind()
            {
                return Some(Lookup::new_with_max_ttl(
                    query.as_ref().to_owned(),
                    vec![record.as_ref().to_owned().into_record_of_rdata()].into(),
                ));
            }
        }
        None
    }
}

impl From<ResponseCode> for LookupError {
    fn from(value: ResponseCode) -> Self {
        Self::ResponseCode(value)
    }
}

impl From<ProtoError> for LookupError {
    fn from(value: ProtoError) -> Self {
        Self::ResolveError(value.into())
    }
}

impl From<ResolveErrorKind> for LookupError {
    fn from(value: ResolveErrorKind) -> Self {
        Self::ResolveError(value.into())
    }
}
