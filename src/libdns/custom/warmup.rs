use crate::{
    dns_error::LookupError,
    libdns::net::xfer::{DnsHandle, FirstAnswer},
};

static DEFAULT_QUERY: std::sync::LazyLock<crate::libdns::proto::op::DnsRequest> =
    std::sync::LazyLock::new(|| {
        use crate::libdns::proto::{
            op::{DnsRequest, Message, Query},
            rr::{Name, RecordType},
        };
        let query = Query::query(Name::root(), RecordType::NS);
        let mut message = Message::query();
        message.add_query(query);
        DnsRequest::new(message, Default::default())
    });

pub trait DnsHandleWarmpup {
    async fn warmup(&self) -> Result<(), LookupError>;
}

impl<T: DnsHandle> DnsHandleWarmpup for T {
    async fn warmup(&self) -> Result<(), LookupError> {
        self.send(DEFAULT_QUERY.clone()).first_answer().await?;
        Ok(())
    }
}
