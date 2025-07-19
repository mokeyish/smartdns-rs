use crate::libdns::proto::{
    ProtoError,
    xfer::{DnsHandle, FirstAnswer},
};

static DEFAULT_QUERY: std::sync::LazyLock<crate::libdns::proto::xfer::DnsRequest> =
    std::sync::LazyLock::new(|| {
        use crate::libdns::proto::{
            op::{Message, Query},
            rr::RecordType,
            xfer::DnsRequest,
        };
        let query = Query::query("example.com.".parse().unwrap(), RecordType::A);
        let mut message = Message::query();
        message.add_query(query);
        DnsRequest::new(message, Default::default())
    });

pub trait DnsHandleWarmpup {
    async fn warmup(&self) -> Result<(), ProtoError>;
}

impl<T: DnsHandle> DnsHandleWarmpup for T {
    async fn warmup(&self) -> Result<(), ProtoError> {
        self.send(DEFAULT_QUERY.clone()).first_answer().await?;
        Ok(())
    }
}
