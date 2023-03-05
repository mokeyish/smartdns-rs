pub mod proto {
    pub use trust_dns_proto::*;
}

pub mod resolver {
    use self::lookup::Lookup;
    pub use trust_dns_resolver::*;

    pub trait LookupTtl {
        fn max_ttl(&self) -> Option<u32>;
        fn min_ttl(&self) -> Option<u32>;

        fn with_new_ttl(&self, ttl: u32) -> Self
        where
            Self: Sized;
    }

    impl LookupTtl for Lookup {
        fn max_ttl(&self) -> Option<u32> {
            self.record_iter().map(|record| record.ttl()).max()
        }

        fn min_ttl(&self) -> Option<u32> {
            self.record_iter().map(|record| record.ttl()).min()
        }

        fn with_new_ttl(&self, ttl: u32) -> Self {
            let records = self
                .records()
                .iter()
                .map(|record| {
                    let mut record = record.clone();
                    record.set_ttl(ttl);
                    record
                })
                .collect::<Vec<_>>();

            Lookup::new_with_deadline(self.query().clone(), records.into(), self.valid_until())
        }
    }
}
