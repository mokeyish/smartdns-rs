pub mod proto {
    pub use hickory_proto::*;
}

pub mod resolver {
    use hickory_resolver::lookup::Lookup;
    pub use hickory_resolver::*;
    use proto::rr::Record;

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

    pub trait LookupTtl {
        fn max_ttl(&self) -> Option<u32>;
        fn min_ttl(&self) -> Option<u32>;

        fn with_new_ttl(&self, ttl: u32) -> Self
        where
            Self: Sized;

        fn with_max_ttl(&self, ttl: u32) -> Self
        where
            Self: Sized;

        fn with_min_ttl(&self, ttl: u32) -> Self
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

        fn with_max_ttl(&self, ttl: u32) -> Self {
            let records = self
                .records()
                .iter()
                .map(|record| {
                    let mut record = record.clone();
                    record.set_max_ttl(ttl);
                    record
                })
                .collect::<Vec<_>>();

            Lookup::new_with_deadline(self.query().clone(), records.into(), self.valid_until())
        }

        fn with_min_ttl(&self, ttl: u32) -> Self {
            let records = self
                .records()
                .iter()
                .map(|record| {
                    let mut record = record.clone();
                    record.set_min_ttl(ttl);
                    record
                })
                .collect::<Vec<_>>();

            Lookup::new_with_deadline(self.query().clone(), records.into(), self.valid_until())
        }
    }
}

pub mod server {
    pub use hickory_server::*;
}
