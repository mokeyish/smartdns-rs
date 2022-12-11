use std::io::Write;
use std::path::Path;
use std::time::Duration;
use std::time::Instant;

use chrono::prelude::*;
use smallvec::SmallVec;
use tokio::sync::mpsc::{self, Sender};

use trust_dns_proto::op::Query;

use crate::dns::*;
use crate::infra::mapped_file::MappedFile;
use crate::log::warn;
use crate::middleware::*;

pub struct DnsAuditMiddleware {
    audit_sender: Sender<DnsAuditRecord>,
}

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsAuditMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let now = Local::now();

        let start = Instant::now();

        let res = next.run(ctx, req).await;

        let duration = start.elapsed();

        let audit = DnsAuditRecord::new(
            req.id(),
            now,
            req.src().to_string(),
            req.query().original().to_owned(),
            res.clone(),
            duration,
            ctx.fastest_speed,
            ctx.lookup_source.clone(),
        );

        // debug!("{}", audit.to_string_without_date());

        self.audit_sender
            .send(audit)
            .await
            .unwrap_or_else(|err| warn!("send audit failed,{}", err));

        res
    }
}

impl DnsAuditMiddleware {
    pub fn new<P: AsRef<Path>>(path: P, audit_size: u64, audit_num: usize) -> Self {
        let audit_file = path.as_ref().to_owned();

        let (audit_tx, mut audit_rx) = mpsc::channel::<DnsAuditRecord>(100);

        tokio::spawn(async move {
            let mut audit_file = MappedFile::open(audit_file, audit_size, Some(audit_num));

            const BUF_SIZE: usize = 10;
            let mut buf: SmallVec<[DnsAuditRecord; BUF_SIZE]> = SmallVec::new();

            while let Some(audit) = audit_rx.recv().await {
                buf.push(audit);

                if buf.len() == BUF_SIZE {
                    record_audit_to_file(&mut audit_file, buf.as_slice());
                    buf.clear();
                }
            }
        });

        Self {
            audit_sender: audit_tx,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsAuditRecord {
    id: u16,
    client: String,
    query: Query,
    result: Result<DnsResponse, DnsError>,
    speed: Duration,
    elapsed: Duration,
    date: DateTime<Local>,
    lookup_source: LookupSource,
}

impl DnsAuditRecord {
    fn new(
        id: u16,
        now: DateTime<Local>,
        source_host: String,
        query: Query,
        result: Result<DnsResponse, DnsError>,
        elapsed: Duration,
        speed: Duration,
        lookup_source: LookupSource,
    ) -> Self {
        Self {
            id,
            date: now,
            client: source_host,
            query,
            result,
            elapsed,
            speed,
            lookup_source,
        }
    }

    fn fmt_result(&self) -> String {
        self.result
            .as_ref()
            .map(|lookup| lookup.records().to_vec())
            .unwrap_or_default();

        if let Ok(lookup) = self.result.as_ref() {
            lookup
                .records()
                .iter()
                .map(|record| {
                    format!(
                        "{} {} {}",
                        record
                            .data()
                            .map(|data| data.to_string())
                            .unwrap_or_default(),
                        record.ttl(),
                        record.rr_type()
                    )
                })
                .collect::<Vec<_>>()
                .join("|")
        } else {
            "query failed".to_string()
        }
    }

    fn to_string_without_date(&self) -> String {
        format!(
            "{} query {}, type: {}, elapsed: {:?}, speed: {:?}, result {}",
            self.client,
            self.query.name(),
            self.query.query_type(),
            self.elapsed,
            self.speed,
            self.fmt_result()
        )
    }
}

impl ToString for DnsAuditRecord {
    fn to_string(&self) -> String {
        format!(
            "[{}] {} query {}, type: {}, elapsed: {:?}, speed: {:?}, result {}",
            self.date.format("%Y-%m-%d %H:%M:%S,%3f"),
            self.client,
            self.query.name(),
            self.query.query_type(),
            self.elapsed,
            self.speed,
            self.fmt_result()
        )
    }
}

fn record_audit_to_file(audit_file: &mut MappedFile, audit_records: &[DnsAuditRecord]) {
    if matches!(audit_file.extension(), Some(ext) if ext == "csv") {
        // write as csv

        if audit_file.peamble().is_none() {
            let mut writer = csv::Writer::from_writer(vec![]);
            writer
                .write_record(&[
                    "id",
                    "timestamp",
                    "client",
                    "name",
                    "type",
                    "elapsed",
                    "speed",
                    "state",
                    "result",
                    "lookup_source",
                ])
                .unwrap();

            audit_file.set_peamble(Some(writer.into_inner().unwrap().into_boxed_slice()))
        }

        let mut writer = csv::Writer::from_writer(audit_file);

        for audit in audit_records {
            writer
                .write_record(&[
                    audit.id.to_string().as_str(),
                    audit.date.timestamp().to_string().as_str(),
                    audit.client.as_str(),
                    audit.query.name().to_string().as_str(),
                    audit.query.query_type().to_string().as_str(),
                    format!("{:?}", audit.elapsed).as_str(),
                    format!("{:?}", audit.speed).as_str(),
                    if audit.result.is_ok() {
                        "success"
                    } else {
                        "failed"
                    },
                    audit.fmt_result().as_str(),
                    format!("{:?}", audit.lookup_source).as_str(),
                ])
                .unwrap();
        }
    } else {
        // write as nornmal log format.
        for audit in audit_records {
            if writeln!(audit_file, "{}", audit.to_string()).is_err() {
                warn!("Write audit to file '{:?}' failed", audit_file.path());
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use std::io::Read;
    use std::str::FromStr;
    use trust_dns_proto::op::Query;
    use trust_dns_proto::rr::{RData, RecordType};

    use super::*;

    #[test]
    fn test_dns_audit_to_string() {
        let now = "2022-11-11 20:18:11.099966887 +08:00".parse().unwrap();
        let query = Query::query(Name::from_str("www.example.com").unwrap(), RecordType::A);
        let result = Ok(Lookup::from_rdata(
            query.to_owned(),
            RData::A("93.184.216.34".parse().unwrap()),
        ));

        let audit = DnsAuditRecord::new(
            11,
            now,
            "127.0.0.1".to_string(),
            query,
            result,
            Duration::from_millis(10),
            Duration::from_millis(11),
            LookupSource::Server("default".to_string()),
        );

        assert_eq!(audit.to_string(), format!("[{}] 127.0.0.1 query www.example.com, type: A, elapsed: 10ms, speed: 11ms, result 93.184.216.34 86400 A", now.format("%Y-%m-%d %H:%M:%S,%3f")));
    }

    #[test]
    fn test_dns_audit_to_string_without_date() {
        let now = "2022-11-11 20:18:11.099966887 +08:00".parse().unwrap();

        let query = Query::query(Name::from_str("www.example.com").unwrap(), RecordType::A);
        let result = Ok(Lookup::from_rdata(
            query.to_owned(),
            RData::A("93.184.216.34".parse().unwrap()),
        ));

        let audit = DnsAuditRecord::new(
            11,
            now,
            "127.0.0.1".to_string(),
            query,
            result,
            Duration::from_millis(10),
            Duration::from_millis(11),
            LookupSource::Server("default".to_string()),
        );

        assert_eq!(audit.to_string_without_date(), "127.0.0.1 query www.example.com, type: A, elapsed: 10ms, speed: 11ms, result 93.184.216.34 86400 A");
    }

    #[test]
    fn test_record_audit_to_file() {
        let query = Query::query(Name::from_str("www.example.com").unwrap(), RecordType::A);

        let result = Ok(Lookup::from_rdata(
            query.to_owned(),
            RData::A("93.184.216.34".parse().unwrap()),
        ));

        let now = "2022-11-11 20:18:11.099966887 +08:00".parse().unwrap();

        let audit = DnsAuditRecord::new(
            11,
            now,
            "127.0.0.1".to_string(),
            query,
            result,
            Duration::from_millis(10),
            Duration::from_millis(11),
            LookupSource::Server("default".to_string()),
        );

        let file = format!("./logs/test-{}-audit.log", Local::now().timestamp_millis());
        let file = Path::new(file.as_str());

        record_audit_to_file(&mut MappedFile::open(file, 102400, None), &[audit]);

        assert!(file.exists());

        let mut s = String::new();

        std::fs::File::open(file)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();

        assert_eq!(s, format!("[{}] 127.0.0.1 query www.example.com, type: A, elapsed: 10ms, speed: 11ms, result 93.184.216.34 86400 A\n", now.format("%Y-%m-%d %H:%M:%S,%3f")));

        std::fs::remove_file(file).unwrap();

        assert!(!file.exists());
    }

    #[test]
    fn test_record_audit_to_csv_file() {
        let query = Query::query(Name::from_str("www.example.com").unwrap(), RecordType::A);

        let result = Ok(Lookup::from_rdata(
            query.to_owned(),
            RData::A("93.184.216.34".parse().unwrap()),
        ));

        let audit1 = DnsAuditRecord::new(
            11,
            "2022-11-11 20:18:11.099966887 +08:00".parse().unwrap(),
            "127.0.0.1".to_string(),
            query.clone(),
            result.clone(),
            Duration::from_millis(10),
            Duration::from_millis(11),
            LookupSource::Server("default1".to_string()),
        );

        let audit2 = DnsAuditRecord::new(
            12,
            "2022-11-11 20:18:11.099966887 +08:00".parse().unwrap(),
            "127.0.0.1".to_string(),
            query,
            result,
            Duration::from_millis(10),
            Duration::from_millis(11),
            LookupSource::Server("default2".to_string()),
        );

        let file = format!("./logs/test-{}-audit.csv", Local::now().timestamp_millis());
        let file = Path::new(file.as_str());

        record_audit_to_file(&mut MappedFile::open(file, 102400, None), &[audit1]);

        assert!(file.exists());

        let mut s = String::new();

        std::fs::File::open(file)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();

        assert_eq!(s, "id,timestamp,client,name,type,elapsed,speed,state,result,lookup_source\n11,1668169091,127.0.0.1,www.example.com,A,10ms,11ms,success,93.184.216.34 86400 A,Server: default1\n");

        record_audit_to_file(&mut MappedFile::open(file, 102400, None), &[audit2]);

        let mut s = String::new();

        std::fs::File::open(file)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();

        assert_eq!(s, "id,timestamp,client,name,type,elapsed,speed,state,result,lookup_source\n11,1668169091,127.0.0.1,www.example.com,A,10ms,11ms,success,93.184.216.34 86400 A,Server: default1\n12,1668169091,127.0.0.1,www.example.com,A,10ms,11ms,success,93.184.216.34 86400 A,Server: default2\n");

        std::fs::remove_file(file).unwrap();

        assert!(!file.exists());
    }
}
