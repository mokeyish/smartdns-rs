use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::Duration;
use std::time::Instant;

use chrono::prelude::*;
use smallvec::SmallVec;
use tokio::sync::mpsc::{self, Sender};

use trust_dns_client::rr::Record;
use trust_dns_client::rr::RecordType;
use trust_dns_resolver::Name;

use crate::dns::*;
use crate::log::{debug, warn};
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

        let records = res
            .as_ref()
            .map(|lookup| lookup.records().to_vec())
            .unwrap_or_default();
        let audit = DnsAuditRecord::new(
            now,
            req.src().to_string(),
            req.query().original().name().to_owned(),
            req.query().query_type().to_owned(),
            records,
            duration,
            ctx.fastest_speed,
        );

        debug!("{}", audit.to_string_without_date());

        self.audit_sender
            .send(audit)
            .await
            .unwrap_or_else(|err| warn!("send audit failed,{}", err));

        res
    }
}

impl DnsAuditMiddleware {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let audit_file = path.as_ref().to_owned();

        let (audit_tx, mut audit_rx) = mpsc::channel::<DnsAuditRecord>(100);

        tokio::spawn(async move {
            let audit_file = audit_file;

            const BUF_SIZE: usize = 10;
            let mut buf: SmallVec<[DnsAuditRecord; BUF_SIZE]> = SmallVec::new();

            while let Some(audit) = audit_rx.recv().await {
                buf.push(audit);

                if buf.len() == BUF_SIZE {
                    record_audit_to_file(audit_file.as_path(), buf.as_slice());
                    buf.clear();
                }
            }
        });

        Self {
            audit_sender: audit_tx,
        }
    }
}

#[derive(Debug)]
pub struct DnsAuditRecord {
    source_host: String,
    query: Name,
    query_type: RecordType,
    result: Vec<Record>,
    speed: Duration,
    elapsed: Duration,
    date: DateTime<Local>,
}

impl DnsAuditRecord {
    fn new(
        now: DateTime<Local>,
        source_host: String,
        query: Name,
        query_type: RecordType,
        result: Vec<Record>,
        elapsed: Duration,
        speed: Duration,
    ) -> Self {
        Self {
            date: now,
            source_host,
            query,
            query_type,
            result,
            elapsed,
            speed,
        }
    }

    fn fmt_result(&self) -> String {
        if self.result.is_empty() {
            "query failed".to_string()
        } else {
            self.result
                .iter()
                .map(|record| {
                    format!(
                        "{}",
                        record
                            .data()
                            .map(|data| data.to_string())
                            .unwrap_or_default()
                    )
                })
                .collect::<Vec<_>>()
                .join(",")
        }
    }

    fn to_string_without_date(&self) -> String {
        format!(
            "{} query {}, type: {}, elapsed: {:?}, speed: {:?}, result {}",
            self.source_host,
            self.query,
            self.query_type,
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
            self.source_host,
            self.query,
            self.query_type,
            self.elapsed,
            self.speed,
            self.fmt_result()
        )
    }
}

fn record_audit_to_file<P: AsRef<Path>>(audit_file: P, audit_records: &[DnsAuditRecord]) {
    use std::fs;
    let audit_file = audit_file.as_ref();

    if let Some(dir) = audit_file.parent() {
        if !dir.exists() && fs::create_dir_all(dir).is_err() {
            return;
        }
    }

    if let Ok(file) = File::options().create(true).append(true).open(audit_file) {
        let mut writer = BufWriter::new(file);
        for audit in audit_records {
            if writeln!(writer, "{}", audit.to_string()).is_err() {
                warn!("Write audit to file '{:?}' failed", audit_file);
            }
        }
        if writer.flush().is_err() {
            warn!("Flush audit to file '{:?}' failed", audit_file);
        }
    }
}

#[cfg(test)]
mod tests {

    use std::io::Read;
    use std::str::FromStr;

    use trust_dns_client::rr::RData;

    use super::*;

    #[test]
    fn test_dns_audit_to_string() {
        let now = "2022-11-11 20:18:11.099966887 +08:00".parse().unwrap();

        let audit = DnsAuditRecord::new(
            now,
            "127.0.0.1".to_string(),
            Name::from_str("www.example.com").unwrap(),
            RecordType::A,
            vec![Record::from_rdata(
                Name::from_str("www.example.com").unwrap(),
                30,
                RData::A("93.184.216.34".parse().unwrap()),
            )],
            Duration::from_millis(10),
            Duration::from_millis(11),
        );

        assert_eq!(audit.to_string(), "[2022-11-11 20:18:11,099] 127.0.0.1 query www.example.com, type: A, elapsed: 10ms, speed: 11ms, result 93.184.216.34");
    }

    #[test]
    fn test_dns_audit_to_string_without_date() {
        let now = "2022-11-11 20:18:11.099966887 +08:00".parse().unwrap();

        let audit = DnsAuditRecord::new(
            now,
            "127.0.0.1".to_string(),
            Name::from_str("www.example.com").unwrap(),
            RecordType::A,
            vec![Record::from_rdata(
                Name::from_str("www.example.com").unwrap(),
                30,
                RData::A("93.184.216.34".parse().unwrap()),
            )],
            Duration::from_millis(10),
            Duration::from_millis(11),
        );

        assert_eq!(audit.to_string_without_date(), "127.0.0.1 query www.example.com, type: A, elapsed: 10ms, speed: 11ms, result 93.184.216.34");
    }

    #[test]
    fn test_record_audit_to_file() {
        let audit = DnsAuditRecord::new(
            "2022-11-11 20:18:11.099966887 +08:00".parse().unwrap(),
            "127.0.0.1".to_string(),
            Name::from_str("www.example.com").unwrap(),
            RecordType::A,
            vec![Record::from_rdata(
                Name::from_str("www.example.com").unwrap(),
                30,
                RData::A("93.184.216.34".parse().unwrap()),
            )],
            Duration::from_millis(10),
            Duration::from_millis(11),
        );

        let file = format!("./logs/test-{}-audit.log", Local::now().timestamp_millis());
        let file = Path::new(file.as_str());

        record_audit_to_file(file, &[audit]);

        assert!(file.exists());

        let mut s = String::new();

        std::fs::File::open(file)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();

        assert_eq!(s, "[2022-11-11 20:18:11,099] 127.0.0.1 query www.example.com, type: A, elapsed: 10ms, speed: 11ms, result 93.184.216.34\n");

        std::fs::remove_file(file).unwrap();

        assert!(!file.exists());
    }
}
