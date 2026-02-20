# SmartDNS Performance Suite

This directory contains a scenario-based performance suite that targets specific runtime paths.

## Scenarios and covered functionality

| Scenario | Covered functionality |
|---|---|
| `static_address_rule` | `AddressMiddleware` static response path, local UDP server path |
| `dnsmasq_lease_lookup` | `DnsmasqMiddleware` path, `LanClientStore` lease-file mtime cache |
| `dns_cache_hit_path` | `DnsCacheMiddleware` insert/get + cache-hit path + bounded `DnsHandle` queue |
| `prefetch_scheduler_active` | cache prefetch scheduling/index path with large cached domain set |

## Local run

```bash
cargo build --release --no-default-features --features disable_icmp_ping

python3 contrib/perf/run_perf_suite.py \
  --binary target/release/smartdns \
  --duration-sec 8 \
  --concurrency 64 \
  --timeout-ms 500 \
  --prefill-domains 3000 \
  --output-json artifacts/perf/results.json \
  --output-md artifacts/perf/summary.md
```

The script prints the Markdown summary to stdout and writes:

- JSON metrics: `artifacts/perf/results.json`
- Markdown summary: `artifacts/perf/summary.md`

## CI output

The GitHub workflow `.github/workflows/perf.yml` runs this suite and publishes:

1. Job Summary table (QPS, success rate, p50/p95/p99, avg latency)
2. Uploaded artifact containing both JSON and Markdown outputs
