# SmartDNS Performance Suite

This directory contains a scenario-based performance suite that targets specific runtime paths.

## Scenarios and covered functionality

| Scenario | Covered functionality |
|---|---|
| `static_address_rule` | `AddressMiddleware` static response path, local UDP server path |
| `hosts_file_lookup` | `DnsHostsMiddleware` hosts-file lookup path, hosts file mtime/signature cache |
| `dnsmasq_lease_lookup` | `DnsmasqMiddleware` path, `LanClientStore` lease-file mtime cache |
| `dns_cache_hit_path` | `DnsCacheMiddleware` insert/get + cache-hit path + bounded `DnsHandle` queue |
| `prefetch_scheduler_active` | cache prefetch scheduling/index path with large cached domain set |

## Local run

```bash
just build --release --features disable_icmp_ping

python3 contrib/perf/run_perf_suite.py \
  --binary target/release/smartdns \
  --duration-sec 8 \
  --concurrency 64 \
  --timeout-ms 500 \
  --hosts-records 12000 \
  --lease-records 2000 \
  --prefill-domains 3000 \
  --repeats 1 \
  --output-json artifacts/perf/results.json \
  --output-md artifacts/perf/summary.md
```

The script prints the Markdown summary to stdout and writes:

- JSON metrics: `artifacts/perf/results.json`
- Markdown summary: `artifacts/perf/summary.md`

Useful knobs:

- `--hosts-records`: scales hosts-file size for `DnsHostsMiddleware` cache-path sensitivity
- `--lease-records`: scales dnsmasq lease-file size for cache-path sensitivity
- `--prefill-domains`: scales cached-domain count for prefetch scheduler pressure
- `--repeats`: repeats each scenario and uses median values to reduce run-to-run noise

## Compare two branches (or binaries)

```bash
python3 contrib/perf/compare_perf.py \
  --base artifacts/perf/main.json \
  --target artifacts/perf/current.json \
  --base-name main \
  --target-name current \
  --output-md artifacts/perf/compare.md
```

## CI output

The GitHub workflow `.github/workflows/perf.yml` runs this suite and publishes:

1. Job Summary table (QPS, success rate, p50/p95/p99, avg latency)
2. Uploaded artifact containing both JSON and Markdown outputs
