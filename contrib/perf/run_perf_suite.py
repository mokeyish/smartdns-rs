#!/usr/bin/env python3
"""
SmartDNS performance suite.

This script runs scenario-based UDP DNS load tests and exports:
1) machine-readable JSON
2) human-readable Markdown summary

All scenarios are local and deterministic (no external DNS dependency).
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import random
import signal
import socket
import statistics
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable, Iterable


DNS_TYPE_A = 1
DNS_CLASS_IN = 1


def encode_qname(name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    parts = []
    for label in labels:
        raw = label.encode("utf-8")
        if len(raw) > 63:
            raise ValueError(f"label too long: {label}")
        parts.append(bytes([len(raw)]))
        parts.append(raw)
    parts.append(b"\x00")
    return b"".join(parts)


def build_dns_query(name: str, qtype: int, query_id: int) -> bytes:
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = encode_qname(name) + struct.pack("!HH", qtype, DNS_CLASS_IN)
    return header + question


def parse_question_end_offset(data: bytes) -> int:
    if len(data) < 12:
        raise ValueError("packet too short")
    offset = 12
    while offset < len(data):
        length = data[offset]
        offset += 1
        if length == 0:
            break
        offset += length
    if offset + 4 > len(data):
        raise ValueError("question section truncated")
    return offset + 4


def build_fake_upstream_a_response(request: bytes, ipv4: str) -> bytes | None:
    if len(request) < 12:
        return None
    query_id = request[0:2]
    try:
        question_end = parse_question_end_offset(request)
    except ValueError:
        return None
    question = request[12:question_end]
    flags = 0x8180  # standard query response, recursion available, no error
    header = query_id + struct.pack("!HHHHH", flags, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", DNS_TYPE_A, DNS_CLASS_IN, 60, 4) + socket.inet_aton(ipv4)
    return header + question + answer


class FakeUpstreamServer:
    def __init__(self, ip: str = "127.0.0.1", port: int = 0, response_ip: str = "7.7.7.7"):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((ip, port))
        self._sock.settimeout(0.2)
        self.address = self._sock.getsockname()
        self.response_ip = response_ip
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=1.0)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                return
            response = build_fake_upstream_a_response(data, self.response_ip)
            if response is None:
                continue
            try:
                self._sock.sendto(response, addr)
            except OSError:
                return


@dataclasses.dataclass
class LoadMetrics:
    duration_sec: float
    sent: int
    succeeded: int
    failed: int
    timeouts: int
    qps: float
    latency_ms_p50: float
    latency_ms_p95: float
    latency_ms_p99: float
    latency_ms_avg: float
    success_rate: float


@dataclasses.dataclass
class ScenarioResult:
    name: str
    description: str
    covered_items: list[str]
    metrics: LoadMetrics
    notes: list[str]
    runs: list[LoadMetrics]


def percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    rank = (len(sorted_vals) - 1) * p
    low = int(rank)
    high = min(low + 1, len(sorted_vals) - 1)
    frac = rank - low
    return sorted_vals[low] * (1 - frac) + sorted_vals[high] * frac


def median_float(values: list[float]) -> float:
    if not values:
        return 0.0
    return statistics.median(values)


def aggregate_metrics(runs: list[LoadMetrics]) -> LoadMetrics:
    if not runs:
        raise ValueError("no metrics to aggregate")
    return LoadMetrics(
        duration_sec=statistics.fmean(m.duration_sec for m in runs),
        sent=int(round(statistics.fmean(m.sent for m in runs))),
        succeeded=int(round(statistics.fmean(m.succeeded for m in runs))),
        failed=int(round(statistics.fmean(m.failed for m in runs))),
        timeouts=int(round(statistics.fmean(m.timeouts for m in runs))),
        qps=median_float([m.qps for m in runs]),
        latency_ms_p50=median_float([m.latency_ms_p50 for m in runs]),
        latency_ms_p95=median_float([m.latency_ms_p95 for m in runs]),
        latency_ms_p99=median_float([m.latency_ms_p99 for m in runs]),
        latency_ms_avg=median_float([m.latency_ms_avg for m in runs]),
        success_rate=median_float([m.success_rate for m in runs]),
    )


def run_scenario_repeated(run: Callable[[], ScenarioResult], repeats: int) -> ScenarioResult:
    if repeats <= 0:
        raise ValueError("repeats must be > 0")
    results = [run() for _ in range(repeats)]
    first = results[0]
    run_metrics = [r.metrics for r in results]
    aggregate = aggregate_metrics(run_metrics)
    notes = list(first.notes)
    notes.append(f"repeats: {repeats}")
    notes.append("qps per run: " + ", ".join(f"{m.qps:.1f}" for m in run_metrics))
    return ScenarioResult(
        name=first.name,
        description=first.description,
        covered_items=first.covered_items,
        metrics=aggregate,
        notes=notes,
        runs=run_metrics,
    )


def run_udp_load(
    host: str,
    port: int,
    qname: str,
    duration_sec: float,
    concurrency: int,
    timeout_ms: int,
) -> LoadMetrics:
    if concurrency <= 0:
        raise ValueError("concurrency must be > 0")
    timeout_sec = timeout_ms / 1000.0
    end_at = time.perf_counter() + duration_sec
    qname = qname.rstrip(".") + "."

    per_thread = []
    lock = threading.Lock()

    def worker(seed: int) -> None:
        rnd = random.Random(seed)
        latencies = []
        sent = succeeded = failed = timeouts = 0
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout_sec)
        try:
            while time.perf_counter() < end_at:
                query_id = rnd.randint(0, 65535)
                packet = build_dns_query(qname, DNS_TYPE_A, query_id)
                sent += 1
                start = time.perf_counter_ns()
                try:
                    sock.sendto(packet, (host, port))
                    response, _ = sock.recvfrom(4096)
                    if len(response) < 2 or response[0:2] != packet[0:2]:
                        failed += 1
                        continue
                    elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000.0
                    latencies.append(elapsed_ms)
                    succeeded += 1
                except socket.timeout:
                    failed += 1
                    timeouts += 1
                except OSError:
                    failed += 1
        finally:
            sock.close()
            with lock:
                per_thread.append((sent, succeeded, failed, timeouts, latencies))

    threads = [threading.Thread(target=worker, args=(1000 + i,), daemon=True) for i in range(concurrency)]
    start_wall = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed_wall = max(time.perf_counter() - start_wall, 0.001)

    sent = sum(x[0] for x in per_thread)
    succeeded = sum(x[1] for x in per_thread)
    failed = sum(x[2] for x in per_thread)
    timeouts = sum(x[3] for x in per_thread)
    latencies = [ms for x in per_thread for ms in x[4]]
    latencies.sort()

    return LoadMetrics(
        duration_sec=elapsed_wall,
        sent=sent,
        succeeded=succeeded,
        failed=failed,
        timeouts=timeouts,
        qps=succeeded / elapsed_wall,
        latency_ms_p50=percentile(latencies, 0.50),
        latency_ms_p95=percentile(latencies, 0.95),
        latency_ms_p99=percentile(latencies, 0.99),
        latency_ms_avg=(statistics.fmean(latencies) if latencies else 0.0),
        success_rate=(succeeded / sent if sent else 0.0),
    )


def single_udp_query(host: str, port: int, qname: str, timeout_sec: float = 0.5) -> bool:
    query_id = random.randint(0, 65535)
    packet = build_dns_query(qname.rstrip(".") + ".", DNS_TYPE_A, query_id)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_sec)
    try:
        sock.sendto(packet, (host, port))
        response, _ = sock.recvfrom(4096)
        return len(response) >= 2 and response[0:2] == packet[0:2]
    except OSError:
        return False
    finally:
        sock.close()


def warmup_ready(host: str, port: int, qname: str, timeout_sec: float = 15.0) -> None:
    deadline = time.perf_counter() + timeout_sec
    while time.perf_counter() < deadline:
        if single_udp_query(host, port, qname, timeout_sec=0.4):
            return
        time.sleep(0.1)
    raise RuntimeError(f"smartdns not ready on {host}:{port} within {timeout_sec}s")


def write_config(path: Path, lines: Iterable[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def start_smartdns(binary: Path, config: Path) -> subprocess.Popen:
    return subprocess.Popen(
        [str(binary), "run", "-c", str(config)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=os.environ.copy(),
    )


def stop_process(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def scenario_static_address(
    binary: Path,
    duration: float,
    concurrency: int,
    timeout_ms: int,
) -> ScenarioResult:
    with tempfile.TemporaryDirectory(prefix="smartdns-perf-static-") as tmp:
        tmpdir = Path(tmp)
        port = random.randint(20000, 26000)
        qname = "bench-static.perf"
        conf = tmpdir / "smartdns.conf"
        write_config(
            conf,
            [
                f"bind 127.0.0.1:{port}",
                "log-num 0",
                "cache-size 0",
                "address /bench-static.perf/1.2.3.4",
            ],
        )

        proc = start_smartdns(binary, conf)
        try:
            warmup_ready("127.0.0.1", port, qname)
            metrics = run_udp_load("127.0.0.1", port, qname, duration, concurrency, timeout_ms)
        finally:
            stop_process(proc)

    return ScenarioResult(
        name="static_address_rule",
        description="AddressMiddleware static rule resolution throughput",
        covered_items=["AddressMiddleware static rule path", "server UDP request/response hot path"],
        metrics=metrics,
        notes=["No upstream dependency", "Cache disabled"],
        runs=[metrics],
    )


def scenario_dnsmasq_lease_cache(
    binary: Path,
    duration: float,
    concurrency: int,
    timeout_ms: int,
    lease_records: int,
) -> ScenarioResult:
    with tempfile.TemporaryDirectory(prefix="smartdns-perf-dnsmasq-") as tmp:
        tmpdir = Path(tmp)
        port = random.randint(26001, 32000)
        qname = "host-perf.perf.lan"
        lease = tmpdir / "dhcp.leases"
        expires_at = int(time.time()) + 86400
        total_records = max(1, lease_records)
        rows = []
        for i in range(total_records - 1):
            host = f"host-{i}"
            ip = f"192.168.{(i // 250) % 200}.{(i % 250) + 1}"
            rows.append(
                f"{expires_at} aa:bb:cc:dd:{i // 256:02x}:{i % 256:02x} {ip} {host} 01:aa:bb:cc:dd:00:01"
            )
        rows.append(
            f"{expires_at} aa:bb:cc:dd:ee:ff 192.168.100.16 host-perf 01:aa:bb:cc:dd:ee:ff"
        )
        lease.write_text("\n".join(rows) + "\n", encoding="utf-8")

        conf = tmpdir / "smartdns.conf"
        write_config(
            conf,
            [
                f"bind 127.0.0.1:{port}",
                "log-num 0",
                "cache-size 0",
                f"dnsmasq-lease-file {lease}",
                "domain perf.lan",
            ],
        )

        proc = start_smartdns(binary, conf)
        try:
            warmup_ready("127.0.0.1", port, qname)
            metrics = run_udp_load("127.0.0.1", port, qname, duration, concurrency, timeout_ms)
        finally:
            stop_process(proc)

    return ScenarioResult(
        name="dnsmasq_lease_lookup",
        description="DnsmasqMiddleware and lease-file in-memory cache",
        covered_items=["DnsmasqMiddleware lookup", "LanClientStore file mtime cache optimization"],
        metrics=metrics,
        notes=["No upstream dependency", "Cache disabled", f"lease records: {total_records}"],
        runs=[metrics],
    )


def scenario_cache_hit(
    binary: Path,
    duration: float,
    concurrency: int,
    timeout_ms: int,
) -> ScenarioResult:
    with tempfile.TemporaryDirectory(prefix="smartdns-perf-cachehit-") as tmp:
        tmpdir = Path(tmp)
        port = random.randint(32001, 38000)
        qname = "cache-hit.perf"
        upstream = FakeUpstreamServer(response_ip="9.9.9.9")
        upstream.start()
        try:
            conf = tmpdir / "smartdns.conf"
            write_config(
                conf,
                [
                    f"bind 127.0.0.1:{port}",
                    "log-num 0",
                    "cache-size 8192",
                    "prefetch-domain no",
                    f"server 127.0.0.1:{upstream.address[1]}",
                ],
            )
            proc = start_smartdns(binary, conf)
            try:
                warmup_ready("127.0.0.1", port, qname)
                for _ in range(20):
                    single_udp_query("127.0.0.1", port, qname, timeout_sec=0.3)
                metrics = run_udp_load("127.0.0.1", port, qname, duration, concurrency, timeout_ms)
            finally:
                stop_process(proc)
        finally:
            upstream.stop()

    return ScenarioResult(
        name="dns_cache_hit_path",
        description="DnsCacheMiddleware hit path with local fake upstream",
        covered_items=["DnsCacheMiddleware insert/get", "cache hit fast path", "DnsHandle bounded queue path"],
        metrics=metrics,
        notes=["Local fake upstream", "Cache enabled"],
        runs=[metrics],
    )


def scenario_prefetch_scheduler(
    binary: Path,
    duration: float,
    concurrency: int,
    timeout_ms: int,
    prefill_domains: int,
) -> ScenarioResult:
    with tempfile.TemporaryDirectory(prefix="smartdns-perf-prefetch-") as tmp:
        tmpdir = Path(tmp)
        port = random.randint(38001, 44000)
        hot_qname = "prefetch-hot.perf"
        upstream = FakeUpstreamServer(response_ip="8.8.4.4")
        upstream.start()
        try:
            conf = tmpdir / "smartdns.conf"
            write_config(
                conf,
                [
                    f"bind 127.0.0.1:{port}",
                    "log-num 0",
                    "cache-size 65535",
                    "prefetch-domain yes",
                    f"server 127.0.0.1:{upstream.address[1]}",
                ],
            )
            proc = start_smartdns(binary, conf)
            try:
                warmup_ready("127.0.0.1", port, hot_qname)
                for i in range(prefill_domains):
                    single_udp_query("127.0.0.1", port, f"prefetch-{i}.perf", timeout_sec=0.2)
                for _ in range(10):
                    single_udp_query("127.0.0.1", port, hot_qname, timeout_sec=0.3)
                time.sleep(0.6)
                metrics = run_udp_load("127.0.0.1", port, hot_qname, duration, concurrency, timeout_ms)
            finally:
                stop_process(proc)
        finally:
            upstream.stop()

    return ScenarioResult(
        name="prefetch_scheduler_active",
        description="Prefetch scheduler under large cache set",
        covered_items=["cache prefetch scheduler index", "prefetch trigger pipeline", "cache + background query coexistence"],
        metrics=metrics,
        notes=[f"Prefill domains: {prefill_domains}", "Prefetch enabled"],
        runs=[metrics],
    )


def to_jsonable(results: list[ScenarioResult]) -> dict:
    return {
        "generated_at_unix": int(time.time()),
        "scenario_count": len(results),
        "scenarios": [
            {
                "name": r.name,
                "description": r.description,
                "covered_items": r.covered_items,
                "notes": r.notes,
                "metrics": dataclasses.asdict(r.metrics),
                "runs": [dataclasses.asdict(run) for run in r.runs],
            }
            for r in results
        ],
    }


def build_markdown(results: list[ScenarioResult], binary: Path) -> str:
    lines = []
    lines.append("# SmartDNS Performance Summary")
    lines.append("")
    lines.append(f"- Binary: `{binary}`")
    lines.append(f"- Generated at: `{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}`")
    lines.append("")
    lines.append("## Scenario Metrics")
    lines.append("")
    lines.append("| Scenario | Covered item(s) | QPS | Success | p50 (ms) | p95 (ms) | p99 (ms) | Avg (ms) |")
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|")
    for r in results:
        m = r.metrics
        covered = "<br/>".join(r.covered_items)
        lines.append(
            f"| `{r.name}` | {covered} | {m.qps:.1f} | {m.success_rate * 100:.2f}% | "
            f"{m.latency_ms_p50:.3f} | {m.latency_ms_p95:.3f} | {m.latency_ms_p99:.3f} | {m.latency_ms_avg:.3f} |"
        )
    lines.append("")
    lines.append("## Scenario Notes")
    lines.append("")
    for r in results:
        lines.append(f"### {r.name}")
        lines.append(f"- Description: {r.description}")
        if len(r.runs) > 1:
            lines.append("- Run metrics (QPS): " + ", ".join(f"{run.qps:.1f}" for run in r.runs))
        for note in r.notes:
            lines.append(f"- {note}")
        lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run SmartDNS performance suite")
    parser.add_argument("--binary", required=True, help="Path to smartdns binary")
    parser.add_argument("--duration-sec", type=float, default=8.0, help="Per scenario load duration")
    parser.add_argument("--concurrency", type=int, default=64, help="Per scenario load concurrency")
    parser.add_argument("--timeout-ms", type=int, default=500, help="DNS query timeout in milliseconds")
    parser.add_argument("--prefill-domains", type=int, default=3000, help="Prefill domain count for prefetch scenario")
    parser.add_argument("--lease-records", type=int, default=2000, help="Lease records count for dnsmasq scenario")
    parser.add_argument("--repeats", type=int, default=1, help="Repeat each scenario and use median metrics")
    parser.add_argument("--output-json", required=True, help="Output JSON path")
    parser.add_argument("--output-md", required=True, help="Output markdown summary path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    binary = Path(args.binary).resolve()
    if not binary.is_file():
        raise FileNotFoundError(f"binary not found: {binary}")

    scenarios: list[Callable[[], ScenarioResult]] = [
        lambda: scenario_static_address(binary, args.duration_sec, args.concurrency, args.timeout_ms),
        lambda: scenario_dnsmasq_lease_cache(
            binary,
            args.duration_sec,
            args.concurrency,
            args.timeout_ms,
            args.lease_records,
        ),
        lambda: scenario_cache_hit(binary, args.duration_sec, args.concurrency, args.timeout_ms),
        lambda: scenario_prefetch_scheduler(
            binary,
            args.duration_sec,
            args.concurrency,
            args.timeout_ms,
            args.prefill_domains,
        ),
    ]

    results = []
    for run in scenarios:
        results.append(run_scenario_repeated(run, args.repeats))

    out_json = Path(args.output_json)
    out_md = Path(args.output_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(to_jsonable(results), indent=2), encoding="utf-8")
    out_md.write_text(build_markdown(results, binary), encoding="utf-8")
    print(out_md.read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
