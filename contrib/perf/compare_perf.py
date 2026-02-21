#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_results(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def pct_change(base: float, target: float) -> float:
    if base == 0:
        return 0.0
    return ((target - base) / base) * 100.0


def fmt_pct(delta: float, higher_is_better: bool) -> str:
    if higher_is_better:
        mark = "better" if delta >= 0 else "worse"
    else:
        mark = "better" if delta <= 0 else "worse"
    sign = "+" if delta >= 0 else ""
    return f"{sign}{delta:.2f}% ({mark})"


def build_markdown(base_name: str, target_name: str, base: dict, target: dict) -> str:
    base_map = {s["name"]: s for s in base.get("scenarios", [])}
    target_map = {s["name"]: s for s in target.get("scenarios", [])}
    scenario_names = sorted(set(base_map.keys()) & set(target_map.keys()))

    lines = []
    lines.append("# SmartDNS Performance Comparison")
    lines.append("")
    lines.append(f"- Baseline: **{base_name}**")
    lines.append(f"- Target: **{target_name}**")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(
        "| Scenario | QPS base | QPS target | QPS delta | p95 base (ms) | p95 target (ms) | p95 delta | p99 base (ms) | p99 target (ms) | p99 delta |"
    )
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")

    for name in scenario_names:
        b = base_map[name]["metrics"]
        t = target_map[name]["metrics"]
        qps_delta = pct_change(b["qps"], t["qps"])
        p95_delta = pct_change(b["latency_ms_p95"], t["latency_ms_p95"])
        p99_delta = pct_change(b["latency_ms_p99"], t["latency_ms_p99"])
        lines.append(
            f"| `{name}` | {b['qps']:.1f} | {t['qps']:.1f} | {fmt_pct(qps_delta, True)} | "
            f"{b['latency_ms_p95']:.3f} | {t['latency_ms_p95']:.3f} | {fmt_pct(p95_delta, False)} | "
            f"{b['latency_ms_p99']:.3f} | {t['latency_ms_p99']:.3f} | {fmt_pct(p99_delta, False)} |"
        )

    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- QPS: higher is better")
    lines.append("- p95/p99 latency: lower is better")
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare two SmartDNS perf JSON files")
    parser.add_argument("--base", required=True, help="Baseline results.json path")
    parser.add_argument("--target", required=True, help="Target results.json path")
    parser.add_argument("--base-name", default="main", help="Baseline label")
    parser.add_argument("--target-name", default="current", help="Target label")
    parser.add_argument("--output-md", required=True, help="Output markdown path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    base = load_results(Path(args.base))
    target = load_results(Path(args.target))
    md = build_markdown(args.base_name, args.target_name, base, target)
    output = Path(args.output_md)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
