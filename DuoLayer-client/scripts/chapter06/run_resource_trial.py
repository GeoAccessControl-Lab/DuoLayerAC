#!/usr/bin/env python3
"""Measure one fixed-rate decision batch with cgroup-v2 accounting."""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import subprocess
import time
from pathlib import Path


class ContainerCgroup:
    def __init__(self, name: str) -> None:
        self.name = name
        pid = subprocess.check_output(
            ["docker", "inspect", "-f", "{{.State.Pid}}", name], text=True
        ).strip()
        cgroup_lines = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
        unified = next((line.split("::", 1)[1] for line in cgroup_lines if line.startswith("0::")), None)
        if unified is None:
            raise RuntimeError(f"container {name} is not attached to cgroup v2")
        self.root = Path("/sys/fs/cgroup") / unified.lstrip("/")
        if not (self.root / "cpu.stat").exists() or not (self.root / "memory.current").exists():
            raise RuntimeError(f"missing resource counters for {name}: {self.root}")

    def read(self) -> tuple[int, int]:
        cpu_fields = {}
        for line in (self.root / "cpu.stat").read_text().splitlines():
            key, value = line.split()
            cpu_fields[key] = int(value)
        return cpu_fields["usage_usec"], int((self.root / "memory.current").read_text().strip())


def snapshot(readers: list[ContainerCgroup]) -> tuple[int, int, dict[str, int]]:
    total_cpu = 0
    total_memory = 0
    memory_by_container = {}
    for reader in readers:
        cpu, memory = reader.read()
        total_cpu += cpu
        total_memory += memory
        memory_by_container[reader.name] = memory
    return total_cpu, total_memory, memory_by_container


def sample_for(
    readers: list[ContainerCgroup], duration: float, interval: float, phase: str, origin: float
) -> list[dict[str, object]]:
    records = []
    deadline = time.monotonic() + duration
    while True:
        now = time.monotonic()
        cpu, memory, by_container = snapshot(readers)
        records.append(
            {
                "phase": phase,
                "elapsed_s": now - origin,
                "cpu_usage_usec": cpu,
                "memory_bytes": memory,
                "memory_by_container": by_container,
            }
        )
        if now >= deadline:
            break
        time.sleep(min(interval, max(0.0, deadline - now)))
    return records


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--method", required=True)
    parser.add_argument("--trial", type=int, required=True)
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--rate", type=float, default=20.0)
    parser.add_argument("--containers", nargs="+", required=True)
    parser.add_argument("--signal-container", required=True)
    parser.add_argument("--ready-file", required=True)
    parser.add_argument("--start-file", required=True)
    parser.add_argument("--baseline-seconds", type=float, default=5.0)
    parser.add_argument("--sample-interval", type=float, default=0.1)
    parser.add_argument("--ready-timeout", type=float, default=180.0)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--samples-csv", type=Path, required=True)
    parser.add_argument("--command-output", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command and args.command[0] == "--" else args.command
    if not command:
        raise SystemExit("a benchmark command is required after --")

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.samples_csv.parent.mkdir(parents=True, exist_ok=True)
    args.command_output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["docker", "exec", args.signal_container, "rm", "-f", args.ready_file, args.start_file],
        check=True,
    )
    readers = [ContainerCgroup(name) for name in args.containers]
    origin = time.monotonic()
    samples = sample_for(readers, args.baseline_seconds, args.sample_interval, "prelaunch", origin)

    with args.command_output.open("w") as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, text=True)
        ready_deadline = time.monotonic() + args.ready_timeout
        while time.monotonic() < ready_deadline:
            if process.poll() is not None:
                raise RuntimeError(f"benchmark exited before readiness with status {process.returncode}")
            ready = subprocess.run(
                ["docker", "exec", args.signal_container, "test", "-f", args.ready_file],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if ready.returncode == 0:
                break
            time.sleep(0.1)
        else:
            process.terminate()
            raise RuntimeError("benchmark readiness timed out")

        samples.extend(sample_for(readers, args.baseline_seconds, args.sample_interval, "resident_idle", origin))
        active_started = time.monotonic()
        active_first = snapshot(readers)
        subprocess.run(["docker", "exec", args.signal_container, "touch", args.start_file], check=True)
        while process.poll() is None:
            now = time.monotonic()
            cpu, memory, by_container = snapshot(readers)
            samples.append(
                {
                    "phase": "active",
                    "elapsed_s": now - origin,
                    "cpu_usage_usec": cpu,
                    "memory_bytes": memory,
                    "memory_by_container": by_container,
                }
            )
            time.sleep(args.sample_interval)
        active_last = snapshot(readers)
        active_ended = time.monotonic()
        samples.append(
            {
                "phase": "active",
                "elapsed_s": active_ended - origin,
                "cpu_usage_usec": active_last[0],
                "memory_bytes": active_last[1],
                "memory_by_container": active_last[2],
            }
        )
        if process.returncode != 0:
            raise RuntimeError(f"benchmark failed with status {process.returncode}")

    prelaunch = [row for row in samples if row["phase"] == "prelaunch"]
    resident = [row for row in samples if row["phase"] == "resident_idle"]
    active = [row for row in samples if row["phase"] == "active"]
    idle_elapsed = resident[-1]["elapsed_s"] - resident[0]["elapsed_s"]
    idle_cpu_usec = resident[-1]["cpu_usage_usec"] - resident[0]["cpu_usage_usec"]
    idle_cpu_usec_per_s = idle_cpu_usec / idle_elapsed if idle_elapsed > 0 else 0.0
    active_elapsed = active_ended - active_started
    active_cpu_usec = active_last[0] - active_first[0]
    expected_idle_cpu_usec = idle_cpu_usec_per_s * active_elapsed
    net_cpu_usec = max(0.0, active_cpu_usec - expected_idle_cpu_usec)
    prelaunch_memory = statistics.median(float(row["memory_bytes"]) for row in prelaunch)
    resident_memory = statistics.median(float(row["memory_bytes"]) for row in resident)
    active_peak_memory = max(float(row["memory_bytes"]) for row in active)

    result = {
        "method": args.method,
        "trial": args.trial,
        "requests": args.requests,
        "rate_per_second": args.rate,
        "containers": args.containers,
        "active_wall_seconds": active_elapsed,
        "active_cpu_total_ms": active_cpu_usec / 1000.0,
        "idle_adjusted_cpu_total_ms": net_cpu_usec / 1000.0,
        "cpu_ms_per_request": net_cpu_usec / 1000.0 / args.requests,
        "equivalent_single_core_cpu_pct": net_cpu_usec / 1_000_000.0 / active_elapsed * 100.0,
        "prelaunch_memory_mb": prelaunch_memory / 1_000_000.0,
        "resident_idle_memory_mb": resident_memory / 1_000_000.0,
        "resident_increment_mb": max(0.0, resident_memory - prelaunch_memory) / 1_000_000.0,
        "active_peak_memory_mb": active_peak_memory / 1_000_000.0,
        "active_peak_increment_mb": max(0.0, active_peak_memory - resident_memory) / 1_000_000.0,
        "service_peak_increment_mb": max(0.0, active_peak_memory - prelaunch_memory) / 1_000_000.0,
        "command_output": str(args.command_output),
    }
    args.output_json.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")

    container_columns = [f"memory_{name}_bytes" for name in args.containers]
    with args.samples_csv.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["phase", "elapsed_s", "cpu_usage_usec", "memory_bytes", *container_columns])
        for row in samples:
            writer.writerow(
                [
                    row["phase"],
                    f"{float(row['elapsed_s']):.9f}",
                    row["cpu_usage_usec"],
                    row["memory_bytes"],
                    *[row["memory_by_container"].get(name, "") for name in args.containers],
                ]
            )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
