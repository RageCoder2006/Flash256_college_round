# Monitoring: the Status page, metrics, Prometheus and Grafana

## Status page (`/console`, the first page after sign-in)
Live over server-sent events (`GET /api/status/stream`, a snapshot every `refresh_sec`, default 2 s) with 15 minutes of history preloaded
(`GET /api/status/history`); the API keeps 30 minutes in memory. Everything is read from this machine, no agent, no root:

| Panel | Source |
|---|---|
| CPU total and per core, load 1/5/15, frequency, model | `/proc/stat`, `/proc/loadavg`, `/proc/cpuinfo` |
| RAM (used, cache, free), **swap**, dirty pages | `/proc/meminfo` (used = total - available) |
| Pressure stall (CPU, memory, IO) | `/proc/pressure/*` (PSI), when the kernel has it |
| Disk usage (system and the runs directory), disk I/O | `statfs`, `/proc/diskstats` (whole disks only) |
| Network rx/tx | `/proc/net/dev`, loopback excluded |
| Temperatures | `/sys/class/thermal`, hwmon (absent in many VMs) |
| **Sandbox resource usage** | the current run's process subtree: CPU, memory, threads, process count, top processes, beside the configured limits |
| Containers | `docker stats` for gVisor episode containers and the Neo4j/Qdrant stack |
| Environment health | API, guard (mode, latency), Neo4j, Qdrant, model endpoint (latency), Landlock, gVisor, Chrome, signing key (private and public key must match), audit-log chain, intel cache |
| Run activity | current run, elapsed, episodes and exploit counts, live log tail, **Cancel** for operators |

Honest limits: Linux only (elsewhere the page says so); it monitors the machine the API runs on, not remote hosts; per-process CPU is of one core
(like `top`); **Landlock does not limit memory** for command-line agents, and the page says "no memory limit" rather than implying a ceiling;
process names are shown, never command lines.

## Metrics endpoint
`GET /metrics` (Prometheus text format, bearer token like every route) exposes `avhsol_host_*` (cpu, load, memory, swap, disk, network, pressure,
temperature), `avhsol_process_*`, `avhsol_sandbox_*`, `avhsol_container_*`, `avhsol_runs_active`, `avhsol_episodes_total{outcome}`,
`avhsol_guard_decisions_total{decision}`, `avhsol_guard_decision_latency_microseconds{quantile}`, `avhsol_intel_items`.

## Prometheus and Grafana (optional)
```
scripts/stack.sh up --observability          # adds Prometheus 127.0.0.1:9090 and Grafana 127.0.0.1:3001
AVHSOL_GRAFANA_URL=http://127.0.0.1:3001 avhsol serve ...     # shows "Open Grafana" on the Status page
```
Both run on the host network (to reach the loopback-only API), bind to 127.0.0.1, run as your user with all capabilities dropped,
`no-new-privileges`, and a read-only root, with images pinned by digest. Prometheus scrapes with a **viewer-role** token written to
`deploy/stack/prometheus/token` (mode 600, git-ignored); Grafana's admin password is generated into `deploy/stack/.env`. Grafana provisions the
Prometheus data source and an **AVHSOL overview** dashboard from `deploy/stack/grafana/`. Prometheus keeps 15 days. The Status page works without any of this.
