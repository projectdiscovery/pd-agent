# Scaling pd-agent

When a single pd-agent cannot keep up with inbound work, this guide tells you which metric to watch and how to scale your deployment up or down.

Every running agent exposes a Prometheus endpoint on `:9090/metrics` (or whatever you set via `PDCP_METRICS_ADDR`). Off by default, opt-in with the env var.

## Why scale

pd-agent runs scans and discovery jobs in chunks. One agent processes a fixed number of chunks in parallel (`PDCP_CHUNK_PARALLELISM`, auto-detected by default). When the inbound queue is faster than your single agent can drain, the only fix is more agents. There is no per-agent option that helps once you've maxed out CPU on one box.

Adding more agents (pods, VMs, whatever) with the same configuration causes them to fan in on the same scans automatically. Two agents draining the same scan finish in roughly half the time. No leader, no shard map: just more agents pull from the same queue.

## Metrics reference

All metrics are prefixed `pdagent_group_*` because they describe the group of agents collectively, not the single pod that exposes them. Every agent in the same group reports the same numbers (within a small skew from independent collection caches).

| Metric | Type | What it means |
|---|---|---|
| `pdagent_group_chunks_pending` | gauge | Chunks sitting in the queue, not yet picked up by any agent. **The primary scale signal.** |
| `pdagent_group_chunks_inflight` | gauge | Chunks currently being processed (delivered to an agent, not yet finished). Useful for true total backlog: `pending + inflight`. |
| `pdagent_group_active_scans` | gauge | Number of distinct scans the group is currently working on. |
| `pdagent_group_work_pending` | gauge | Scans that have been published but no agent has yet started them. Same value across all agents. |
| `pdagent_group_oldest_consumer_age_seconds` | gauge | Age of the oldest active scan. A growing value while `chunks_inflight` is flat suggests a stuck agent or a very slow scan. |
| `pdagent_group_collection_duration_milliseconds` | gauge | How long the last metric collection took. Watch for this growing if you have very many concurrent scans. |
| `pdagent_group_collection_errors_total` | counter | Cumulative collection failures. Should be near zero in healthy operation. |

## What to look for

**Scale up when:**
- `chunks_pending` is consistently above your threshold for several minutes.
- `chunks_inflight` is at or near `agents × chunk_parallelism` (you're saturated, can't go faster without more agents).

**Scale down when:**
- `chunks_pending` is zero AND `chunks_inflight` is zero for several minutes.
- Total backlog `pending + inflight` is well below capacity (`agents × chunk_parallelism`).

**Investigate, don't scale, when:**
- `chunks_pending` is zero but `oldest_consumer_age_seconds` keeps growing. A scan is stuck; more agents won't help.
- `collection_errors_total` is increasing. Metric collection itself is failing; trust the values less until it stabilizes.
- `chunks_pending` is non-zero but `chunks_inflight` is also zero for a long stretch. Agents may be unhealthy. Check agent logs first.

## Querying with PromQL

Every pod reports the same numbers, so always fold across pods with `max()` or `avg()`. Never `sum()` (that multiplies by pod count and your scaler will go wild).

```promql
# Primary scale signal
max(pdagent_group_chunks_pending)

# True backlog
max(pdagent_group_chunks_pending + pdagent_group_chunks_inflight)

# Per-agent backlog (useful for averageValue HPAs)
max(pdagent_group_chunks_pending) / count(up{job="pd-agent"} == 1)

# Stalled queue alarm
max(pdagent_group_chunks_pending) > 100
  and max(pdagent_group_chunks_inflight) == 0
```

## Kubernetes: KEDA

KEDA is the cleanest path. It scales a Deployment based on a PromQL query and supports scale-to-zero between scans.

```yaml
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: pd-agent
spec:
  scaleTargetRef:
    name: pd-agent
  minReplicaCount: 1
  maxReplicaCount: 20
  pollingInterval: 30
  cooldownPeriod: 300
  triggers:
  - type: prometheus
    metadata:
      serverAddress: http://prometheus.monitoring.svc:9090
      metricName: pdagent_group_chunks_pending
      threshold: "100"
      query: max(pdagent_group_chunks_pending)
```

KEDA divides the query result by `threshold` to compute desired replicas. With `threshold: 100`, a value of 400 pending becomes 4 replicas. Pick `threshold` as "how many pending chunks you want each agent to be responsible for at steady state".

For pure Kubernetes HPA without KEDA, use `prometheus-adapter` to register `pdagent_group_chunks_pending` as an external metric, then write a standard HPA with `target.averageValue: 100`. The math is the same, the YAML is just longer.

## Kubernetes: scrape configuration

Annotate the pd-agent Pod template so Prometheus picks it up:

```yaml
metadata:
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/path: "/metrics"
    prometheus.io/port: "9090"
```

Make sure `PDCP_METRICS_ADDR=:9090` is set in the container env.

## VMs / cloud auto-scaling: bird's eye

If you're not on Kubernetes, the same metrics work; you write the loop. The pattern most customers use:

1. **Run pd-agent on each VM with `PDCP_METRICS_ADDR=:9090`.**
2. **Have one observer poll any single agent every 30-60s.** It can be a small script on a controller, a sidecar, a Lambda, whatever fits your stack. You only need to poll one agent because every agent reports the same numbers.
3. **Decide desired capacity** with simple math: `desired = ceil(chunks_pending / threshold)`, clamped to your `[min, max]`.
4. **Tell your fleet manager** (AWS Auto Scaling Group, GCP MIG, Azure VMSS, custom orchestrator) to set the desired count.

Most cloud auto-scaling products let you skip step 2-3 by **pushing the metric as a custom CloudWatch/Stackdriver/Azure metric** and writing a target-tracking policy directly on it. That's usually the lowest-effort route.

A bare-metal sketch:

```bash
while true; do
  pending=$(curl -fsS http://agent-1:9090/metrics \
    | awk '/^pdagent_group_chunks_pending /{print $2}')
  desired=$(( (pending + 99) / 100 ))
  desired=$(( desired < 1 ? 1 : (desired > 20 ? 20 : desired) ))
  # call your fleet API here with $desired
  sleep 60
done
```

This is the bare-minimum form; a real loop should add hysteresis (don't change capacity on every sample), check `oldest_consumer_age_seconds` for stalls before scaling out, and avoid scaling down on a single zero reading.

## Picking a threshold

Order-of-magnitude reasoning: if a chunk takes ~30s on average and one agent processes 20 chunks in parallel, one agent drains roughly 40 chunks/min. To keep `chunks_pending` below 200 at steady state, you want `pending/replicas ≈ 50`, so set the per-agent threshold to ~50 chunks.

Adjust from observation, not theory. Run with a generous threshold first, watch how the curves look during a real scan, then tune down if the queue is consistently over-provisioned.

## Tuning notes

- **Add a cooldown / stabilization window of 3-5 minutes** before scaling down. A scan finishing creates a brief drop in `chunks_pending`; you don't want to lose a pod, then immediately need it back for the next scan.
- **Cap `maxReplicas`** at something sensible. Adding more agents than your control plane (or your bandwidth) can publish chunks to is wasted money.
- **`minReplicas: 0`** is safe with KEDA if scan workload is bursty. The first scan will sit in `work_pending` until the controller spins up an agent; some startup latency is the cost.
- **Customers with their own metrics stack** (Datadog, NewRelic, Zabbix) can scrape the Prometheus endpoint with the standard exporter integration their tool already provides. Same metrics, same advice.
