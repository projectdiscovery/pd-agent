# Scan log

The raw per-chunk nuclei output, where it goes, and how to configure it.

---

## 1. What the scan log is

For every template nuclei attempts against a target, it writes one JSON record. The agent gzips that file once per chunk and uploads it to every destination you configure.

The record is written whether the template matched or not, so the log holds the checks that found nothing alongside the ones that did. Findings alone tell you what was wrong; the scan log tells you what was tried.

```
scan
 └── chunk                      one nuclei run
      └── <chunk_id>.jsonl      one record per template attempted
            │ gzip
            ├──► PD-managed storage
            └──► your S3 bucket
```

## 2. Configuration

Two destinations, independent of each other. Either, both, or neither.

| Variable | Default | Description |
| --- | --- | --- |
| `PDCP_ENABLE_SCAN_LOG_UPLOAD` | `false` | Upload to PD-managed storage. |
| `PDCP_SCAN_LOG_S3_BUCKET` | — | Bucket in your own S3-compatible storage. Setting it enables the destination and makes the next three required. |
| `PDCP_SCAN_LOG_S3_REGION` | — | Bound into the request signature, so a wrong value fails every upload. Use the real region on AWS, `auto` on Cloudflare R2. |
| `PDCP_SCAN_LOG_S3_ACCESS_KEY_ID` | — | |
| `PDCP_SCAN_LOG_S3_SECRET_ACCESS_KEY` | — | |
| `PDCP_SCAN_LOG_S3_ENDPOINT` | — | For non-AWS storage, e.g. `http://minio:9000`. Must include the scheme. Empty uses the regional AWS endpoint. |
| `PDCP_SCAN_LOG_S3_USE_PATH_STYLE` | `false` | `true` for MinIO and most in-cluster stores, where a per-bucket hostname does not resolve. |
| `PDCP_SCAN_LOG_S3_PREFIX` | `scan-logs` | Key prefix. |

Credentials are read only from these variables. The AWS default credential chain is never consulted, so no instance profile, IRSA role, shared config file, or `AWS_*` variable on the host can write to your bucket. Long-lived keys only; temporary credentials are not supported.

Objects land at:

```
<prefix>/<scan_id>/<history_id>/<chunk_id>.jsonl.gz
```

Stored as `application/gzip` with no `Content-Encoding`, so consumers gunzip on read.

### Confirm the configuration was read

The agent logs its resolved destinations once at startup, credentials excluded:

```
INFO scan-log: upload enabled destinations=[s3] s3_bucket=your-bucket
     s3_region=us-east-1 s3_endpoint= s3_path_style=false s3_prefix=scan-logs
```

> If you see `scan-log: upload disabled, no destinations configured` instead, nothing will upload. Check for one of these two lines before your first scan.

An incomplete S3 config stops the agent at startup with the missing variable named, rather than starting and failing every upload.

## 3. Record format

One JSON object per line:

```json
{"template-id":"example-check",
 "template-path":"http/exposures/example-check.yaml",
 "info":{"name":"Example Check","severity":"medium","tags":["exposure"]},
 "type":"http",
 "host":"target.example.com",
 "port":"443",
 "url":"https://target.example.com:443",
 "timestamp":"2026-01-01T00:00:00Z",
 "matcher-status":false}
```

| Field | Use |
| --- | --- |
| `template-id`, `template-path` | which check ran |
| `host`, `port`, `url` | what it ran against |
| `matcher-status` | `true` for a finding, `false` for a check that ran and matched nothing |
| `error` | present when the attempt failed, with the reason |

## 4. What the scan log does not cover

### Targets that were not scanned

Before running templates, the agent port-scans each target using the ports its templates care about. A target with none of those ports open is dropped, and if a chunk has no targets left it is skipped without invoking nuclei.

A skipped chunk produces no object and no records. **An absent object does not mean the target was clean.** It can equally mean the target was never scanned.

### What the scan was asked to do

The log records what ran. It does not record the request: targets submitted, targets dropped by the port scan, templates requested, or templates that could not be resolved. Use it to see what was attempted, not to reconcile against what you asked for.

### A fixed target-by-template count

The record count is not targets multiplied by templates. Three things change it:

- The port scan replaces each target with one entry per open port, so a single target can become several.
- A template only runs against the ports its protocol matched.
- Work is split into chunks, and the same template and target can appear in more than one, so records can repeat.

### Consistent host formatting

Depending on template type, `host` is either a bare hostname or a full URL including scheme and port. Normalise both before aggregating, or one target will appear as two.

### Guaranteed delivery

Upload is best-effort. A failure is logged and the chunk still completes, so a misconfigured bucket does not fail a scan. Watch the agent log for `scan-log upload failed`.

### Enumeration

Only scans produce a scan log. Enumeration tasks do not.

## 5. Limits

| | |
| --- | --- |
| Maximum object size (your bucket) | 512 MiB gzipped. Rejected before the upload starts, so nothing is transferred |
| Encryption at rest | the bucket default. The agent sets no encryption header |
| Retention | none. The agent never deletes an object |
| Outbound proxy (your bucket) | `PROXY_URL` is honoured, and `NO_PROXY` / `no_proxy` apply. Unset, the standard `HTTP_PROXY` / `HTTPS_PROXY` variables apply instead |
| Plaintext endpoints | an `http://` endpoint is allowed and warned about at startup. Scan logs and the signed request cross the network unencrypted |
| PD-managed storage | proxy behaviour and the size cap differ: it follows the platform's own limit and does not use `PROXY_URL` for the storage leg |

Verified against AWS S3 and MinIO. Cloudflare R2 and GCS interop are expected to work but are untested.

## 6. Reading an object

```bash
aws s3 ls "s3://$BUCKET/scan-logs/" --recursive | head
aws s3 cp "s3://$BUCKET/<key>" - | gunzip | head -1 | jq .

# check integrity of what you downloaded
for f in *.gz; do gunzip -t "$f" || echo "CORRUPT: $f"; done
```
