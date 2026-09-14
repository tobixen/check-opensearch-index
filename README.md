# OpenSearch Index Activity Nagios Plugin

Nagios/NRPE plugin to monitor OpenSearch/Elasticsearch index activity by checking the timestamp of the most recent documents.

## Features

- ✅ Monitors for insufficient activity (documents too old)
- ✅ Monitors for excessive activity (documents too new - detects runaway processes, attacks)
- ✅ Anti-flapping: Look at the Nth newest document rather than the newest
- ✅ Flexible filtering: JSON query support to monitor specific document subsets
- ✅ Alert on the presence of unwanted documents (errors, security events) with a filter and a minimum age
- ✅ Supports index patterns (e.g., `logs-*`, `filebeat-2024-*`)
- ✅ Warning and critical thresholds in the Nagios range format (minimum and/or maximum age)
- ✅ Reads credentials from `~/.netrc` or `/etc/nagios/netrc` (secure)
- ✅ Performance data output for graphing
- ✅ SSL support, with a private CA (`--ca-file`) or optionally without verification
- ✅ Zero external dependencies (Python 3.8+ stdlib only)

## Disclaimer

The script logic was entirely AI-generated - though, human-curated.  While I haven't looked through all of the code, I've done some inspections and come up with some suggestions for improvements.  This README is mostly written by AI, but polished and modified by me.

## Alternatives

There is a more generic script at https://github.com/misiupajor/check_elasticsearch - but it's also more complex and comes with more dependencies.

## Prerequisites

The script needs Python 3.8 or newer (the oldest version the test suite runs on) and uses only the standard library.

It works with any OpenSearch version, and with Elasticsearch 7.2 or newer.

## Installation

* Script should be copied to the nrpe plugin directory, typically `/usr/lib/nagios/plugins/`
* The nrpe configuration should be fixed
* The nagios/icinga/naemon configuration should be set up

## Security Setup

### Create a Read-Only Monitoring User (Recommended)

Create a dedicated monitoring user with minimal permissions:

```bash
# Create a role with read-only access to indices
curl -X PUT "https://localhost:9200/_plugins/_security/api/roles/monitoring_role" \
  -u admin:ADMINPASSWORD -k -H 'Content-Type: application/json' -d '
{
  "cluster_permissions": [],
  "index_permissions": [{
    "index_patterns": ["*"],
    "allowed_actions": ["indices:data/read/search"]
  }]
}'

# Create a monitoring user
curl -X PUT "https://localhost:9200/_plugins/_security/api/internalusers/monitoring" \
  -u admin:ADMINPASSWORD -k -H 'Content-Type: application/json' -d '
{
  "password": "your-secure-password-here",
  "backend_roles": [],
  "attributes": {}
}'

# Map the user to the role
curl -X PUT "https://localhost:9200/_plugins/_security/api/rolesmapping/monitoring_role" \
  -u admin:ADMINPASSWORD -k -H 'Content-Type: application/json' -d '
{
  "backend_roles": [],
  "hosts": [],
  "users": ["monitoring"]
}'
```

**For Elasticsearch (without OpenSearch Security Plugin):**

```bash
# Create role with read permission
curl -X POST "https://localhost:9200/_security/role/monitoring_role" \
  -u elastic:password -k -H 'Content-Type: application/json' -d '
{
  "indices": [{
    "names": ["*"],
    "privileges": ["read"]
  }]
}'

# Create user
curl -X POST "https://localhost:9200/_security/user/monitoring" \
  -u elastic:password -k -H 'Content-Type: application/json' -d '
{
  "password": "your-secure-password-here",
  "roles": ["monitoring_role"]
}'
```

### Credentials Setup

Add the monitoring user credentials to a netrc file. The script will automatically try `~/.netrc` first, then `/etc/nagios/netrc` as a fallback. For NRPE/Nagios deployments, use `/etc/nagios/netrc`:

```bash
sudo tee /etc/nagios/netrc <<EOF
machine localhost
  login monitoring
  password your-secure-password-here
EOF

sudo chown root:nagios /etc/nagios/netrc
sudo chmod 640 /etc/nagios/netrc
```

... or replace `localhost` with the location of your opensearch instance.  Use the group the NRPE daemon runs as (`nagios` or `nrpe`, depending on the distribution).

The netrc-file may contain several machine sections separated by a blank line, if needed.

**Security notes:**
- The monitoring user only needs `indices:data/read/search` permission (read-only)
- Never use admin credentials for monitoring
- Keep the netrc file unreadable for others: `640` with the plugin's user in the group, or `600` owned by that user
- Consider restricting the monitoring role to specific indices if needed

## Usage

### Thresholds

`-w` and `-c` take [Nagios threshold ranges](https://www.monitoring-plugins.org/doc/guidelines.html#THRESHOLDFORMAT), applied to the age in seconds of the oldest of the `--count` newest documents:

| Range   | Alerts when the age is | Typical use |
|---------|------------------------|-------------|
| `N`     | above N                | too little activity |
| `N:`    | below N                | too much activity, or unwanted documents found |
| `M:N`   | below M or above N     | both |
| `~:N`   | above N                | same as `N` |
| `@M:N`  | between M and N        | rarely useful |

If fewer than `--count` documents are found, the age counts as infinite: CRITICAL for `-c 7200`, OK for `-c 300:`.

Without any threshold option, `-w 3600 -c 7200` is used.  If any threshold is given, the others have no default.

`--min-warning N` and `--min-critical N` are an older way to set the lower bound: `--min-warning 30 -w 180` is the same as `-w 30:180`.

### Options

```
usage: check_opensearch_index.py [-h] -i INDEX [-w RANGE] [-c RANGE] [--min-warning SECONDS]
                                 [--min-critical SECONDS] [-t TIMESTAMP_FIELD] [-H HOST] [-k] [-v]
                                 [--ca-file CA_FILE] [-V] [--count COUNT] [--filter FILTER]
                                 [--netrc NETRC]

Check OpenSearch index activity

options:
  -h, --help            show this help message and exit
  -i, --index INDEX     OpenSearch index name or pattern (e.g., logs-*, filebeat-2024)
  -w, --warning RANGE   Warning threshold for the age in seconds, as a Nagios range (see below). N
                        alerts on ages above N, N: on ages below N.
  -c, --critical RANGE  Critical threshold for the age in seconds, as a Nagios range (see below).
  --min-warning SECONDS
                        Lower bound of the warning range: --min-warning 30 -w 180 is the same as
                        -w 30:180.
  --min-critical SECONDS
                        Lower bound of the critical range.
  -t, --timestamp-field TIMESTAMP_FIELD
                        Timestamp field name (default: @timestamp)
  -H, --host HOST       OpenSearch host URL (default: https://localhost:9200)
  -k, --insecure        Skip SSL certificate verification
  -v, --verbose         Verbose output for debugging
  --ca-file CA_FILE     CA certificate bundle (PEM) to verify the server certificate against
  -V, --version         show program's version number and exit
  --count COUNT         Number of recent documents to check (default: 1). Fetches this many recent
                        documents and checks that the oldest is within thresholds.
  --filter FILTER       JSON filter query to apply (e.g., '{"term": {"field.keyword": "value"}}').
                        Will be wrapped in a bool filter. Multiple filters can be combined in a
                        JSON array.
  --netrc NETRC         Path to .netrc file for credentials (default: ~/.netrc, then
                        /etc/nagios/netrc)
```

`--help` also prints the threshold table and examples.


## Examples

### Basic Monitoring

```bash
# Default thresholds (1h warning, 2h critical)
./check_opensearch_index.py -i logs-2024

# Custom thresholds: warn at 5m, critical at 10m
./check_opensearch_index.py -i filebeat-* -w 300 -c 600

# Custom timestamp field (Vector uses 'timestamp', Filebeat uses '@timestamp')
./check_opensearch_index.py -i vector-logs -t timestamp -w 600 -c 1200

# Remote host with self-signed cert
./check_opensearch_index.py -i logs -H https://opensearch.example.com:9200 -k -w 600 -c 1800
```

### Anti-Flapping with --count

To reduce the "jitter" in the monitoring, as well as being able to give alarms if the frequency of logging drops a lot (but does not stop), it's possible to add the `--count` argument - set it to 5 and it will take out the 5 most recent documents and consider the age of the fifth.

```bash
# Check 5 recent docs; if 5th oldest is stale, at least one source stopped
./check_opensearch_index.py -i mixed-logs-* -w 60 -c 300 --count 5

# High-frequency: verify 100 docs all recent
./check_opensearch_index.py -i realtime-* -w 60 -c 300 --count 100
```

### Excessive Activity Detection

Too much activity is often bad - it may be an indication that something is seriously wrong, and it may eat up all available disk space.  You may monitor for TOO MUCH activity by giving the threshold a lower bound:

```bash
# The "my-logs" index is supposed to have around 100 documents pr minute.  
# Alert if it takes more than 10m or less than 10s to produce 100 documents.
./check_opensearch_index.py -i my-logs-* --count 100 -w 30:180 -c 10:600
```

### Filtering Documents

If some index is receiving data from multiple sources, and you need to monitor that a specific source is constantly feeding the index, filters can be useful.  The full query language is available, some examples are given in [FILTERS.md](FILTERS.md)

Monitor specific subsets with `--filter` (JSON Elasticsearch query):

```bash
# Specific host
./check_opensearch_index.py -i logs-* -w 300 -c 600 --filter '{"term": {"host.keyword": "web-01"}}'

# Multiple conditions (AND)
./check_opensearch_index.py -i app-logs -w 300 -c 600 \
  --filter '[{"term": {"env.keyword": "prod"}}, {"term": {"app.keyword": "api"}}]'

# Numeric field
./check_opensearch_index.py -i metrics-* -w 120 -c 300 --filter '{"term": {"site_id": 1}}'

# Wildcard
./check_opensearch_index.py -i logs-* -w 300 -c 600 --filter '{"wildcard": {"service.keyword": "backend-*"}}'
```

**Filter notes:** Text fields need `.keyword` suffix for exact match. Numeric fields don't. Check mapping: `curl -k --netrc https://localhost:9200/index/_mapping`

### Alerting on Unwanted Documents

Combine `--filter` with a lower-bound threshold (`N:`) to alert when specific messages ARE found.  This is useful for alarming about:

* Log messages failing to be parsed correctly 
* A web server delivers too many 500 internal server errors
* A web server with too slow response time
* Other critical or unpleasant errors found in some logs

```bash
# Error logs index should have few hits; warn if 10 errors in < 5 minutes
./check_opensearch_index.py -i error-logs-* --count 10 -w 300:

# Detect DoS: 100 HTTP errors in < 60 seconds is critical
./check_opensearch_index.py -i nginx-* --count 100 -c 60: \
  --filter '{"range": {"status": {"gte": 400}}}'

# 100 HTTP 5xx errors in < 30 minutes is a warning, in < 5 minutes critical
./check_opensearch_index.py -i haproxy-* --count 100 -w 1800: -c 300: \
  --filter '{"range": {"http_code": {"gte": 500}}}'

# Alert if ERROR logs found in last 5 minutes
./check_opensearch_index.py -i logs-* --filter '{"term": {"level.keyword": "ERROR"}}' -c 300:

# Warn if FATAL/CRITICAL messages in last 10 minutes
./check_opensearch_index.py -i app-* --filter '{"query_string": {"query": "FATAL OR CRITICAL"}}' -w 600:

# Security monitoring: alert on unauthorized access
./check_opensearch_index.py -i security-* --filter '{"term": {"event.keyword": "unauthorized_access"}}' -c 3600:
```

**How it works:** `-c 300:` alerts when the oldest of the `--count` newest matching documents is younger than 300 seconds.  If fewer than `--count` documents match, the age counts as infinite, which is OK.  Don't add an upper bound (`-c 300:7200`) to such a check: then finding no errors becomes CRITICAL.

## Output Examples

```
OK: Index 'logs-2024' has activity from 5m 23s ago | age=323s;3600;7200;0;
OK: 5 documents, newest: 3s, oldest: 45s | age=3s;;;0; oldest_age=45s;60;300;0;
OK: No documents found matching filter in index 'haproxy-*'

WARNING: Insufficient activity - oldest of the 5 newest documents is 1m 25s old (maximum threshold: 1m 0s) | age=5s;;;0; oldest_age=85s;60;300;0;

CRITICAL: Insufficient activity - oldest of the 10 newest documents is 6m 40s old (maximum threshold: 5m 0s) | age=12s;;;0; oldest_age=400s;120;300;0;
CRITICAL: Excessive activity - oldest of the 100 newest documents matching filter is only 3m 12s old (minimum threshold: 5m 0s) | age=2s;;;0; oldest_age=192s;1800:;300:;0;
CRITICAL: No documents found in index 'nonexistent-index'
CRITICAL: HTTP 401 error querying OpenSearch: Unauthorized

UNKNOWN: --count must be >= 1
```

**Exit codes:** 0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN

**Performance data format:** `age=323s;warning;critical;0;` (suitable for graphing with PNP4Nagios, Grafana, etc.)

The thresholds are attached to the value they are checked against.  With `--count` > 1 that is `oldest_age`, and `age` (the newest document) carries none.  They use the same Nagios range format as `-w`/`-c`.

## Nagios/NRPE Configuration

### NRPE Command Definition

Add to `/etc/nagios/nrpe.cfg`:

```ini
# Normal mode: Check logs index for activity (using custom netrc location)
command[check_opensearch_logs]=/usr/lib/nagios/plugins/check_opensearch_index.py -i logs-* -w 3600 -c 7200 --netrc /etc/nagios/credentials/opensearch.netrc

# Check filebeat with shorter thresholds
command[check_opensearch_filebeat]=/usr/lib/nagios/plugins/check_opensearch_index.py -i filebeat-* -w 300 -c 600 --netrc /etc/nagios/credentials/opensearch.netrc

# Check metrics with very short thresholds
command[check_opensearch_metrics]=/usr/lib/nagios/plugins/check_opensearch_index.py -i metrics-* -w 120 -c 300 --netrc /etc/nagios/credentials/opensearch.netrc

# High-frequency index with anti-flapping (check 5 docs, oldest within 30s)
command[check_opensearch_realtime]=/usr/lib/nagios/plugins/check_opensearch_index.py -i realtime-* -w 30 -c 120 --count 5 --netrc /etc/nagios/credentials/opensearch.netrc

# Unwanted documents: Alert if ERROR logs found in last 5 minutes
command[check_opensearch_errors]=/usr/lib/nagios/plugins/check_opensearch_index.py -i logs-* --filter '{"term": {"level.keyword": "ERROR"}}' -c 300: --netrc /etc/nagios/credentials/opensearch.netrc

# Unwanted documents: Alert if FATAL/CRITICAL messages found in last 10 minutes
command[check_opensearch_critical]=/usr/lib/nagios/plugins/check_opensearch_index.py -i app-* --filter '{"query_string": {"query": "FATAL OR CRITICAL"}}' -w 600: --netrc /etc/nagios/credentials/opensearch.netrc
```

**Note:** The `nagios`/`nrpe` system users typically don't have a proper home directory, so the plugin falls back to `/etc/nagios/netrc`.  `--netrc` is only needed for credentials stored elsewhere, as in the examples above.

### Nagios Service Definition

Add to Nagios configuration:

```cfg
define service {
    use                     generic-service
    host_name               opensearch-server
    service_description     OpenSearch Logs Index Activity
    check_command           check_nrpe!check_opensearch_logs
    check_interval          5
    retry_interval          1
    max_check_attempts      3
}

define service {
    use                     generic-service
    host_name               opensearch-server
    service_description     OpenSearch Filebeat Index Activity
    check_command           check_nrpe!check_opensearch_filebeat
    check_interval          2
    retry_interval          1
    max_check_attempts      3
}
```

### Direct Check via check_nrpe

```bash
# From Nagios server
/usr/lib/nagios/plugins/check_nrpe -H opensearch-host -c check_opensearch_logs
```

## Troubleshooting

```bash
# Enable verbose mode for debugging
./check_opensearch_index.py -i logs-* -v
```

### Common Issues

| Issue | Solution |
|-------|----------|
| `No documents found in index 'myindex'` | Check index exists: `curl -k --netrc https://localhost:9200/_cat/indices?v` |
| `Timestamp field '@timestamp' not found` | Check mapping: `curl -k --netrc https://localhost:9200/myindex/_mapping`<br>Use `-t timestamp` for Vector logs |
| `HTTP 401 Unauthorized` | Verify the netrc file has correct credentials and is readable by the plugin's user (`-v` shows which file was used) |
| `SSL: CERTIFICATE_VERIFY_FAILED` | Use `--ca-file` with the CA certificate that signed the server certificate, or `-k` to skip verification |
| `Connection refused` | Check OpenSearch is running: `systemctl status opensearch` |

## Testing

```bash
# Create test index and insert recent document
curl -k --netrc -X PUT https://localhost:9200/test-index
curl -k --netrc -X POST https://localhost:9200/test-index/_doc -H 'Content-Type: application/json' -d \
  '{"@timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'", "message": "test"}'

# Test (should return OK)
./check_opensearch_index.py -i test-index -w 60 -c 120

# Insert old document to test WARNING
curl -k --netrc -X POST https://localhost:9200/test-index/_doc -H 'Content-Type: application/json' -d \
  '{"@timestamp": "'$(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%S.%3NZ)'", "message": "old"}'
./check_opensearch_index.py -i test-index -w 3600 -c 7200  # Should return WARNING
```

## Security & Support

**Security:** Use a read-only monitoring user, keep the netrc file unreadable for others, and prefer `--ca-file` over `-k` in production.

**Issues:** Check with `-v` flag first, then report at https://github.com/tobixen/check-opensearch-index/issues

**License:** MIT

**Author:** AI-generated by Claude, reviewed by Tobias Brox
