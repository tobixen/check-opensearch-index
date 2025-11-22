# OpenSearch Index Activity Nagios Plugin

Nagios/NRPE plugin to monitor OpenSearch/Elasticsearch index activity by checking the timestamp of the most recent documents.

## Features

- ✅ Monitors for insufficient activity (documents too old)
- ✅ Monitors for excessive activity (documents too new - detects runaway processes, attacks)
- ✅ Anti-flapping: Look at the Nth newest document rather than the newest
- ✅ Flexible filtering: JSON query support to monitor specific document subsets
- ✅ Reverse mode with filtering: alert on presence of critical messages (errors, security events)
- ✅ Supports index patterns (e.g., `logs-*`, `filebeat-2024-*`)
- ✅ Configurable warning and critical thresholds (both minimum and maximum age)
- ✅ Reads credentials from `~/.netrc` (secure)
- ✅ Performance data output for graphing
- ✅ SSL support with optional verification
- ✅ Zero external dependencies (Python 3.6+ stdlib only)

There exists a Bash version of the script as well, but it's already deprecated, contains less feautures and will not be maintained.

## Disclaimer

The script logic was entirely AI-generated - though, human-curated.  While I haven't looked through all of the code, I've done some inspections and come up with some suggestions for improvements.  This README is mostly written by AI, but polished and modified by me.

## Alternatives

There is a more generic script at https://github.com/misiupajor/check_elasticsearch - but it's also more complex and comes with more dependencies.

## Prerequisites

The Python script works even with very old Python versions (3.6+) and uses only standard library.

The deprecated Bash script depends on `curl`, `jq` and GNU `date`.

## Installation

* Script should be copied to the nrpe plugin directory, typically `/usr/lib/nagios/plugins/`
* The nrpe configuration should be fixed
* The nagios/icinga/naemon configuration should be set up

## Security Setup

### Create a Read-Only Monitoring User (Recommended)

**Do not use the admin user for monitoring!** Create a dedicated read-only user with minimal permissions:

```bash
# Create a role with read-only access to indices
curl -X PUT "https://localhost:9200/_plugins/_security/api/roles/monitoring_role" \
  -u admin:admin -k -H 'Content-Type: application/json' -d '
{
  "cluster_permissions": [],
  "index_permissions": [{
    "index_patterns": ["*"],
    "allowed_actions": ["indices:data/read/search"]
  }]
}'

# Create a monitoring user
curl -X PUT "https://localhost:9200/_plugins/_security/api/internalusers/monitoring" \
  -u admin:admin -k -H 'Content-Type: application/json' -d '
{
  "password": "your-secure-password-here",
  "backend_roles": [],
  "attributes": {}
}'

# Map the user to the role
curl -X PUT "https://localhost:9200/_plugins/_security/api/rolesmapping/monitoring_role" \
  -u admin:admin -k -H 'Content-Type: application/json' -d '
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

Add the monitoring user credentials to `~/.netrc`:

```bash
cat >> ~/.netrc <<EOF
machine localhost
  login monitoring
  password your-secure-password-here
EOF

chmod 600 ~/.netrc
```

For custom hosts:
```bash
cat >> ~/.netrc <<EOF
machine opensearch.example.com
  login monitoring
  password your-secure-password-here
EOF
```

**Security notes:**
- The monitoring user only needs `indices:data/read/search` permission (read-only)
- Never use admin credentials for monitoring
- Ensure `.netrc` has `600` permissions (readable only by owner)
- Consider restricting the monitoring role to specific indices if needed

**For NRPE/system users with non-standard home directories:**

If running as the `nagios` or `nrpe` user (which may have `/` or `/var/run/nrpe` as home), use a custom netrc location:

```bash
# Create netrc file in a dedicated location
sudo mkdir -p /etc/nagios/credentials
sudo cat > /etc/nagios/credentials/opensearch.netrc <<EOF
machine localhost
  login monitoring
  password your-secure-password-here
EOF

# Set proper permissions
sudo chmod 600 /etc/nagios/credentials/opensearch.netrc
sudo chown nagios:nagios /etc/nagios/credentials/opensearch.netrc
```

Then use `--netrc` parameter:
```bash
./check_opensearch_index.py -i logs-* -w 300 -c 600 \
  --netrc /etc/nagios/credentials/opensearch.netrc
```

## Usage

### Options

```
usage: check_opensearch_index.py [-h] -i INDEX [-w WARNING] [-c CRITICAL]
                                  [-t TIMESTAMP_FIELD] [-H HOST] [-k] [-v]
                                  [--count N] [--filter JSON] [--reverse]

Required:
  -i, --index INDEX           OpenSearch index name or pattern

Optional:
  -w, --warning SECONDS       Maximum age warning threshold (default: 3600)
                              Alert if documents are OLDER than this
  -c, --critical SECONDS      Maximum age critical threshold (default: 7200)
                              Alert if documents are OLDER than this
  --min-warning SECONDS       Minimum age warning threshold (excessive activity)
                              Alert if documents are NEWER than this
  --min-critical SECONDS      Minimum age critical threshold (excessive activity)
                              Alert if documents are NEWER than this
  -t, --timestamp-field NAME  Timestamp field name (default: @timestamp)
  -H, --host URL              OpenSearch URL (default: https://localhost:9200)
  -k, --insecure              Skip SSL certificate verification
  -v, --verbose               Verbose output for debugging

Advanced (anti-flapping for indices with multiple sources):
  --count N                   Number of recent documents to check (default: 1)

Filtering:
  --filter JSON               JSON filter query to apply to document search

Mode:
  --reverse                   Reverse logic: OK when no documents found, CRITICAL when
                              documents ARE found. Ignores max age (--warning, --critical).
                              Use with --filter and --min-warning/--min-critical to alert
                              on presence of critical log messages.

Credentials:
  --netrc FILE                Path to .netrc file (default: ~/.netrc)
```


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

Use `--count` for indices with multiple sources - checks that the Nth oldest document is recent:

```bash
# Check 5 recent docs; if 5th oldest is stale, at least one source stopped
./check_opensearch_index.py -i mixed-logs-* -w 60 -c 300 --count 5

# High-frequency: verify 10 docs all recent
./check_opensearch_index.py -i realtime-* -w 30 -c 120 --count 10
```

### Excessive Activity Detection

Monitor for TOO MUCH activity using `--min-warning`/`--min-critical`:

```bash
# Error logs should be rare; alert if 10 errors in < 5 minutes
./check_opensearch_index.py -i error-logs-* --count 10 --min-warning 300 -w 86400 -c 172800

# Detect DoS: 100 HTTP errors in < 60 seconds is critical
./check_opensearch_index.py -i nginx-* --count 100 --min-critical 60 -w 3600 -c 7200 \
  --filter '{"range": {"status": {"gte": 400}}}'
```

### Reverse Mode: Alert on Presence

Use `--reverse` to alert when specific messages ARE found (inverts logic):

```bash
# Alert if ERROR logs found in last 5 minutes
./check_opensearch_index.py -i logs-* --filter '{"term": {"level.keyword": "ERROR"}}' \
  --min-critical 300 --reverse

# Warn if FATAL/CRITICAL messages in last 10 minutes
./check_opensearch_index.py -i app-* --filter '{"query_string": {"query": "FATAL OR CRITICAL"}}' \
  --min-warning 600 --reverse

# Security monitoring: alert on unauthorized access
./check_opensearch_index.py -i security-* --filter '{"term": {"event.keyword": "unauthorized_access"}}' \
  --min-critical 3600 --reverse
```

**Reverse mode behavior:**
- No matching documents → **OK**
- Documents found but older than threshold → **OK**
- Documents newer than `--min-critical` → **CRITICAL**
- Documents newer than `--min-warning` → **WARNING**

### Filtering Documents

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

## Output Examples

```
OK: Index 'logs-2024' has activity from 5m 23s ago | age=323s;3600;7200;0;
OK: 5 documents, newest: 3s, oldest: 45s | age=3s;60;300;0; oldest_age=45s;60;300;0;

WARNING: Insufficient activity - oldest of 5 documents is 1m 25s old (maximum threshold: 1m 0s) | age=5s;60;300;0; oldest_age=85s;60;300;0;

CRITICAL: Insufficient activity - oldest of 10 documents is 6m 40s old (maximum threshold: 5m 0s) | age=12s;120;300;0; oldest_age=400s;120;300;0;
CRITICAL: No documents found in index 'nonexistent-index'
CRITICAL: HTTP 401 error querying OpenSearch: Unauthorized

UNKNOWN: --count must be >= 1
```

**Exit codes:** 0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN

**Performance data format:** `age=323s;warning;critical;min;` (suitable for graphing with PNP4Nagios, Grafana, etc.)

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

# Reverse mode: Alert if ERROR logs found in last 5 minutes
command[check_opensearch_errors]=/usr/lib/nagios/plugins/check_opensearch_index.py -i logs-* --filter '{"term": {"level.keyword": "ERROR"}}' --min-critical 300 --reverse --netrc /etc/nagios/credentials/opensearch.netrc

# Reverse mode: Alert if FATAL/CRITICAL messages found in last 10 minutes
command[check_opensearch_critical]=/usr/lib/nagios/plugins/check_opensearch_index.py -i app-* --filter '{"query_string": {"query": "FATAL OR CRITICAL"}}' --min-warning 600 --reverse --netrc /etc/nagios/credentials/opensearch.netrc
```

**Note:** The `--netrc` parameter is essential when running as the `nagios`/`nrpe` user, as these system users typically don't have a proper home directory.

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
| `HTTP 401 Unauthorized` | Verify `.netrc` has correct credentials and `600` permissions |
| `SSL: CERTIFICATE_VERIFY_FAILED` | Use `-k` flag for self-signed certs |
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

**Security:** Use read-only monitoring user, keep `.netrc` at `600` permissions, avoid `-k` in production.

**Issues:** Check with `-v` flag first, then report at https://github.com/tobixen/check-opensearch-index/issues

**License:** MIT

**Author:** AI-generated by Claude, reviewed by Tobias Brox
