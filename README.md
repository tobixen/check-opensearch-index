# OpenSearch Index Activity Nagios Plugin

Nagios/NRPE plugin to monitor OpenSearch/Elasticsearch index activity by checking the timestamp of the most recent documents.

## Features

- ✅ Monitors for insufficient activity (documents too old)
- ✅ Monitors for excessive activity (documents too new - detects runaway processes, attacks)
- ✅ Anti-flapping: requires N unique recent documents (handles multiple sources at different frequencies)
- ✅ Flexible filtering: JSON query support to monitor specific document subsets
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

## Credentials Setup

Add OpenSearch credentials to `~/.netrc`:

```bash
cat >> ~/.netrc <<EOF
machine localhost
  login admin
  password your-opensearch-password
EOF

chmod 600 ~/.netrc
```

For custom hosts:
```bash
cat >> ~/.netrc <<EOF
machine opensearch.example.com
  login monitoring_user
  password secret123
EOF
```

## Usage

### Basic Usage

```bash
# Check 'logs-2024' index with default thresholds (1h warning, 2h critical)
./check_opensearch_index.py -i logs-2024

# Check with custom thresholds
./check_opensearch_index.py -i filebeat-* -w 300 -c 600
  # Warn if no activity for 5 minutes, critical at 10 minutes

# Check with custom timestamp field
./check_opensearch_index.py -i myindex -t event_timestamp -w 1800 -c 3600
```

### Options

```
usage: check_opensearch_index.py [-h] -i INDEX [-w WARNING] [-c CRITICAL]
                                  [-t TIMESTAMP_FIELD] [-H HOST] [-k] [-v]
                                  [--count N]

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
```


## Examples

### Standard Log Monitoring

```bash
# Filebeat logs - warn after 10 min, critical after 30 min
./check_opensearch_index.py -i filebeat-* -w 600 -c 1800

# Application logs - warn after 1h, critical after 4h
./check_opensearch_index.py -i app-logs-* -w 3600 -c 14400
```

### Indices with Multiple Sources (Anti-Flapping)

For indices with multiple sources at varying frequencies, use `--count` to avoid false positives:

```bash
# Check 5 recent documents, oldest must be within thresholds
# This prevents flapping when one infrequent source stops while others continue
./check_opensearch_index.py -i mixed-logs-* -w 60 -c 300 --count 5

# High-frequency index: check 10 recent documents
./check_opensearch_index.py -i realtime-* -w 30 -c 120 --count 10

# Conservative check for critical index
./check_opensearch_index.py -i critical-app-* -w 120 -c 600 --count 20
```

**How it works:**
- Fetches N most recent documents in a single query (where N = --count)
- Verifies we got N unique documents (fails if index has < N total docs)
- Checks that the **oldest** of those N documents is within warning/critical thresholds
- Single query = fast execution, suitable for NRPE

**Example:** With `--count 5 -w 60 -c 300`:
- Fetches 5 most recent documents
- If the 5th-oldest is only 45 seconds old → OK (all 5 are recent)
- If the 5th-oldest is 90 seconds old → WARNING (not enough recent activity from all sources)
- If the 5th-oldest is 400 seconds old → CRITICAL (significant inactivity)

### Custom OpenSearch Instance

```bash
# Remote OpenSearch with custom port
./check_opensearch_index.py \
  -i production-logs-* \
  -H https://opensearch.prod.example.com:9200 \
  -w 600 -c 1800

# Development instance with self-signed cert
./check_opensearch_index.py \
  -i dev-logs \
  -H https://dev-opensearch:9200 \
  -k \
  -w 3600 -c 7200
```

### Different Timestamp Fields

```bash
# Custom timestamp field
./check_opensearch_index.py -i custom-index -t event_time -w 1800 -c 3600

# Logstash-style timestamp
./check_opensearch_index.py -i logstash-* -t timestamp -w 600 -c 1200
```

### Excessive Activity Monitoring

Monitor for TOO MUCH activity (infinite loops, excessive logging, attacks, disk space issues):

```bash
# Error logs should be rare - alert if too frequent
# Warn if oldest of 10 docs is < 5 minutes old, critical if < 1 minute
./check_opensearch_index.py -i error-logs-* --count 10 \
  --min-warning 300 --min-critical 60 -w 86400 -c 172800

# Debug logging should be disabled in production
# Alert if ANY debug logs appear (oldest of 5 docs < 1 hour old)
./check_opensearch_index.py -i app-logs -w 3600 -c 7200 \
  --filter '{"term": {"level.keyword": "DEBUG"}}' \
  --count 5 --min-warning 3600

# Detect DoS/attack patterns - too many 4xx/5xx errors
./check_opensearch_index.py -i nginx-access-* --count 100 \
  --filter '{"range": {"status": {"gte": 400}}}' \
  --min-warning 60 --min-critical 10 -w 3600 -c 7200

# Application should only log once per minute normally
# Alert if logging faster than every 10 seconds
./check_opensearch_index.py -i app-audit-* --count 10 \
  --min-warning 10 -w 3600 -c 7200
```

**How it works:**
- `--min-warning` / `--min-critical` check if oldest document is TOO NEW (excessive activity)
- `-w` / `-c` still check if oldest document is TOO OLD (insufficient activity)
- Both can be used together to create an acceptable range

**Example:** With `--count 10 --min-warning 300 -w 3600`:
- Fetches 10 most recent documents
- CRITICAL: if oldest is > 3600s (no activity)
- WARNING: if oldest is < 300s (too much activity)
- OK: if oldest is between 300s and 3600s

### Filtering Documents

Use `--filter` to monitor specific subsets of documents within an index:

```bash
# Monitor only documents from a specific host
./check_opensearch_index.py -i logs-* -w 300 -c 600 \
  --filter '{"term": {"host.keyword": "webserver-01"}}'

# Monitor documents with specific field values (multiple filters)
./check_opensearch_index.py -i app-logs -w 300 -c 600 \
  --filter '[{"term": {"environment.keyword": "production"}}, {"term": {"app.keyword": "api"}}]'

# Numeric field filtering
./check_opensearch_index.py -i metrics-* -w 120 -c 300 \
  --filter '{"term": {"site_id": 1}}'

# Wildcard matching
./check_opensearch_index.py -i logs-* -w 300 -c 600 \
  --filter '{"wildcard": {"service.keyword": "backend-*"}}'

# Multiple conditions with different types
./check_opensearch_index.py -i filebeat-* -w 300 -c 600 \
  --filter '[{"term": {"SM_SITE_ID": "1"}}, {"term": {"SM_BUILD_DOMAIN": "proto.example.com"}}]'

# Range query (documents from last hour only)
./check_opensearch_index.py -i logs-* -w 300 -c 600 \
  --filter '{"range": {"@timestamp": {"gte": "now-1h"}}}'
```

**Filter syntax notes:**
- Single filter: Pass a JSON object `'{"term": {"field": "value"}}'`
- Multiple filters (AND): Pass a JSON array `'[{"term": {...}}, {"term": {...}}]'`
- Text fields: Use `.keyword` suffix for exact matches: `"field.keyword"`
- Numeric fields: No `.keyword` needed: `"site_id": 1` or `"site_id": "1"`
- Check your index mapping with: `curl -k --netrc https://localhost:9200/index/_mapping`

## Output Examples

### OK Status
```
# Single document check (default)
OK: Index 'logs-2024' has activity from 5m 23s ago | age=323s;3600;7200;0;

# Multi-document check
OK: 5 unique documents, newest: 3s, oldest: 45s | age=3s;60;300;0; oldest_age=45s;60;300;0; unique_docs=5;;;;
```
**Exit code:** 0

### WARNING Status
```
# Age threshold exceeded (single document)
WARNING: No activity in 'filebeat-*' for 1h 15m (threshold: 1h 0m) | age=4500s;3600;7200;0;

# Oldest document exceeds warning threshold
WARNING: Oldest of 5 documents is 1m 25s old (threshold: 1m 0s) | age=5s;60;300;0; oldest_age=85s;60;300;0; unique_docs=5;;;;
```
**Exit code:** 1

### CRITICAL Status
```
# Age threshold exceeded
CRITICAL: No activity in 'app-logs' for 3h 45m (threshold: 2h 0m) | age=13500s;3600;7200;0;

# Oldest document exceeds critical threshold
CRITICAL: Oldest of 10 documents is 6m 40s old (threshold: 5m 0s) | age=12s;120;300;0; oldest_age=400s;120;300;0; unique_docs=10;;;;
```
**Exit code:** 2

### ERROR Cases
```
CRITICAL: No documents found in index 'nonexistent-index'
CRITICAL: Only 3 documents found, need 5
CRITICAL: Only 2 unique documents found, need 5
CRITICAL: HTTP 401 error querying OpenSearch: Unauthorized
CRITICAL: Connection error: Connection refused
UNKNOWN: --count must be >= 1
```
**Exit code:** 2 (CRITICAL) or 3 (UNKNOWN)

## Nagios/NRPE Configuration

### NRPE Command Definition

Add to `/etc/nagios/nrpe.cfg`:

```ini
# Check logs index
command[check_opensearch_logs]=/usr/lib/nagios/plugins/check_opensearch_index.py -i logs-* -w 3600 -c 7200

# Check filebeat with shorter thresholds
command[check_opensearch_filebeat]=/usr/lib/nagios/plugins/check_opensearch_index.py -i filebeat-* -w 300 -c 600

# Check metrics with very short thresholds
command[check_opensearch_metrics]=/usr/lib/nagios/plugins/check_opensearch_index.py -i metrics-* -w 120 -c 300

# High-frequency index with anti-flapping (check 5 docs, oldest within 30s)
command[check_opensearch_realtime]=/usr/lib/nagios/plugins/check_opensearch_index.py -i realtime-* -w 30 -c 120 --count 5
```

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

## Performance Data

The plugin outputs performance data in Nagios format:

### Single Document Mode (default)
```
age=323s;3600;7200;0;
```

Where:
- `323s` - Current age of latest document in seconds
- `3600` - Warning threshold
- `7200` - Critical threshold
- `0` - Minimum value (always 0)

### Multi-Document Mode (--count > 1)
```
age=3s;60;300;0; oldest_age=45s;60;300;0; unique_docs=5;;;;
```

Where:
- `age=3s;60;300;0;` - Age of newest document with thresholds
- `oldest_age=45s;60;300;0;` - Age of oldest document (this is checked against thresholds)
- `unique_docs=5;;;;` - Count of unique documents found (informational, no thresholds)

This can be graphed using PNP4Nagios, Grafana, or other monitoring tools.

## Troubleshooting

### Enable Verbose Mode

```bash
./check_opensearch_index.py -i logs-* -v
```

Output:
```
DEBUG: Credentials found in ~/.netrc
DEBUG: Querying https://localhost:9200/logs-*
DEBUG: Query response: {...}
DEBUG: Latest document timestamp: 2024-05-28T14:30:00.123Z
DEBUG: Current time: 2024-05-28T14:35:23.456Z
DEBUG: Age: 323 seconds
OK: Index 'logs-*' has activity from 5m 23s ago | age=323s;3600;7200;0;
```

### Common Issues

**No documents found**
```
CRITICAL: No documents found in index 'myindex'
```
- Check if index exists: `curl -k --netrc https://localhost:9200/_cat/indices?v`
- Check index pattern matches: `curl -k --netrc https://localhost:9200/myindex*/_count`

**Timestamp field not found**
```
CRITICAL: Timestamp field '@timestamp' not found in document
```
- Check field name: `curl -k --netrc https://localhost:9200/myindex/_mapping`
- Use `-t` option: `./check_opensearch_index.py -i myindex -t event_time`

**Authentication failed**
```
CRITICAL: HTTP 401 error querying OpenSearch: Unauthorized
```
- Verify `.netrc` exists and has correct permissions (600)
- Check credentials: `curl -k --netrc https://localhost:9200/_cluster/health`
- Verify hostname in `.netrc` matches URL

**SSL Certificate error**
```
CRITICAL: Connection error: [SSL: CERTIFICATE_VERIFY_FAILED]
```
- Use `-k` flag for self-signed certs: `./check_opensearch_index.py -i myindex -k`
- Or install proper CA certificate

**Connection refused**
```
CRITICAL: Connection error: Connection refused
```
- Check OpenSearch is running: `systemctl status opensearch`
- Verify port: `netstat -tlnp | grep 9200`
- Check firewall rules

## Testing

### Test with Sample Data

```bash
# Create test index
curl -k --netrc -X PUT https://localhost:9200/test-index

# Insert test document
curl -k --netrc -X POST https://localhost:9200/test-index/_doc -H 'Content-Type: application/json' -d '{
  "@timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'",
  "message": "test"
}'

# Run check
./check_opensearch_index.py -i test-index -w 60 -c 120

# Should return OK
```

### Test Warning Threshold

```bash
# Insert old document (2 hours ago)
curl -k --netrc -X POST https://localhost:9200/test-index/_doc -H 'Content-Type: application/json' -d '{
  "@timestamp": "'$(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%S.%3NZ)'",
  "message": "old test"
}'

# Check with 1h warning threshold
./check_opensearch_index.py -i test-index -w 3600 -c 7200

# Should return WARNING
```

## Performance

- **Python version**: ~0.1-0.5 seconds typical execution time
- **Bash version**: ~0.2-0.6 seconds typical execution time
- **Network dependent**: Most time spent on OpenSearch query

## Security Considerations

1. **Credentials Storage**: `.netrc` file should have `600` permissions
2. **SSL Verification**: Only use `-k` flag in development/testing
3. **Least Privilege**: Use dedicated monitoring user with read-only access
4. **Network Security**: Consider firewall rules for OpenSearch access

## License

MIT License - Free to use and modify

## Support

For issues or questions:
- Check verbose output with `-v` flag
- Review OpenSearch logs
- Test manual queries with `curl`
- Raise an issue at https://github.com/tobixen/check-opensearch-index/issues

## Author

The code was 100% AI-generated, by Claude - but with Tobias Brox doing some reviewing and ensuring good prompts.
