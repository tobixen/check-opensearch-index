# OpenSearch Index Activity Nagios Plugin

Nagios/NRPE plugin to monitor OpenSearch/Elasticsearch index activity by checking the timestamp of the most recent document.

## Features

- ✅ Checks for recent activity in OpenSearch/Elasticsearch indices
- ✅ Supports index patterns (e.g., `logs-*`, `filebeat-2024-*`)
- ✅ Configurable warning and critical thresholds
- ✅ Reads credentials from `~/.netrc` (secure)
- ✅ Performance data output for graphing
- ✅ Detailed error messages
- ✅ SSL support with optional verification
- ✅ Two implementations: Python (robust) and Bash (simple)

## Prerequisites

### Python Version
- Python 3.6+
- No external dependencies (uses only standard library)

### Bash Version
- Bash 4.0+
- Required commands: `curl`, `jq`, GNU `date`

## Installation

```bash
# Copy to Nagios plugins directory
sudo cp check_opensearch_index.py /usr/lib/nagios/plugins/
sudo chmod +x /usr/lib/nagios/plugins/check_opensearch_index.py

# Or use the bash version
sudo cp check_opensearch_index.sh /usr/lib/nagios/plugins/
sudo chmod +x /usr/lib/nagios/plugins/check_opensearch_index.sh
```

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

### Python Version Options

```
usage: check_opensearch_index.py [-h] -i INDEX [-w WARNING] [-c CRITICAL]
                                  [-t TIMESTAMP_FIELD] [-H HOST] [-k] [-v]

Required:
  -i, --index INDEX           OpenSearch index name or pattern

Optional:
  -w, --warning SECONDS       Warning threshold in seconds (default: 3600)
  -c, --critical SECONDS      Critical threshold in seconds (default: 7200)
  -t, --timestamp-field NAME  Timestamp field name (default: @timestamp)
  -H, --host URL              OpenSearch URL (default: https://localhost:9200)
  -k, --insecure              Skip SSL certificate verification
  -v, --verbose               Verbose output for debugging
```

### Bash Version Options

```
usage: check_opensearch_index.sh -i INDEX [-w WARNING] [-c CRITICAL]
                                  [-t TIMESTAMP_FIELD] [-H HOST] [-k] [-v]

Same options as Python version
```

## Examples

### Standard Log Monitoring

```bash
# Filebeat logs - warn after 10 min, critical after 30 min
./check_opensearch_index.py -i filebeat-* -w 600 -c 1800

# Application logs - warn after 1h, critical after 4h
./check_opensearch_index.py -i app-logs-* -w 3600 -c 14400
```

### High-Frequency Indices

```bash
# Metrics with 1-minute data - warn after 2 min, critical after 5 min
./check_opensearch_index.py -i metrics-2024 -w 120 -c 300

# Real-time events - warn after 30 sec, critical after 2 min
./check_opensearch_index.py -i events-* -w 30 -c 120
```

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

## Output Examples

### OK Status
```
OK: Index 'logs-2024' has activity from 5m 23s ago | age=323s;3600;7200;0;
```
**Exit code:** 0

### WARNING Status
```
WARNING: No activity in 'filebeat-*' for 1h 15m (threshold: 1h 0m) | age=4500s;3600;7200;0;
```
**Exit code:** 1

### CRITICAL Status
```
CRITICAL: No activity in 'app-logs' for 3h 45m (threshold: 2h 0m) | age=13500s;3600;7200;0;
```
**Exit code:** 2

### ERROR Cases
```
CRITICAL: No documents found in index 'nonexistent-index'
CRITICAL: HTTP 401 error querying OpenSearch: Unauthorized
CRITICAL: Connection error: Connection refused
```
**Exit code:** 2

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

```
age=323s;3600;7200;0;
```

Where:
- `323s` - Current age of latest document in seconds
- `3600` - Warning threshold
- `7200` - Critical threshold
- `0` - Minimum value (always 0)

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

## Author

Created for Nagios/NRPE monitoring of OpenSearch/Elasticsearch indices.
