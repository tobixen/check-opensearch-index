#!/usr/bin/env bash

## THIS FILE WILL NOT BE MAINTAINED.
## USE check_opensearch_index.py instead!

#
# Nagios/NRPE plugin to check OpenSearch index activity (bash version)
#
# This is a simpler bash alternative to the Python version.
# Requires: curl, jq, date (GNU coreutils)
#
# Exit codes:
#   0 - OK: Index has recent activity
#   1 - WARNING: No activity within warning threshold
#   2 - CRITICAL: No activity within critical threshold or error
#   3 - UNKNOWN: Invalid arguments or unexpected error

set -euo pipefail

# Nagios exit codes
STATE_OK=0
STATE_WARNING=1
STATE_CRITICAL=2
STATE_UNKNOWN=3

# Default values
HOST="https://localhost:9200"
TIMESTAMP_FIELD="@timestamp"
WARNING=3600    # 1 hour
CRITICAL=7200   # 2 hours
INSECURE=""
VERBOSE=0

# Usage information
usage() {
    cat <<EOF
Usage: $0 -i INDEX [-w WARNING] [-c CRITICAL] [-t TIMESTAMP_FIELD] [-H HOST] [-k] [-v]

Check OpenSearch index activity

Required:
  -i INDEX              OpenSearch index name or pattern

Options:
  -w WARNING            Warning threshold in seconds (default: 3600 = 1h)
  -c CRITICAL           Critical threshold in seconds (default: 7200 = 2h)
  -t TIMESTAMP_FIELD    Timestamp field name (default: @timestamp)
  -H HOST               OpenSearch URL (default: https://localhost:9200)
  -k                    Skip SSL verification (insecure)
  -v                    Verbose output
  -h                    Show this help

Credentials are read from ~/.netrc

Examples:
  $0 -i logs-2024 -w 3600 -c 7200
  $0 -i filebeat-* -w 300 -c 600 -t @timestamp
  $0 -i myindex -w 1800 -c 3600 -H https://opensearch.local:9200

EOF
    exit $STATE_UNKNOWN
}

# Parse command line arguments
while getopts "i:w:c:t:H:kvh" opt; do
    case $opt in
        i) INDEX="$OPTARG" ;;
        w) WARNING="$OPTARG" ;;
        c) CRITICAL="$OPTARG" ;;
        t) TIMESTAMP_FIELD="$OPTARG" ;;
        H) HOST="$OPTARG" ;;
        k) INSECURE="--insecure" ;;
        v) VERBOSE=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Check required arguments
if [[ -z "${INDEX:-}" ]]; then
    echo "UNKNOWN: Index name required (-i)"
    exit $STATE_UNKNOWN
fi

# Validate thresholds
if (( CRITICAL < WARNING )); then
    echo "UNKNOWN: Critical threshold must be >= warning threshold"
    exit $STATE_UNKNOWN
fi

# Check required commands
for cmd in curl jq date; do
    if ! command -v $cmd &> /dev/null; then
        echo "UNKNOWN: Required command '$cmd' not found"
        exit $STATE_UNKNOWN
    fi
done

# Build curl command with netrc auth
CURL_CMD="curl -s --netrc $INSECURE -H 'Content-Type: application/json'"

# Query to get the most recent document
QUERY=$(cat <<EOF
{
  "size": 1,
  "sort": [
    {"${TIMESTAMP_FIELD}": {"order": "desc"}}
  ],
  "_source": ["${TIMESTAMP_FIELD}"]
}
EOF
)

[[ $VERBOSE -eq 1 ]] && echo "DEBUG: Querying $HOST/$INDEX/_search" >&2
[[ $VERBOSE -eq 1 ]] && echo "DEBUG: Query: $QUERY" >&2

# Execute query
RESPONSE=$(curl -s --netrc $INSECURE \
    -H 'Content-Type: application/json' \
    -X POST \
    --max-time 30 \
    "$HOST/$INDEX/_search" \
    -d "$QUERY" 2>&1)

CURL_EXIT=$?

if [[ $CURL_EXIT -ne 0 ]]; then
    echo "CRITICAL: Failed to query OpenSearch (curl exit code: $CURL_EXIT)"
    [[ $VERBOSE -eq 1 ]] && echo "DEBUG: Response: $RESPONSE" >&2
    exit $STATE_CRITICAL
fi

[[ $VERBOSE -eq 1 ]] && echo "DEBUG: Response: $RESPONSE" >&2

# Check for HTTP errors in response
if echo "$RESPONSE" | jq -e '.error' &> /dev/null; then
    ERROR_MSG=$(echo "$RESPONSE" | jq -r '.error.reason // .error.type // "Unknown error"')
    echo "CRITICAL: OpenSearch error: $ERROR_MSG"
    exit $STATE_CRITICAL
fi

# Extract the most recent document
HITS=$(echo "$RESPONSE" | jq -r '.hits.hits // []')

if [[ "$HITS" == "[]" ]]; then
    echo "CRITICAL: No documents found in index '$INDEX'"
    exit $STATE_CRITICAL
fi

# Extract timestamp
TIMESTAMP=$(echo "$RESPONSE" | jq -r ".hits.hits[0]._source.\"$TIMESTAMP_FIELD\" // empty")

if [[ -z "$TIMESTAMP" ]]; then
    echo "CRITICAL: Timestamp field '$TIMESTAMP_FIELD' not found in document"
    exit $STATE_CRITICAL
fi

[[ $VERBOSE -eq 1 ]] && echo "DEBUG: Latest timestamp: $TIMESTAMP" >&2

# Parse timestamp to epoch seconds
# Handle both with and without timezone
TIMESTAMP_CLEAN="${TIMESTAMP/Z/+00:00}"
TIMESTAMP_EPOCH=$(date -d "$TIMESTAMP_CLEAN" +%s 2>/dev/null)

if [[ -z "$TIMESTAMP_EPOCH" ]]; then
    echo "CRITICAL: Unable to parse timestamp: $TIMESTAMP"
    exit $STATE_CRITICAL
fi

# Calculate age
NOW_EPOCH=$(date +%s)
AGE_SECONDS=$((NOW_EPOCH - TIMESTAMP_EPOCH))

[[ $VERBOSE -eq 1 ]] && echo "DEBUG: Document age: $AGE_SECONDS seconds" >&2

# Format age for display
format_duration() {
    local seconds=$1
    if (( seconds < 60 )); then
        echo "${seconds}s"
    elif (( seconds < 3600 )); then
        echo "$((seconds / 60))m $((seconds % 60))s"
    elif (( seconds < 86400 )); then
        echo "$((seconds / 3600))h $(((seconds % 3600) / 60))m"
    else:
        echo "$((seconds / 86400))d $((seconds % 86400 / 3600))h"
    fi
}

AGE_FORMATTED=$(format_duration $AGE_SECONDS)
WARNING_FORMATTED=$(format_duration $WARNING)
CRITICAL_FORMATTED=$(format_duration $CRITICAL)

# Performance data for Nagios
PERFDATA="age=${AGE_SECONDS}s;${WARNING};${CRITICAL};0;"

# Check against thresholds
if (( AGE_SECONDS >= CRITICAL )); then
    echo "CRITICAL: No activity in '$INDEX' for $AGE_FORMATTED (threshold: $CRITICAL_FORMATTED) | $PERFDATA"
    exit $STATE_CRITICAL
elif (( AGE_SECONDS >= WARNING )); then
    echo "WARNING: No activity in '$INDEX' for $AGE_FORMATTED (threshold: $WARNING_FORMATTED) | $PERFDATA"
    exit $STATE_WARNING
else
    echo "OK: Index '$INDEX' has activity from $AGE_FORMATTED ago | $PERFDATA"
    exit $STATE_OK
fi
