#!/usr/bin/env python3
"""
Nagios/NRPE plugin to check OpenSearch index activity.

This plugin checks that an OpenSearch index has recent activity by verifying
the timestamp of the most recent document.

Exit codes:
  0 - OK: Index has recent activity
  1 - WARNING: No activity within warning threshold
  2 - CRITICAL: No activity within critical threshold or error
  3 - UNKNOWN: Invalid arguments or unexpected error

Author: Claude / Tobias Brox
License: MIT
Project home: https://github.com/tobixen/check-opensearch-index
Version: v0.4.0-dev0 (Will someone remember to keep this one up-to-date?)
"""

import sys
import argparse
import json
import netrc
from datetime import datetime, timezone, timedelta
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import ssl

# Nagios plugin exit codes
STATE_OK = 0
STATE_WARNING = 1
STATE_CRITICAL = 2
STATE_UNKNOWN = 3


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Check OpenSearch index activity',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Normal mode: Alert if index has NO recent activity
  %(prog)s -i logs-2024 -w 3600 -c 7200
    Check 'logs-2024' index, warn if no activity for 1h, critical at 2h

  %(prog)s -i filebeat-* -w 300 -c 600 -t @timestamp
    Check 'filebeat-*' index with custom timestamp field

  %(prog)s -i myindex -w 1800 -c 3600 -H https://opensearch.local:9200
    Check with custom OpenSearch URL

  # Reverse mode: Alert if critical messages ARE found
  %(prog)s -i logs-* --filter '{"term": {"level.keyword": "ERROR"}}' --min-critical 300 --reverse
    Alert CRITICAL if ERROR level logs found in last 5 minutes

  %(prog)s -i app-* --filter '{"query_string": {"query": "FATAL OR CRITICAL"}}' --min-warning 600 --reverse
    Alert WARNING if FATAL/CRITICAL messages found in last 10 minutes
        """
    )

    parser.add_argument(
        '-i', '--index',
        required=True,
        help='OpenSearch index name or pattern (e.g., logs-*, filebeat-2024)'
    )

    parser.add_argument(
        '-w', '--warning',
        type=int,
        default=3600,
        help='Maximum age warning threshold in seconds (default: 3600 = 1 hour). '
             'Alert if documents are OLDER than this.'
    )

    parser.add_argument(
        '-c', '--critical',
        type=int,
        default=7200,
        help='Maximum age critical threshold in seconds (default: 7200 = 2 hours). '
             'Alert if documents are OLDER than this.'
    )

    parser.add_argument(
        '--min-warning',
        type=int,
        help='Minimum age warning threshold in seconds. '
             'Alert if documents are NEWER than this (excessive activity).'
    )

    parser.add_argument(
        '--min-critical',
        type=int,
        help='Minimum age critical threshold in seconds. '
             'Alert if documents are NEWER than this (excessive activity).'
    )

    parser.add_argument(
        '-t', '--timestamp-field',
        default='@timestamp',
        help='Timestamp field name (default: @timestamp)'
    )

    parser.add_argument(
        '-H', '--host',
        default='https://localhost:9200',
        help='OpenSearch host URL (default: https://localhost:9200)'
    )

    parser.add_argument(
        '-k', '--insecure',
        action='store_true',
        help='Skip SSL certificate verification'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output for debugging'
    )

    parser.add_argument(
        '--count',
        type=int,
        default=1,
        help='Number of recent documents to check (default: 1). '
             'Fetches this many recent documents and checks that the oldest is within thresholds.'
    )

    parser.add_argument(
        '--filter',
        type=str,
        help='JSON filter query to apply (e.g., \'{"term": {"field.keyword": "value"}}\'). '
             'Will be wrapped in a bool filter. Multiple filters can be combined in a JSON array.'
    )

    parser.add_argument(
        '--netrc',
        type=str,
        help='Path to .netrc file for credentials (default: ~/.netrc, then /etc/nagios/netrc)'
    )

    parser.add_argument(
        '--reverse',
        action='store_true',
        help='Reverse logic: OK when no documents found, CRITICAL when documents found. '
             'Ignores max age (--warning, --critical). Requires --min-warning and/or --min-critical. '
             'Use with --filter to alert on presence of critical log messages.'
    )

    return parser.parse_args()


def get_credentials(host, netrc_file=None):
    """
    Get credentials from .netrc file for the given host.

    Args:
        host: The host URL to get credentials for
        netrc_file: Optional path to .netrc file (default: ~/.netrc, then /etc/nagios/netrc)

    Returns:
        tuple: (username, password) or (None, None) if not found
    """
    from pathlib import Path
    from urllib.parse import urlparse

    # Determine which netrc file to use
    if netrc_file:
        netrc_paths = [netrc_file]
    else:
        # Try ~/.netrc first, then /etc/nagios/netrc as fallback
        netrc_paths = [
            str(Path.home() / '.netrc'),
            '/etc/nagios/netrc'
        ]

    hostname = urlparse(host).hostname or 'localhost'

    for netrc_path in netrc_paths:
        try:
            nrc = netrc.netrc(netrc_path)
            auth = nrc.authenticators(hostname)

            if auth:
                return auth[0], auth[2]  # username, password
        except FileNotFoundError:
            # Try next path
            continue
        except netrc.NetrcParseError as e:
            print(f"UNKNOWN: Error parsing netrc file {netrc_path}: {e}")
            sys.exit(STATE_UNKNOWN)

    # No credentials found in any file
    return None, None


def query_latest_documents(host, index, timestamp_field, username, password, size=1, filter_query=None, insecure=False, verbose=False):
    """
    Query OpenSearch for the most recent documents in the index.

    Args:
        size: Number of documents to retrieve (default: 1)
        filter_query: Optional dict or list of dicts for filtering documents

    Returns:
        list: List of documents with timestamps, or empty list if no documents found
    """
    url = f"{host}/{index}/_search"

    # Query to get the most recent documents based on timestamp
    query = {
        "size": size,
        "sort": [
            {timestamp_field: {"order": "desc"}}
        ],
        "_source": [timestamp_field]
    }

    # Add filter if provided
    if filter_query:
        # Ensure filter_query is a list
        if isinstance(filter_query, dict):
            filters = [filter_query]
        else:
            filters = filter_query

        query["query"] = {
            "bool": {
                "filter": filters
            }
        }

    headers = {
        'Content-Type': 'application/json'
    }

    # Add basic auth if credentials available
    if username and password:
        import base64
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers['Authorization'] = f'Basic {credentials}'

    try:
        request = Request(
            url,
            data=json.dumps(query).encode('utf-8'),
            headers=headers,
            method='POST'
        )

        # Handle SSL verification
        context = None
        if insecure:
            context = ssl._create_unverified_context()

        with urlopen(request, context=context, timeout=30) as response:
            result = json.loads(response.read().decode('utf-8'))

            if verbose:
                print(f"DEBUG: Query response: {json.dumps(result, indent=2)}", file=sys.stderr)

            hits = result.get('hits', {}).get('hits', [])

            return hits

    except HTTPError as e:
        error_body = e.read().decode('utf-8', errors='ignore')
        print(f"CRITICAL: HTTP {e.code} error querying OpenSearch: {error_body}")
        sys.exit(STATE_CRITICAL)
    except URLError as e:
        print(f"CRITICAL: Connection error: {e.reason}")
        sys.exit(STATE_CRITICAL)
    except json.JSONDecodeError as e:
        print(f"CRITICAL: Invalid JSON response: {e}")
        sys.exit(STATE_CRITICAL)
    except Exception as e:
        print(f"UNKNOWN: Unexpected error: {e}")
        sys.exit(STATE_UNKNOWN)


def parse_timestamp(timestamp_str):
    """
    Parse ISO 8601 timestamp string to datetime object.

    Supports various formats including with/without microseconds and timezone.
    """
    # Common timestamp formats
    formats = [
        '%Y-%m-%dT%H:%M:%S.%fZ',      # 2024-01-01T12:00:00.123Z
        '%Y-%m-%dT%H:%M:%SZ',          # 2024-01-01T12:00:00Z
        '%Y-%m-%dT%H:%M:%S.%f%z',      # 2024-01-01T12:00:00.123+00:00
        '%Y-%m-%dT%H:%M:%S%z',         # 2024-01-01T12:00:00+00:00
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(timestamp_str, fmt)
            # Ensure timezone aware
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    # Fallback: try fromisoformat (Python 3.7+)
    try:
        return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
    except ValueError:
        return None


def format_duration(seconds):
    """Format seconds into human-readable duration."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    elif seconds < 86400:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"
    else:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        return f"{days}d {hours}h"


def main():
    """Main plugin execution."""
    args = parse_args()

    # In reverse mode, max age thresholds are ignored
    if not args.reverse:
        # Validate maximum age thresholds
        if args.critical < args.warning:
            print("UNKNOWN: --critical must be >= --warning")
            sys.exit(STATE_UNKNOWN)

        # Validate minimum age thresholds (if provided)
        if args.min_warning is not None and args.min_critical is not None:
            if args.min_critical > args.min_warning:
                print("UNKNOWN: --min-critical must be <= --min-warning")
                sys.exit(STATE_UNKNOWN)

        # Check for conflicting thresholds
        if args.min_warning is not None and args.min_warning >= args.warning:
            print("UNKNOWN: --min-warning must be < --warning (can't require both too old AND too new)")
            sys.exit(STATE_UNKNOWN)

        if args.min_critical is not None and args.min_critical >= args.critical:
            print("UNKNOWN: --min-critical must be < --critical (can't require both too old AND too new)")
            sys.exit(STATE_UNKNOWN)
    else:
        # In reverse mode, only min-age thresholds make sense and at least one is required
        if args.min_warning is None and args.min_critical is None:
            print("UNKNOWN: --reverse mode requires --min-warning and/or --min-critical")
            sys.exit(STATE_UNKNOWN)

        if args.min_warning is not None and args.min_critical is not None:
            if args.min_critical > args.min_warning:
                print("UNKNOWN: --min-critical must be <= --min-warning")
                sys.exit(STATE_UNKNOWN)

    # Validate count parameter
    if args.count < 1:
        print("UNKNOWN: --count must be >= 1")
        sys.exit(STATE_UNKNOWN)

    # Parse filter JSON if provided
    filter_query = None
    if args.filter:
        try:
            filter_query = json.loads(args.filter)
        except json.JSONDecodeError as e:
            print(f"UNKNOWN: Invalid JSON in --filter: {e}")
            sys.exit(STATE_UNKNOWN)

    # Get credentials
    username, password = get_credentials(args.host, args.netrc)

    if args.verbose:
        cred_status = "found" if username else "not found"
        netrc_location = args.netrc if args.netrc else "~/.netrc"
        print(f"DEBUG: Credentials {cred_status} in {netrc_location}", file=sys.stderr)
        print(f"DEBUG: Querying {args.host}/{args.index}", file=sys.stderr)
        if args.count > 1:
            print(f"DEBUG: Fetching {args.count} documents, all must be within thresholds", file=sys.stderr)
        if filter_query:
            print(f"DEBUG: Applying filter: {json.dumps(filter_query)}", file=sys.stderr)

    # Query for latest documents (fetch exactly count documents)
    documents = query_latest_documents(
        args.host,
        args.index,
        args.timestamp_field,
        username,
        password,
        args.count,
        filter_query,
        args.insecure,
        args.verbose
    )

    # Check if any documents found
    if not documents:
        if args.reverse:
            # In reverse mode, no documents is OK (no critical messages found)
            filter_msg = f" matching filter" if filter_query else ""
            print(f"OK: No documents found{filter_msg} in index '{args.index}'")
            sys.exit(STATE_OK)
        else:
            print(f"CRITICAL: No documents found in index '{args.index}'")
            sys.exit(STATE_CRITICAL)

    # Check if we got enough documents
    if len(documents) < args.count:
        if args.reverse:
            # In reverse mode, fewer documents than requested is OK
            filter_msg = f" matching filter" if filter_query else ""
            print(f"OK: Only {len(documents)} document(s) found{filter_msg} (requested {args.count})")
            sys.exit(STATE_OK)
        else:
            print(f"CRITICAL: Only {len(documents)} documents found, need {args.count}")
            sys.exit(STATE_CRITICAL)

    # Parse timestamps - only need newest (first) and oldest (last)
    now = datetime.now(timezone.utc)

    # Parse newest document (first in sorted results)
    newest_doc = documents[0]
    newest_timestamp_value = newest_doc.get('_source', {}).get(args.timestamp_field)

    if not newest_timestamp_value:
        print(f"CRITICAL: Timestamp field '{args.timestamp_field}' not found in newest document")
        sys.exit(STATE_CRITICAL)

    newest_time = parse_timestamp(newest_timestamp_value)
    if newest_time is None:
        print(f"CRITICAL: Unable to parse newest timestamp: {newest_timestamp_value}")
        sys.exit(STATE_CRITICAL)

    newest_age = int((now - newest_time).total_seconds())

    # Parse oldest document (last in sorted results)
    oldest_doc = documents[-1]
    oldest_timestamp_value = oldest_doc.get('_source', {}).get(args.timestamp_field)

    if not oldest_timestamp_value:
        print(f"CRITICAL: Timestamp field '{args.timestamp_field}' not found in oldest document")
        sys.exit(STATE_CRITICAL)

    oldest_time = parse_timestamp(oldest_timestamp_value)
    if oldest_time is None:
        print(f"CRITICAL: Unable to parse oldest timestamp: {oldest_timestamp_value}")
        sys.exit(STATE_CRITICAL)

    oldest_age = int((now - oldest_time).total_seconds())

    if args.verbose:
        print(f"DEBUG: Newest document age: {newest_age}s", file=sys.stderr)
        print(f"DEBUG: Oldest document age: {oldest_age}s", file=sys.stderr)
        print(f"DEBUG: Checked {len(documents)} documents", file=sys.stderr)

    # REVERSE MODE: Documents found is bad (critical messages detected)
    # Only check minimum age thresholds - documents must be newer than threshold to trigger alert
    if args.reverse:
        # Check CRITICAL threshold - documents newer than min-critical trigger CRITICAL
        if args.min_critical is not None and newest_age < args.min_critical:
            age_formatted = format_duration(newest_age)
            filter_msg = f" matching filter" if filter_query else ""
            perfdata = f"age={newest_age}s;;;0;"
            if args.count > 1:
                perfdata += f" count={len(documents)};;;0;"
            print(f"CRITICAL: Found {len(documents)} document(s){filter_msg}, newest is {age_formatted} old "
                  f"(< {format_duration(args.min_critical)}) | {perfdata}")
            sys.exit(STATE_CRITICAL)

        # Check WARNING threshold - documents newer than min-warning trigger WARNING
        if args.min_warning is not None and newest_age < args.min_warning:
            age_formatted = format_duration(newest_age)
            filter_msg = f" matching filter" if filter_query else ""
            perfdata = f"age={newest_age}s;;;0;"
            if args.count > 1:
                perfdata += f" count={len(documents)};;;0;"
            print(f"WARNING: Found {len(documents)} document(s){filter_msg}, newest is {age_formatted} old "
                  f"(< {format_duration(args.min_warning)}) | {perfdata}")
            sys.exit(STATE_WARNING)

        # Documents found but older than thresholds - OK (old critical messages are fine)
        age_formatted = format_duration(newest_age)
        filter_msg = f" matching filter" if filter_query else ""
        perfdata = f"age={newest_age}s;;;0;"
        if args.count > 1:
            perfdata += f" count={len(documents)};;;0;"
        print(f"OK: Found {len(documents)} document(s){filter_msg}, but newest is {age_formatted} old "
              f"(older than thresholds) | {perfdata}")
        sys.exit(STATE_OK)

    # NORMAL MODE: Check for activity issues
    # Check for excessive activity (minimum age thresholds) - CRITICAL takes precedence
    if args.min_critical is not None and oldest_age < args.min_critical:
        age_formatted = format_duration(oldest_age)
        perfdata = f"age={newest_age}s;{args.warning};{args.critical};0;"
        if args.count > 1:
            perfdata += f" oldest_age={oldest_age}s;{args.warning};{args.critical};0;"
        print(f"CRITICAL: Excessive activity - oldest of {args.count} documents is only {age_formatted} old "
              f"(minimum threshold: {format_duration(args.min_critical)}) | {perfdata}")
        sys.exit(STATE_CRITICAL)

    # Check for too little activity (maximum age thresholds) - CRITICAL
    if oldest_age >= args.critical:
        age_formatted = format_duration(oldest_age)
        perfdata = f"age={newest_age}s;{args.warning};{args.critical};0;"
        if args.count > 1:
            perfdata += f" oldest_age={oldest_age}s;{args.warning};{args.critical};0;"
        print(f"CRITICAL: Insufficient activity - oldest of {args.count} documents is {age_formatted} old "
              f"(maximum threshold: {format_duration(args.critical)}) | {perfdata}")
        sys.exit(STATE_CRITICAL)

    # Check for excessive activity (minimum age thresholds) - WARNING
    if args.min_warning is not None and oldest_age < args.min_warning:
        age_formatted = format_duration(oldest_age)
        perfdata = f"age={newest_age}s;{args.warning};{args.critical};0;"
        if args.count > 1:
            perfdata += f" oldest_age={oldest_age}s;{args.warning};{args.critical};0;"
        print(f"WARNING: Excessive activity - oldest of {args.count} documents is only {age_formatted} old "
              f"(minimum threshold: {format_duration(args.min_warning)}) | {perfdata}")
        sys.exit(STATE_WARNING)

    # Check for too little activity (maximum age thresholds) - WARNING
    if oldest_age >= args.warning:
        age_formatted = format_duration(oldest_age)
        perfdata = f"age={newest_age}s;{args.warning};{args.critical};0;"
        if args.count > 1:
            perfdata += f" oldest_age={oldest_age}s;{args.warning};{args.critical};0;"
        print(f"WARNING: Insufficient activity - oldest of {args.count} documents is {age_formatted} old "
              f"(maximum threshold: {format_duration(args.warning)}) | {perfdata}")
        sys.exit(STATE_WARNING)

    # All checks passed
    newest_formatted = format_duration(newest_age)
    oldest_formatted = format_duration(oldest_age)
    perfdata = f"age={newest_age}s;{args.warning};{args.critical};0;"

    if args.count > 1:
        perfdata += f" oldest_age={oldest_age}s;{args.warning};{args.critical};0;"
        print(f"OK: {args.count} documents, newest: {newest_formatted}, oldest: {oldest_formatted} | {perfdata}")
    else:
        print(f"OK: Index '{args.index}' has activity from {newest_formatted} ago | {perfdata}")
    sys.exit(STATE_OK)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("UNKNOWN: Plugin execution interrupted")
        sys.exit(STATE_UNKNOWN)
    except Exception as e:
        print(f"UNKNOWN: Unexpected error: {e}")
        sys.exit(STATE_UNKNOWN)
