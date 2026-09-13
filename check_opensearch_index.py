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
"""

import argparse
import base64
import json
import netrc
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

__version__ = "0.4.0.dev0"

SYSTEM_NETRC = '/etc/nagios/netrc'

# Nagios plugin exit codes
STATE_OK = 0
STATE_WARNING = 1
STATE_CRITICAL = 2
STATE_UNKNOWN = 3

STATE_NAMES = {
    STATE_OK: 'OK',
    STATE_WARNING: 'WARNING',
    STATE_CRITICAL: 'CRITICAL',
    STATE_UNKNOWN: 'UNKNOWN',
}

# Long.MIN_VALUE: the sort value OpenSearch gives a document lacking the sort field
MISSING_SORT_VALUE = -(2**63)


class CheckError(Exception):
    """Ends the check early with a Nagios state and a message."""

    def __init__(self, state, message):
        super().__init__(message)
        self.state = state
        self.message = message


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
        '--ca-file',
        help='CA certificate bundle (PEM) to verify the server certificate against'
    )

    parser.add_argument(
        '-V', '--version',
        action='version',
        version=f'%(prog)s {__version__}'
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


def validate_args(args):
    """Raise CheckError(UNKNOWN) on invalid argument combinations."""
    thresholds = {
        '--warning': args.warning,
        '--critical': args.critical,
        '--min-warning': args.min_warning,
        '--min-critical': args.min_critical,
    }
    for name, value in thresholds.items():
        if value is not None and value < 0:
            raise CheckError(STATE_UNKNOWN, f"{name} must be >= 0")

    if args.min_warning is not None and args.min_critical is not None:
        if args.min_critical > args.min_warning:
            raise CheckError(STATE_UNKNOWN, "--min-critical must be <= --min-warning")

    # In reverse mode, max age thresholds are ignored
    if not args.reverse:
        if args.critical < args.warning:
            raise CheckError(STATE_UNKNOWN, "--critical must be >= --warning")

        # Ages below a min threshold alert, ages from --warning up alert:
        # the OK range is [max(min thresholds), --warning)
        lowest_ok_age = max(
            (v for v in (args.min_warning, args.min_critical) if v is not None),
            default=0,
        )
        if lowest_ok_age >= args.warning:
            raise CheckError(STATE_UNKNOWN, "thresholds leave no OK range "
                             "(need --min-warning and --min-critical < --warning <= --critical)")
    elif args.min_warning is None and args.min_critical is None:
        # In reverse mode, only min-age thresholds make sense and at least one is required
        raise CheckError(STATE_UNKNOWN, "--reverse mode requires --min-warning and/or --min-critical")

    if args.count < 1:
        raise CheckError(STATE_UNKNOWN, "--count must be >= 1")

    if args.insecure and args.ca_file:
        raise CheckError(STATE_UNKNOWN, "--insecure and --ca-file are mutually exclusive")


def parse_filter(filter_json):
    """Parse the --filter JSON, or return None if no filter was given."""
    if not filter_json:
        return None
    try:
        return json.loads(filter_json)
    except json.JSONDecodeError as e:
        raise CheckError(STATE_UNKNOWN, f"Invalid JSON in --filter: {e}") from e


def get_credentials(host, netrc_file=None):
    """
    Get credentials from .netrc file for the given host.

    Args:
        host: The host URL to get credentials for
        netrc_file: Optional path to .netrc file (default: ~/.netrc, then /etc/nagios/netrc)

    Returns:
        tuple: (username, password, netrc_path) or (None, None, None) if not found
    """
    # Determine which netrc file to use
    if netrc_file:
        netrc_paths = [netrc_file]
    else:
        # Try ~/.netrc first, then /etc/nagios/netrc as fallback
        netrc_paths = [
            str(Path.home() / '.netrc'),
            SYSTEM_NETRC
        ]

    hostname = urlparse(host).hostname or 'localhost'

    for netrc_path in netrc_paths:
        try:
            nrc = netrc.netrc(netrc_path)
            auth = nrc.authenticators(hostname)

            if auth:
                return auth[0], auth[2], netrc_path  # username, password, source
        except FileNotFoundError:
            # Try next path
            continue
        except PermissionError as e:
            raise CheckError(STATE_UNKNOWN, f"Cannot read netrc file {netrc_path}: {e.strerror}") from e
        except netrc.NetrcParseError as e:
            raise CheckError(STATE_UNKNOWN, f"Error parsing netrc file {netrc_path}: {e}") from e

    # No credentials found in any file
    return None, None, None


def query_latest_documents(host, index, timestamp_field, username, password, size=1, filter_query=None, context=None, verbose=False):
    """
    Query OpenSearch for the most recent documents in the index.

    Args:
        size: Number of documents to retrieve (default: 1)
        filter_query: Optional dict or list of dicts for filtering documents
        context: Optional ssl.SSLContext for the connection

    Returns:
        list: List of documents with timestamps, or empty list if no documents found
    """
    # Index names may hold date math (<logs-{now/d}>), which must be URL-encoded
    url = f"{host.rstrip('/')}/{quote(index, safe='*,')}/_search"

    # Query to get the most recent documents based on timestamp.  The age is
    # read from the sort value (epoch millis), so _source is not needed.
    # unmapped_type: indices in a pattern lacking the field must not fail the search
    # numeric_type: date and date_nanos indices must sort on the same scale
    query = {
        "size": size,
        "sort": [
            {timestamp_field: {"order": "desc", "unmapped_type": "date", "numeric_type": "date"}}
        ],
        "_source": False
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
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers['Authorization'] = f'Basic {credentials}'

    try:
        request = Request(
            url,
            data=json.dumps(query).encode('utf-8'),
            headers=headers,
            method='POST'
        )

        with urlopen(request, context=context, timeout=30) as response:
            result = json.loads(response.read().decode('utf-8'))

            if verbose:
                print(f"DEBUG: Query response: {json.dumps(result, indent=2)}", file=sys.stderr)

            return result.get('hits', {}).get('hits', [])

    except HTTPError as e:
        error_body = e.read().decode('utf-8', errors='ignore')
        raise CheckError(STATE_CRITICAL, f"HTTP {e.code} error querying OpenSearch: {error_body}") from e
    except URLError as e:
        raise CheckError(STATE_CRITICAL, f"Connection error: {e.reason}") from e
    except OSError as e:
        # e.g. a socket timeout while reading the response
        raise CheckError(STATE_CRITICAL, f"Connection error: {e}") from e
    except json.JSONDecodeError as e:
        raise CheckError(STATE_CRITICAL, f"Invalid JSON response: {e}") from e


def ssl_context(args):
    """SSL context for the connection: default verification, a private CA, or none at all."""
    if args.insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    if args.ca_file:
        try:
            return ssl.create_default_context(cafile=args.ca_file)
        except OSError as e:
            raise CheckError(STATE_UNKNOWN, f"Cannot load --ca-file {args.ca_file}: {e}") from e
    return None


def document_age(hit, now):
    """
    Age in whole seconds of a search hit, or None if it lacks the timestamp field.

    OpenSearch returns the sort value of a date field as epoch millis, whatever
    the field's format or nesting.
    """
    value = (hit.get('sort') or [None])[0]
    if not isinstance(value, (int, float)) or value == MISSING_SORT_VALUE:
        return None
    return int(now - value / 1000)


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


def perfdata(args, newest_age, oldest_age, found):
    """
    Nagios performance data for the check result.

    Thresholds are attached to the value they are checked against: the oldest
    of the --count newest documents.  A min threshold becomes the lower bound
    of a Nagios range ("min:max", or "min:" in reverse mode).
    """
    def threshold(min_age, max_age):
        if min_age is None:
            return "" if max_age is None else f"{max_age}"
        return f"{min_age}:" if max_age is None else f"{min_age}:{max_age}"

    if args.reverse:
        checked = f"{threshold(args.min_warning, None)};{threshold(args.min_critical, None)};0;"
    else:
        checked = (f"{threshold(args.min_warning, args.warning)};"
                   f"{threshold(args.min_critical, args.critical)};0;")

    if args.count == 1:
        return f"age={oldest_age}s;{checked}"
    if args.reverse:
        return f"age={oldest_age}s;{checked} count={found};;;0;"
    return f"age={newest_age}s;;;0; oldest_age={oldest_age}s;{checked}"


def check(args):
    """Run the check; return (state, message)."""
    validate_args(args)
    filter_query = parse_filter(args.filter)

    username, password, netrc_path = get_credentials(args.host, args.netrc)
    context = ssl_context(args)

    if args.verbose:
        if netrc_path:
            print(f"DEBUG: Credentials found in {netrc_path}", file=sys.stderr)
        else:
            print("DEBUG: No credentials found in any netrc file", file=sys.stderr)
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
        context,
        args.verbose
    )

    filter_msg = " matching filter" if filter_query else ""

    # In reverse mode, no or too few documents is OK (no critical messages found)
    if not documents:
        if args.reverse:
            return STATE_OK, f"No documents found{filter_msg} in index '{args.index}'"
        return STATE_CRITICAL, f"No documents found in index '{args.index}'"

    if len(documents) < args.count:
        if args.reverse:
            return STATE_OK, f"Only {len(documents)} document(s) found{filter_msg} (requested {args.count})"
        return STATE_CRITICAL, f"Only {len(documents)} documents found, need {args.count}"

    now = datetime.now(timezone.utc).timestamp()
    ages = [document_age(hit, now) for hit in documents]

    # Documents lacking the field sort last
    if None in ages:
        position = "newest" if ages[0] is None else "oldest"
        return STATE_CRITICAL, f"Timestamp field '{args.timestamp_field}' not found in {position} document"

    if ages != sorted(ages):
        return STATE_UNKNOWN, f"OpenSearch returned documents out of order (ages: {ages})"

    newest_age = ages[0]
    oldest_age = ages[-1]

    if args.verbose:
        print(f"DEBUG: Newest document age: {newest_age}s", file=sys.stderr)
        print(f"DEBUG: Oldest document age: {oldest_age}s", file=sys.stderr)
        print(f"DEBUG: Checked {len(documents)} documents", file=sys.stderr)

    perf = perfdata(args, newest_age, oldest_age, len(documents))
    newest_formatted = format_duration(newest_age)
    oldest_formatted = format_duration(oldest_age)

    # REVERSE MODE: Documents found is bad (critical messages detected)
    # Only check minimum age thresholds - the oldest of the --count newest
    # documents must be newer than a threshold to trigger an alert
    if args.reverse:
        found = f"Found {len(documents)} document(s){filter_msg}"
        for state, min_age in ((STATE_CRITICAL, args.min_critical), (STATE_WARNING, args.min_warning)):
            if min_age is not None and oldest_age < min_age:
                return state, (f"{found}, oldest is {oldest_formatted} old "
                               f"(< {format_duration(min_age)}) | {perf}")
        # Documents found but older than thresholds - OK (old critical messages are fine)
        return STATE_OK, f"{found}, but oldest is {oldest_formatted} old (older than thresholds) | {perf}"

    # NORMAL MODE: too much activity (min age) or too little (max age);
    # CRITICAL takes precedence
    oldest_of = f"oldest of {args.count} documents is"
    for state, min_age, max_age in (
        (STATE_CRITICAL, args.min_critical, args.critical),
        (STATE_WARNING, args.min_warning, args.warning),
    ):
        if min_age is not None and oldest_age < min_age:
            return state, (f"Excessive activity - {oldest_of} only {oldest_formatted} old "
                           f"(minimum threshold: {format_duration(min_age)}) | {perf}")
        if oldest_age >= max_age:
            return state, (f"Insufficient activity - {oldest_of} {oldest_formatted} old "
                           f"(maximum threshold: {format_duration(max_age)}) | {perf}")

    if args.count > 1:
        return STATE_OK, f"{args.count} documents, newest: {newest_formatted}, oldest: {oldest_formatted} | {perf}"
    return STATE_OK, f"Index '{args.index}' has activity from {newest_formatted} ago | {perf}"


def main():
    """Main plugin execution."""
    args = parse_args()
    try:
        state, message = check(args)
    except CheckError as e:
        state, message = e.state, e.message
    print(f"{STATE_NAMES[state]}: {message}")
    sys.exit(state)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("UNKNOWN: Plugin execution interrupted")
        sys.exit(STATE_UNKNOWN)
    except Exception as e:
        print(f"UNKNOWN: Unexpected error: {e}")
        sys.exit(STATE_UNKNOWN)
