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
import math
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

INF = float('inf')

# Used only when no threshold option at all is given
DEFAULT_WARNING = 3600
DEFAULT_CRITICAL = 7200

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


class Range:
    """
    A Nagios threshold range: N, N:, ~:N, M:N or @M:N.

    See https://www.monitoring-plugins.org/doc/guidelines.html#THRESHOLDFORMAT
    """

    def __init__(self, start=0, end=INF, inside=False):
        if not start <= end:  # also rejects NaN
            raise CheckError(STATE_UNKNOWN,
                             f"invalid threshold range {_number(start)}:{_number(end)}, start is above end")
        self.start = start
        self.end = end
        self.inside = inside

    @classmethod
    def parse(cls, spec):
        text = spec[1:] if spec.startswith('@') else spec
        start_text, colon, end_text = text.rpartition(':')
        try:
            start = -INF if start_text == '~' else float(start_text or 0)
            end = float(end_text) if end_text or not colon else INF
        except ValueError:
            raise CheckError(STATE_UNKNOWN, f"invalid threshold range '{spec}'") from None
        # Infinity is spelled "~" or an empty end, and ages are never negative,
        # so anything else would alert on every run or never
        explicit = [value for value, given in ((start, start_text), (end, end_text)) if given and given != '~']
        if not all(math.isfinite(value) for value in explicit) or end < 0:
            raise CheckError(STATE_UNKNOWN, f"invalid threshold range '{spec}'")
        return cls(start, end, inside=spec.startswith('@'))

    def alerts(self, value):
        """Whether value is outside the range (inside, for @M:N)."""
        outside = value < self.start or value > self.end
        return outside != self.inside

    def __str__(self):
        start = '~' if self.start == -INF else _number(self.start)
        if self.end == INF:
            text = f"{start}:"
        elif self.start == 0:
            text = _number(self.end)
        else:
            text = f"{start}:{_number(self.end)}"
        return ('@' if self.inside else '') + text


def _number(value):
    """Format a threshold number without a needless '.0'."""
    return str(int(value)) if float(value).is_integer() else str(value)


class PluginArgumentParser(argparse.ArgumentParser):
    """Reports usage errors as UNKNOWN; argparse's exit code 2 means CRITICAL to Nagios."""

    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"UNKNOWN: {message}")
        sys.exit(STATE_UNKNOWN)


def parse_args():
    """Parse command line arguments."""
    parser = PluginArgumentParser(
        description='Check OpenSearch index activity',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Thresholds:
  -w and -c take Nagios threshold ranges, applied to the age in seconds of the
  oldest of the --count newest documents.  If fewer documents are found, the
  age counts as infinite.
    N       alert if the age is above N (too little activity)
    N:      alert if the age is below N (too much activity, unwanted documents)
    M:N     alert if the age is below M or above N
    ~:N     same as N
    @M:N    alert if the age is between M and N
  Without any threshold option, -w 3600 -c 7200 is used.

Examples:
  %(prog)s -i logs-2024 -w 3600 -c 7200
    Warn if 'logs-2024' has had no activity for 1h, critical at 2h

  %(prog)s -i filebeat-* -w 300 -c 600 -t @timestamp
    Check 'filebeat-*' index with custom timestamp field

  %(prog)s -i my-logs-* --count 100 -w 30:180 -c 10:600
    Alert if 100 documents arrive in less than 30s/10s or take more than 3m/10m

  %(prog)s -i logs-* --filter '{"term": {"level.keyword": "ERROR"}}' -c 300:
    Alert CRITICAL if ERROR level logs were found in the last 5 minutes

  %(prog)s -i haproxy-* --filter '{"range": {"http_code": {"gte": 500}}}' --count 100 -w 1800: -c 300:
    WARNING if 100 HTTP 5xx errors were logged within 30 minutes, CRITICAL within 5
        """
    )

    parser.add_argument(
        '-i', '--index',
        required=True,
        help='OpenSearch index name or pattern (e.g., logs-*, filebeat-2024)'
    )

    parser.add_argument(
        '-w', '--warning',
        metavar='RANGE',
        help='Warning threshold for the age in seconds, as a Nagios range (see below). '
             'N alerts on ages above N, N: on ages below N.'
    )

    parser.add_argument(
        '-c', '--critical',
        metavar='RANGE',
        help='Critical threshold for the age in seconds, as a Nagios range (see below).'
    )

    parser.add_argument(
        '--min-warning',
        type=int,
        metavar='SECONDS',
        help='Lower bound of the warning range: --min-warning 30 -w 180 is the same as -w 30:180.'
    )

    parser.add_argument(
        '--min-critical',
        type=int,
        metavar='SECONDS',
        help='Lower bound of the critical range.'
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

    return parser.parse_args()


def threshold_range(spec, min_age, name):
    """The Range for -w/-c, with --min-warning/--min-critical as its lower bound."""
    if min_age is not None and min_age < 0:
        raise CheckError(STATE_UNKNOWN, f"--min-{name} must be >= 0")
    if spec is None:
        return None if min_age is None else Range(min_age)
    threshold = Range.parse(spec)
    if min_age is None:
        return threshold
    if threshold.inside or threshold.start != 0:
        raise CheckError(STATE_UNKNOWN, f"--min-{name} conflicts with the lower bound of --{name} {spec}")
    return Range(min_age, threshold.end)


def get_thresholds(args):
    """
    The (warning, critical) Ranges, None for a threshold that is not set.

    Raises CheckError(UNKNOWN) for combinations that can never return OK or WARNING.
    """
    if all(v is None for v in (args.warning, args.critical, args.min_warning, args.min_critical)):
        return Range(end=DEFAULT_WARNING), Range(end=DEFAULT_CRITICAL)

    warning = threshold_range(args.warning, args.min_warning, 'warning')
    critical = threshold_range(args.critical, args.min_critical, 'critical')

    if warning is not None and critical is not None and not (warning.inside or critical.inside):
        # Ages are never negative
        w_start, c_start = max(warning.start, 0), max(critical.start, 0)
        if max(w_start, c_start) > min(warning.end, critical.end):
            raise CheckError(STATE_UNKNOWN,
                             f"warning range {warning} and critical range {critical} leave no OK range")
        if w_start <= c_start and critical.end <= warning.end and (w_start, warning.end) != (c_start, critical.end):
            raise CheckError(STATE_UNKNOWN,
                             f"critical range {critical} lies within warning range {warning}, "
                             "so WARNING can never be returned")
    return warning, critical


def validate_args(args):
    """Raise CheckError(UNKNOWN) on invalid argument combinations."""
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
    the field's format or nesting.  Future timestamps (clock skew) count as 0.
    """
    value = (hit.get('sort') or [None])[0]
    if not isinstance(value, (int, float)) or value == MISSING_SORT_VALUE:
        return None
    return max(0, int(now - value / 1000))


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


def perfdata(newest_age, oldest_age, count, warning, critical):
    """
    Nagios performance data for the check result.

    Thresholds are attached to the value they are checked against: the oldest
    of the --count newest documents.
    """
    checked = f"{warning or ''};{critical or ''};0;"
    if count == 1:
        return f"age={oldest_age}s;{checked}"
    return f"age={newest_age}s;;;0; oldest_age={oldest_age}s;{checked}"


def evaluate(age, warning, critical):
    """(state, the Range that alerted or None) for an age; CRITICAL takes precedence."""
    for state, threshold in ((STATE_CRITICAL, critical), (STATE_WARNING, warning)):
        if threshold is not None and threshold.alerts(age):
            return state, threshold
    return STATE_OK, None


def check(args):
    """Run the check; return (state, message)."""
    validate_args(args)
    warning, critical = get_thresholds(args)
    filter_query = parse_filter(args.filter)

    username, password, netrc_path = get_credentials(args.host, args.netrc)
    context = ssl_context(args)

    if args.verbose:
        if netrc_path:
            print(f"DEBUG: Credentials found in {netrc_path}", file=sys.stderr)
        else:
            print("DEBUG: No credentials found in any netrc file", file=sys.stderr)
        print(f"DEBUG: Querying {args.host}/{args.index}", file=sys.stderr)
        print(f"DEBUG: Warning range: {warning}, critical range: {critical}", file=sys.stderr)
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

    # Fewer documents than --count: the Nth newest is infinitely old
    if len(documents) < args.count:
        state = evaluate(INF, warning, critical)[0]
        if not documents:
            return state, f"No documents found{filter_msg} in index '{args.index}'"
        return state, f"Only {len(documents)} document(s) found{filter_msg}, fewer than --count {args.count}"

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

    perf = perfdata(newest_age, oldest_age, args.count, warning, critical)
    newest_formatted = format_duration(newest_age)
    oldest_formatted = format_duration(oldest_age)
    state, violated = evaluate(oldest_age, warning, critical)

    if violated is None:
        if args.count > 1:
            return STATE_OK, (f"{args.count} documents{filter_msg}, newest: {newest_formatted}, "
                              f"oldest: {oldest_formatted} | {perf}")
        return STATE_OK, f"Index '{args.index}' has activity{filter_msg} from {newest_formatted} ago | {perf}"

    what = "newest document" if args.count == 1 else f"oldest of the {args.count} newest documents"
    what += filter_msg
    if violated.inside:
        return state, f"{what} is {oldest_formatted} old (alert range: {violated}) | {perf}"
    if oldest_age < violated.start:
        return state, (f"Excessive activity - {what} is only {oldest_formatted} old "
                       f"(minimum threshold: {format_duration(int(violated.start))}) | {perf}")
    return state, (f"Insufficient activity - {what} is {oldest_formatted} old "
                   f"(maximum threshold: {format_duration(int(violated.end))}) | {perf}")


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
