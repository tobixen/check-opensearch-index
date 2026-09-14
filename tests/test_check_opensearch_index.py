import io
import json
import ssl
import sys
from datetime import datetime, timedelta, timezone

import pytest

import check_opensearch_index as plugin

OK, WARNING, CRITICAL, UNKNOWN = 0, 1, 2, 3
INF = float("inf")

LONG_MIN = -(2**63)  # sort value OpenSearch gives a document lacking the field


def make_hit(age):
    """A search hit for a document `age` seconds old, as OpenSearch returns it.

    With "_source": false only the sort value (epoch millis) is returned.
    """
    ts = datetime.now(timezone.utc) - timedelta(seconds=age)
    return {"_id": str(age), "sort": [int(ts.timestamp() * 1000)]}


def run(monkeypatch, capsys, argv, ages=(), hits=None, requests=None, response=io.BytesIO):
    """Run the plugin against a fake OpenSearch; return (exit code, stdout).

    Requests made are appended to `requests`, with the urlopen() keyword
    arguments as `request.urlopen_kwargs`.
    """
    if hits is None:
        hits = [make_hit(age) for age in ages]

    def fake_urlopen(request, **kwargs):
        request.urlopen_kwargs = kwargs
        if requests is not None:
            requests.append(request)
        size = json.loads(request.data)["size"]
        return response(json.dumps({"hits": {"hits": hits[:size]}}).encode())

    monkeypatch.setattr(plugin, "urlopen", fake_urlopen)
    monkeypatch.setattr(plugin, "get_credentials", lambda *a, **k: (None, None, None))
    monkeypatch.setattr(sys, "argv", ["check_opensearch_index.py", "-i", "idx", *argv])
    with pytest.raises(SystemExit) as exc:
        plugin.main()
    return exc.value.code, capsys.readouterr().out


@pytest.mark.parametrize(
    "spec, start, end, inside",
    [
        ("10", 0, 10, False),
        ("10:", 10, INF, False),
        ("~:10", -INF, 10, False),
        ("10:20", 10, 20, False),
        ("@10:20", 10, 20, True),
        ("1.5", 0, 1.5, False),
    ],
)
def test_range_parse(spec, start, end, inside):
    threshold = plugin.Range.parse(spec)
    assert (threshold.start, threshold.end, threshold.inside) == (start, end, inside)
    assert str(threshold) == spec


@pytest.mark.parametrize(
    "spec",
    [
        "abc", "10:5", "-5", "", "@", "1:2:3", "nan",
        # ages are never negative: these would alert on every run
        "~:-5", "-10:-5", "@~:-5",
        # infinity is only spelled "~" or an empty end
        "inf", "1e400", "infinity:", "-inf:10",
    ],
)
def test_range_parse_invalid(spec):
    with pytest.raises(plugin.CheckError) as exc:
        plugin.Range.parse(spec)
    assert exc.value.state == UNKNOWN


@pytest.mark.parametrize(
    "spec, value, alerts",
    [
        ("10", 5, False),
        ("10", 10, False),
        ("10", 11, True),
        ("10", INF, True),
        ("10:", 9, True),
        ("10:", 10, False),
        ("10:", INF, False),
        ("~:10", 0, False),
        ("~:10", 11, True),
        ("10:20", 9, True),
        ("10:20", 15, False),
        ("10:20", 21, True),
        ("@10:20", 9, False),
        ("@10:20", 10, True),
        ("@10:20", 20, True),
        ("@10:20", 21, False),
    ],
)
def test_range_alerts(spec, value, alerts):
    assert plugin.Range.parse(spec).alerts(value) is alerts


@pytest.mark.parametrize(
    "argv, ages, expected",
    [
        # defaults: -w 3600 -c 7200
        ([], [10], OK),
        ([], [5000], WARNING),
        ([], [10000], CRITICAL),
        # max age only
        (["-w", "100", "-c", "1000"], [10], OK),
        (["-w", "100", "-c", "1000"], [500], WARNING),
        (["-w", "100", "-c", "1000"], [5000], CRITICAL),
        (["-w", "100", "-c", "1000"], [], CRITICAL),
        # giving one threshold disables the defaults of the others
        (["-w", "100"], [5000], WARNING),
        (["-c", "1000"], [500], OK),
        # min and max age, as ranges and with --min-*
        (["-w", "50:100", "-c", "20:1000"], [10], CRITICAL),
        (["-w", "50:100", "-c", "20:1000"], [30], WARNING),
        (["-w", "50:100", "-c", "20:1000"], [70], OK),
        (["-w", "100", "-c", "1000", "--min-warning", "50", "--min-critical", "20"], [10], CRITICAL),
        (["-w", "100", "-c", "1000", "--min-warning", "50", "--min-critical", "20"], [30], WARNING),
        (["-w", "100", "-c", "1000", "--min-warning", "50", "--min-critical", "20"], [70], OK),
        # --count looks at the oldest of the N newest documents
        (["-w", "100", "-c", "1000", "--count", "3"], [1, 2, 500], WARNING),
        (["-w", "100", "-c", "1000", "--count", "3"], [1, 2, 50], OK),
        (["-w", "100", "-c", "1000", "--count", "3"], [1, 2], CRITICAL),
        (["-w", "100", "-c", "20:1000", "--count", "3"], [1, 2, 10], CRITICAL),
        # future timestamps (clock skew) count as age 0
        (["-w", "100", "-c", "1000"], [-5], OK),
        # alert inside a range
        (["-c", "@10:20"], [15], CRITICAL),
        (["-c", "@10:20"], [30], OK),
    ],
)
def test_thresholds(monkeypatch, capsys, argv, ages, expected):
    code, out = run(monkeypatch, capsys, argv, ages)
    assert code == expected, out


@pytest.mark.parametrize(
    "argv, ages, expected",
    [
        (["-c", "60:"], [], OK),
        (["-c", "60:"], [5], CRITICAL),
        (["-c", "60:"], [500], OK),
        (["-c", "60:", "--count", "3"], [1, 2, 3], CRITICAL),
        # a single new document must not trigger when --count asks for N
        (["-c", "60:", "--count", "3"], [1, 500, 600], OK),
        (["-c", "60:", "--count", "3"], [1, 2], OK),
        (["-c", "60:", "-w", "600:", "--count", "2"], [1, 300], WARNING),
        (["-c", "60:", "-w", "600:", "--count", "2"], [1, 30], CRITICAL),
        # the same with the older --min-* options
        (["--min-critical", "60", "--min-warning", "600", "--count", "2"], [1, 300], WARNING),
        (["--min-critical", "60", "--min-warning", "600"], [], OK),
    ],
)
def test_unwanted_documents(monkeypatch, capsys, argv, ages, expected):
    code, out = run(monkeypatch, capsys, argv, ages)
    assert code == expected, out


FILTER = ["--filter", '{"term": {"http_code": 500}}']


@pytest.mark.parametrize(
    "argv, ages, expected",
    [
        (["-c", "300:", "--count", "2", *FILTER], [1, 5],
         "CRITICAL: Excessive activity - oldest of the 2 newest documents matching filter is only 5s old "
         "(minimum threshold: 5m 0s) | "),
        (["-c", "300:", *FILTER], [], "OK: No documents found matching filter in index 'idx'"),
        (["-c", "300:", "--count", "2", *FILTER], [1],
         "OK: Only 1 document(s) found matching filter, fewer than --count 2"),
        (["-w", "100"], [500],
         "WARNING: Insufficient activity - newest document is 8m 20s old (maximum threshold: 1m 40s) | "),
        (["-c", "@10:20"], [15], "CRITICAL: newest document is 15s old (alert range: @10:20) | "),
    ],
)
def test_messages(monkeypatch, capsys, argv, ages, expected):
    code, out = run(monkeypatch, capsys, argv, ages)
    assert out.startswith(expected), out


@pytest.mark.parametrize(
    "argv",
    [
        # WARNING could never be returned
        ["-w", "600", "-c", "60"],
        ["--min-critical", "100", "--min-warning", "50"],
        # every age < 100 is CRITICAL, every age > 60 is WARNING: never OK
        ["-w", "60", "-c", "600", "--min-critical", "100"],
        ["-w", "-5", "-c", "600"],
        ["-w", "10:5"],
        ["-w", "60", "-c", "600", "--min-warning", "61"],
        ["-w", "600", "-c", "1200", "--min-warning", "-1"],
        ["--min-critical", "-1"],
        # two lower bounds
        ["-w", "1800:", "--min-warning", "60"],
        ["--count", "0"],
        ["--filter", "{not json"],
        ["-k", "--ca-file", "ca.pem"],
        # removed option; argparse errors must not exit 2, which Nagios reads as CRITICAL
        ["--reverse", "--min-critical", "60"],
        ["--no-such-option"],
        ["-w", "abc"],
    ],
)
def test_invalid_arguments(monkeypatch, capsys, argv):
    requests = []
    code, out = run(monkeypatch, capsys, argv, requests=requests)
    assert code == UNKNOWN, out
    assert out.startswith("UNKNOWN")
    assert not requests


def test_query_sorts_newest_first_on_sort_values(monkeypatch, capsys):
    requests = []
    run(monkeypatch, capsys, ["-t", "event.created", "--count", "5"], [1, 2, 3, 4, 5], requests=requests)
    (request,) = requests
    query = json.loads(request.data)
    assert query["size"] == 5
    assert query["_source"] is False
    assert query["sort"] == [
        {"event.created": {"order": "desc", "unmapped_type": "date", "numeric_type": "date"}}
    ]


def test_dotted_timestamp_field(monkeypatch, capsys):
    code, out = run(monkeypatch, capsys, ["-t", "event.created", "-w", "100", "-c", "1000"], [10])
    assert code == OK, out


def test_timestamp_field_missing(monkeypatch, capsys):
    hits = [make_hit(1), {"_id": "x", "sort": [LONG_MIN]}]
    code, out = run(monkeypatch, capsys, ["--count", "2"], hits=hits)
    assert code == CRITICAL, out
    assert "'@timestamp' not found" in out


def test_hits_out_of_order(monkeypatch, capsys):
    code, out = run(monkeypatch, capsys, ["--count", "2"], hits=[make_hit(500), make_hit(1)])
    assert code == UNKNOWN, out
    assert "out of order" in out


def test_valid_min_critical_below_warning(monkeypatch, capsys):
    code, out = run(monkeypatch, capsys, ["-w", "600", "-c", "1200", "--min-critical", "100"], [300])
    assert code == OK, out


@pytest.mark.parametrize(
    "argv, ages, expected",
    [
        ([], [30], "age=30s;3600;7200;0;"),
        (["-w", "100", "-c", "1000"], [10], "age=10s;100;1000;0;"),
        # thresholds go on the series they are applied to
        (["-w", "100", "-c", "1000", "--count", "3"], [1, 2, 50], "age=1s;;;0; oldest_age=50s;100;1000;0;"),
        (["-w", "100", "-c", "1000", "--min-warning", "50", "--min-critical", "20"], [70],
         "age=70s;50:100;20:1000;0;"),
        (["-w", "600:", "-c", "60:"], [5], "age=5s;600:;60:;0;"),
        (["--min-critical", "60", "--count", "2"], [5, 6], "age=5s;;;0; oldest_age=6s;;60:;0;"),
        (["-c", "~:100"], [30], "age=30s;;~:100;0;"),
        # no age, no perfdata
        (["-c", "60:"], [], None),
    ],
)
def test_perfdata(monkeypatch, capsys, argv, ages, expected):
    code, out = run(monkeypatch, capsys, argv, ages)
    if expected is None:
        assert " | " not in out
    else:
        assert out.rstrip("\n").split(" | ", 1)[1] == expected


def test_url_is_quoted_and_trailing_slash_dropped(monkeypatch, capsys):
    requests = []
    run(monkeypatch, capsys, ["-H", "https://os.example:9200/", "-i", "<logs-{now/d}>,other-*"], [1],
        requests=requests)
    assert requests[0].full_url == "https://os.example:9200/%3Clogs-%7Bnow%2Fd%7D%3E,other-*/_search"


def test_read_timeout_is_critical(monkeypatch, capsys):
    class TimingOut(io.BytesIO):
        def read(self, *args):
            raise TimeoutError("The read operation timed out")

    code, out = run(monkeypatch, capsys, [], [1], response=TimingOut)
    assert code == CRITICAL, out
    assert "timed out" in out


def test_insecure_disables_verification(monkeypatch, capsys):
    requests = []
    run(monkeypatch, capsys, ["-k"], [1], requests=requests)
    context = requests[0].urlopen_kwargs["context"]
    assert context.verify_mode == ssl.CERT_NONE
    assert not context.check_hostname


def test_ca_file_is_loaded(monkeypatch, capsys):
    cafiles = []
    real_create_default_context = ssl.create_default_context

    def fake_create_default_context(*args, cafile=None, **kwargs):
        cafiles.append(cafile)
        return real_create_default_context()

    monkeypatch.setattr(plugin.ssl, "create_default_context", fake_create_default_context)
    code, out = run(monkeypatch, capsys, ["--ca-file", "/etc/ssl/private-ca.pem"], [1])
    assert code == OK, out
    assert cafiles == ["/etc/ssl/private-ca.pem"]


def test_ca_file_missing(monkeypatch, capsys, tmp_path):
    code, out = run(monkeypatch, capsys, ["--ca-file", str(tmp_path / "missing.pem")], [1])
    assert code == UNKNOWN, out


def test_version(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["check_opensearch_index.py", "-V"])
    with pytest.raises(SystemExit) as exc:
        plugin.parse_args()
    assert exc.value.code == 0
    assert plugin.__version__ in capsys.readouterr().out


def write_netrc(tmp_path):
    path = tmp_path / "netrc"
    path.write_text("machine localhost\n  login monitoring\n  password secret\n")
    return str(path)


def test_get_credentials_reports_source(tmp_path):
    path = write_netrc(tmp_path)
    assert plugin.get_credentials("https://localhost:9200", path) == ("monitoring", "secret", path)


def test_get_credentials_falls_back_to_system_netrc(tmp_path, monkeypatch):
    monkeypatch.setattr(plugin.Path, "home", lambda: tmp_path / "nohome")
    path = write_netrc(tmp_path)
    monkeypatch.setattr(plugin, "SYSTEM_NETRC", path)
    assert plugin.get_credentials("https://localhost:9200") == ("monitoring", "secret", path)


def test_get_credentials_not_found(tmp_path):
    path = write_netrc(tmp_path)
    assert plugin.get_credentials("https://elsewhere:9200", path) == (None, None, None)


def test_get_credentials_unreadable(tmp_path, monkeypatch):
    def deny(path):
        raise PermissionError(13, "Permission denied", path)

    monkeypatch.setattr(plugin.netrc, "netrc", deny)
    with pytest.raises(plugin.CheckError) as exc:
        plugin.get_credentials("https://localhost:9200", str(tmp_path / "netrc"))
    assert exc.value.state == UNKNOWN
    assert "Permission denied" in exc.value.message
