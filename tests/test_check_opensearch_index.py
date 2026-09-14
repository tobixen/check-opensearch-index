import io
import json
import ssl
import sys
from datetime import datetime, timedelta, timezone

import pytest

import check_opensearch_index as plugin

OK, WARNING, CRITICAL, UNKNOWN = 0, 1, 2, 3


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
    "argv, ages, expected",
    [
        # max age only
        (["-w", "100", "-c", "1000"], [10], OK),
        (["-w", "100", "-c", "1000"], [500], WARNING),
        (["-w", "100", "-c", "1000"], [5000], CRITICAL),
        (["-w", "100", "-c", "1000"], [], CRITICAL),
        # min and max age
        (["-w", "100", "-c", "1000", "--min-warning", "50", "--min-critical", "20"], [10], CRITICAL),
        (["-w", "100", "-c", "1000", "--min-warning", "50", "--min-critical", "20"], [30], WARNING),
        (["-w", "100", "-c", "1000", "--min-warning", "50", "--min-critical", "20"], [70], OK),
        # --count looks at the oldest of the N newest documents
        (["-w", "100", "-c", "1000", "--count", "3"], [1, 2, 500], WARNING),
        (["-w", "100", "-c", "1000", "--count", "3"], [1, 2, 50], OK),
        (["-w", "100", "-c", "1000", "--count", "3"], [1, 2], CRITICAL),
        (["-w", "100", "-c", "1000", "--count", "3", "--min-critical", "20"], [1, 2, 10], CRITICAL),
    ],
)
def test_normal_mode_thresholds(monkeypatch, capsys, argv, ages, expected):
    code, out = run(monkeypatch, capsys, argv, ages)
    assert code == expected, out


@pytest.mark.parametrize(
    "argv, ages, expected",
    [
        (["--min-critical", "60"], [], OK),
        (["--min-critical", "60"], [5], CRITICAL),
        (["--min-critical", "60"], [500], OK),
        (["--min-critical", "60", "--count", "3"], [1, 2, 3], CRITICAL),
        # a single new document must not trigger when --count asks for N
        (["--min-critical", "60", "--count", "3"], [1, 500, 600], OK),
        (["--min-critical", "60", "--count", "3"], [1, 2], OK),
        (["--min-critical", "60", "--min-warning", "600", "--count", "2"], [1, 300], WARNING),
        (["--min-critical", "60", "--min-warning", "600", "--count", "2"], [1, 30], CRITICAL),
    ],
)
def test_reverse_mode_thresholds(monkeypatch, capsys, argv, ages, expected):
    code, out = run(monkeypatch, capsys, ["--reverse", *argv], ages)
    assert code == expected, out


@pytest.mark.parametrize(
    "argv",
    [
        ["-w", "600", "-c", "60"],
        ["-w", "-5", "-c", "600"],
        ["-w", "60", "-c", "600", "--min-warning", "60"],
        # every age < 100 is CRITICAL, every age >= 100 is WARNING: never OK
        ["-w", "60", "-c", "600", "--min-critical", "100"],
        ["-w", "600", "-c", "1200", "--min-critical", "100", "--min-warning", "50"],
        ["-w", "600", "-c", "1200", "--min-warning", "-1"],
        ["--count", "0"],
        ["--reverse"],
        ["--reverse", "--min-critical", "-1"],
        ["--reverse", "--min-critical", "100", "--min-warning", "50"],
        ["--filter", "{not json"],
        ["-k", "--ca-file", "ca.pem"],
        # argparse errors must not exit 2, which Nagios reads as CRITICAL
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
        (["-w", "100", "-c", "1000"], [10], "age=10s;100;1000;0;"),
        # thresholds go on the series they are applied to
        (["-w", "100", "-c", "1000", "--count", "3"], [1, 2, 50], "age=1s;;;0; oldest_age=50s;100;1000;0;"),
        (["-w", "100", "-c", "1000", "--min-warning", "50", "--min-critical", "20"], [70],
         "age=70s;50:100;20:1000;0;"),
        (["--reverse", "--min-critical", "60", "--min-warning", "600"], [5], "age=5s;600:;60:;0;"),
        (["--reverse", "--min-critical", "60", "--count", "2"], [5, 6], "age=6s;;60:;0; count=2;;;0;"),
    ],
)
def test_perfdata(monkeypatch, capsys, argv, ages, expected):
    code, out = run(monkeypatch, capsys, argv, ages)
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
