import io
import json
import sys
from datetime import datetime, timedelta, timezone

import pytest

import check_opensearch_index as plugin

OK, WARNING, CRITICAL, UNKNOWN = 0, 1, 2, 3


def make_hit(age, field="@timestamp"):
    """A search hit for a document `age` seconds old, as OpenSearch returns it."""
    ts = datetime.now(timezone.utc) - timedelta(seconds=age)
    return {
        "_source": {field: ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"},
        "sort": [int(ts.timestamp() * 1000)],
    }


def run(monkeypatch, capsys, argv, ages=(), hits=None, requests=None):
    """Run the plugin against a fake OpenSearch; return (exit code, stdout)."""
    if hits is None:
        hits = [make_hit(age) for age in ages]

    def fake_urlopen(request, **kwargs):
        if requests is not None:
            requests.append(request)
        size = json.loads(request.data)["size"]
        return io.BytesIO(json.dumps({"hits": {"hits": hits[:size]}}).encode())

    monkeypatch.setattr(plugin, "urlopen", fake_urlopen)
    monkeypatch.setattr(plugin, "get_credentials", lambda *a, **k: (None, None))
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
    ],
)
def test_invalid_arguments(monkeypatch, capsys, argv):
    requests = []
    code, out = run(monkeypatch, capsys, argv, requests=requests)
    assert code == UNKNOWN, out
    assert out.startswith("UNKNOWN")
    assert not requests


def test_valid_min_critical_below_warning(monkeypatch, capsys):
    code, out = run(monkeypatch, capsys, ["-w", "600", "-c", "1200", "--min-critical", "100"], [300])
    assert code == OK, out
