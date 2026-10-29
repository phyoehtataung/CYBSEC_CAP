from pathlib import Path

from app.scanner.static.engine import run_static

FIXTURES = Path(__file__).parent / "fixtures"


def test_static_rules_match_known_sinks(monkeypatch, tmp_path):
    for name in ("sinks.js", "sinks.php"):
        (tmp_path / name).write_text((FIXTURES / name).read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(
        "app.scanner.static.engine.LAB_SOURCES",
        {"juice-shop": tmp_path},
    )

    result = run_static("juice-shop")
    assert result["ran"] is True
    cwes = {item["cwe"] for item in result["findings"]}
    assert {"CWE-89", "CWE-95", "CWE-79", "CWE-78", "CWE-798", "CWE-502"} <= cwes
    assert all(item["detection_type"] == "static" for item in result["findings"])


def test_static_clean_file_has_no_findings(monkeypatch, tmp_path):
    (tmp_path / "safe.js").write_text((FIXTURES / "safe.js").read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(
        "app.scanner.static.engine.LAB_SOURCES",
        {"juice-shop": tmp_path},
    )
    result = run_static("juice-shop")
    assert result["ran"] is True
    assert result["findings"] == []


def test_static_skips_missing_source():
    result = run_static("does-not-exist")
    assert result["ran"] is False
    assert result["findings"] == []
