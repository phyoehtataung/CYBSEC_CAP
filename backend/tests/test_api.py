from datetime import datetime, timezone

from app.database import SessionLocal
from app.models import Case, Finding, Scan
from app.scanner.engine import build_scan_result


def _fake_result(**kwargs):
    return build_scan_result(
        scan_id=kwargs["scan_id"],
        case_id=kwargs["case_id"],
        target_name=kwargs["target_name"],
        target_url=kwargs["target_url"],
        started_at=datetime.now(timezone.utc),
        findings=[
            {
                "finding_id": "WEBSET-TEST-001",
                "title": "Security headers missing on the local target",
                "severity": "medium",
                "confidence": "high",
                "status": "open",
                "detection_type": "dynamic",
                "location": kwargs["target_url"],
                "cwe": "CWE-693",
                "owasp": {"id": "A05:2021", "name": "Security Misconfiguration"},
                "nist": "CM-6",
                "sans": "CWE-16",
                "description": "Fixture finding.",
                "evidence": "Missing headers: Content-Security-Policy",
                "recommendation": "Set the missing headers.",
            }
        ],
        tech_stack=[{"name": "Node.js", "confidence": "high", "version": None}],
        modes=["dynamic"],
        out_of_scope=["A04:2021 Insecure Design"],
        notes="mocked scan",
        live_check={
            "reachable": True,
            "status_code": 200,
            "error": None,
            "missing_headers": ["Content-Security-Policy"],
        },
    )


def test_health_and_targets(client):
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    targets = client.get("/api/targets")
    assert targets.status_code == 200
    urls = {item["url"] for item in targets.json()["targets"]}
    assert urls == {"http://localhost:3000", "http://localhost:8081"}


def test_create_case_persists(client):
    created = client.post(
        "/api/cases",
        json={
            "title": "Pytest audit",
            "application": "Juice Shop",
            "notes": "Created by the automated suite",
        },
    )
    assert created.status_code == 200
    body = created.json()
    assert body["case_id"].startswith("CASE-")
    assert body["title"] == "Pytest audit"
    assert body["application"] == "Juice Shop"

    again = client.get(f"/api/cases/{body['case_id']}")
    assert again.status_code == 200
    assert again.json()["notes"] == "Created by the automated suite"


def test_create_case_rejects_short_title(client):
    response = client.post(
        "/api/cases",
        json={"title": "No", "application": "Juice Shop"},
    )
    assert response.status_code == 422


def test_external_url_is_rejected(client):
    response = client.post(
        "/api/scans",
        json={
            "case_id": "CASE-2026-001",
            "target_name": "Google",
            "target_url": "https://google.com",
        },
    )
    assert response.status_code == 400
    assert "authorised local labs" in response.json()["detail"]


def test_scan_persists_mocked_findings(client, monkeypatch):
    monkeypatch.setattr("app.routers.scans.run_scan", _fake_result)
    created = client.post(
        "/api/cases",
        json={"title": "Scan persistence", "application": "Juice Shop"},
    )
    case_id = created.json()["case_id"]

    started = client.post(
        "/api/scans",
        json={
            "case_id": case_id,
            "target_id": "juice-shop",
            "target_name": "OWASP Juice Shop",
            "target_url": "http://localhost:3000",
        },
    )
    assert started.status_code == 200
    scan_id = started.json()["scan_id"]

    detail = client.get(f"/api/scans/{scan_id}")
    assert detail.status_code == 200
    payload = detail.json()
    assert payload["status"] == "completed"
    assert payload["live_check"]["reachable"] is True
    assert payload["findings"][0]["finding_id"] == "WEBSET-TEST-001"

    listed = client.get(f"/api/scans?case_id={case_id}")
    assert listed.json()["scans"][0]["scan_id"] == scan_id


def test_triage_updates_row_and_json(client):
    scans = client.get("/api/scans").json()["scans"]
    scan_id = next(item["scan_id"] for item in scans if item["target_url"] == "http://localhost:3000")
    detail = client.get(f"/api/scans/{scan_id}").json()
    finding_id = detail["findings"][0]["finding_id"]

    patched = client.patch(
        f"/api/scans/{scan_id}/findings/{finding_id}",
        json={"status": "false_positive"},
    )
    assert patched.status_code == 200
    assert patched.json()["status"] == "false_positive"

    stored = client.get(f"/api/scans/{scan_id}").json()
    match = next(item for item in stored["findings"] if item["finding_id"] == finding_id)
    assert match["status"] == "false_positive"

    with SessionLocal() as db:
        row = (
            db.query(Finding)
            .filter(Finding.scan_id == scan_id, Finding.finding_id == finding_id)
            .one()
        )
        assert row.status == "false_positive"


def test_delete_case_removes_scans(client):
    created = client.post(
        "/api/cases",
        json={"title": "Delete me", "application": "DVWA"},
    )
    case_id = created.json()["case_id"]
    with SessionLocal() as db:
        db.add(
            Scan(
                id="scn-delete-me",
                case_id=case_id,
                target_name="DVWA",
                target_url="http://localhost:8081",
                status="completed",
                progress=100,
                message="fixture",
            )
        )
        db.commit()

    deleted = client.delete(f"/api/cases/{case_id}")
    assert deleted.status_code == 200
    assert client.get(f"/api/cases/{case_id}").status_code == 404
    with SessionLocal() as db:
        assert db.get(Case, case_id) is None
        assert db.get(Scan, "scn-delete-me") is None


def test_cancel_queued_scan_marks_cancelled(client):
    created = client.post(
        "/api/cases",
        json={"title": "Cancel path", "application": "DVWA"},
    )
    case_id = created.json()["case_id"]
    with SessionLocal() as db:
        db.add(
            Scan(
                id="scn-cancel-me",
                case_id=case_id,
                target_name="DVWA",
                target_url="http://localhost:8081",
                status="running",
                progress=10,
                message="running",
            )
        )
        db.commit()

    response = client.post("/api/scans/scn-cancel-me/cancel")
    assert response.status_code == 200
    assert response.json()["message"] == "Cancellation requested"

    from app.routers.scans import _execute_scan

    _execute_scan(
        "scn-cancel-me",
        {"target_name": "DVWA", "target_url": "http://localhost:8081", "target_id": "dvwa"},
    )
    with SessionLocal() as db:
        assert db.get(Scan, "scn-cancel-me").status == "cancelled"


def test_report_export(client):
    scans = client.get("/api/scans").json()["scans"]
    scan_id = next(item["scan_id"] for item in scans if item["status"] == "completed")

    report_json = client.get(f"/api/scans/{scan_id}/report.json")
    assert report_json.status_code == 200
    assert "attachment" in report_json.headers["content-disposition"]
    body = report_json.json()
    assert body["scan_id"] == scan_id
    assert body["findings"]

    report_html = client.get(f"/api/scans/{scan_id}/report.html")
    assert report_html.status_code == 200
    assert "text/html" in report_html.headers["content-type"]
    assert body["findings"][0]["title"] in report_html.text
