from __future__ import annotations

import httpx

from ..findings import ScanCancelled
from ..headers import SECURITY_HEADERS, fingerprint_from_headers
from .checks import analyse_pages, cors_finding, extra_paths_for
from .crawler import crawl, fetch
from .reflection import probe_reflections


def run_dynamic(target_url: str, target_id: str, *, progress=None, cancelled=None) -> dict:
    if progress:
        progress(5, "Crawling the local target")
    crawl_result = crawl(
        target_url,
        extra_paths=extra_paths_for(target_id),
        cancelled=cancelled,
        progress=lambda pct, msg: progress(int(5 + pct * 0.55), msg) if progress else None,
    )
    if cancelled and cancelled():
        raise ScanCancelled()

    pages = crawl_result["pages"]
    findings = analyse_pages(pages, start_url=crawl_result["start_url"]) if pages else []

    inspection = {
        "reachable": crawl_result["reachable"],
        "error": crawl_result["error"],
        "status_code": (crawl_result["homepage"] or {}).get("status_code") if crawl_result["homepage"] else None,
        "missing_headers": [],
        "tech_hints": [],
    }
    homepage = crawl_result["homepage"]
    if homepage:
        inspection["tech_hints"] = fingerprint_from_headers(
            {k.title(): v for k, v in (homepage.get("headers") or {}).items()}
        )
        present = homepage.get("headers") or {}
        inspection["missing_headers"] = [
            name for name in SECURITY_HEADERS if name.lower() not in present
        ]

    if crawl_result["reachable"]:
        if progress:
            progress(70, "Checking CORS reflection")
        try:
            with httpx.Client(timeout=4.0, follow_redirects=True) as client:
                response = fetch(
                    client,
                    crawl_result["start_url"],
                    extra_headers={"Origin": "http://webset-cors-test.localhost"},
                )
            if response is not None:
                cors = cors_finding(
                    crawl_result["start_url"],
                    {k.lower(): v for k, v in response.headers.items()},
                )
                if cors:
                    findings.append(cors)
        except httpx.RequestError:
            pass

        if progress:
            progress(80, "Submitting benign reflection canaries")
        findings.extend(probe_reflections(pages, cancelled=cancelled))

    notes = (
        f"Dynamic crawl visited {len(pages)} URL(s). No exploit payloads were sent."
        if crawl_result["reachable"]
        else f"Dynamic analysis skipped: {crawl_result.get('error') or 'no HTTP response'}."
    )
    if progress:
        progress(100, "Dynamic analysis complete" if crawl_result["reachable"] else "Target unreachable")
    return {
        "ran": bool(crawl_result["reachable"]),
        "findings": findings,
        "pages": len(pages),
        "notes": notes,
        "inspection": inspection,
        "tech_stack": inspection.get("tech_hints") or [],
    }
