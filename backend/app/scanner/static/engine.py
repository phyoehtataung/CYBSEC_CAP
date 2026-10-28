from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from ...config import (
    ENABLE_EXTERNAL_SAST,
    LAB_SOURCES,
    STATIC_MAX_FILE_BYTES,
    STATIC_MAX_FILES,
    STATIC_MAX_FINDINGS,
)
from ..findings import ScanCancelled, make_finding, redact_evidence, stable_id
from .rules_js import JS_EXTENSIONS, JS_RULES
from .rules_php import (
    PHP_EXTENSIONS,
    PHP_RULES,
    php_taint_cmd_lines,
    php_taint_sql_lines,
)

SKIP_DIRS = {
    ".git",
    ".github",
    ".angular",
    ".venv",
    "venv",
    "node_modules",
    "bower_components",
    "dist",
    "build",
    "coverage",
    "vendor",
    "__pycache__",
    "tmp",
    "logs",
    "screenshots",
    "cypress",
    "test",
    "tests",
    "e2e",
    "ftp",
}

SKIP_SUFFIXES = {".min.js", ".map", ".lock", ".png", ".jpg", ".woff", ".woff2", ".svg"}


def _cancelled(flag) -> bool:
    return bool(flag and flag())


def iter_source_files(root: Path):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        for filename in filenames:
            path = Path(dirpath) / filename
            if path.suffix.lower() not in (JS_EXTENSIONS | PHP_EXTENSIONS):
                continue
            if any(str(path).endswith(suffix) for suffix in SKIP_SUFFIXES):
                continue
            try:
                if path.stat().st_size > STATIC_MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            count += 1
            if count > STATIC_MAX_FILES:
                return
            yield path


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _location(source_root: Path, path: Path, line_no: int) -> str:
    try:
        rel = path.relative_to(source_root).as_posix()
    except ValueError:
        rel = path.as_posix()
    return f"{rel}:{line_no}"


def _apply_regex_rules(text: str, path: Path, source_root: Path, rules, prefix: str) -> list[dict]:
    findings = []
    per_rule: dict[str, int] = {}
    for rule in rules:
        regex = re.compile(rule.pattern, rule.flags)
        for match in regex.finditer(text):
            taken = per_rule.get(rule.rule_id, 0)
            if taken >= 8:
                break
            line_no = _line_number(text, match.start())
            location = _location(source_root, path, line_no)
            line = text.splitlines()[line_no - 1] if line_no <= len(text.splitlines()) else match.group(0)
            findings.append(
                make_finding(
                    finding_id=stable_id(prefix, rule.rule_id, location),
                    title=rule.title,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    detection_type="static",
                    owasp_id=rule.owasp_id,
                    cwe=rule.cwe,
                    nist=rule.nist,
                    sans=rule.sans,
                    location=location,
                    description=rule.description,
                    recommendation=rule.recommendation,
                    evidence=redact_evidence(line),
                )
            )
            per_rule[rule.rule_id] = taken + 1
    return findings


def _stack_from_source(source_root: Path) -> list[dict]:
    stack: list[dict] = []
    package = source_root / "package.json"
    if package.exists():
        try:
            data = json.loads(package.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            data = {}
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        stack.append({"name": "Node.js", "version": None, "confidence": "high"})
        for name, label in (("express", "Express"), ("@angular/core", "Angular"), ("sequelize", "Sequelize")):
            if name in deps:
                stack.append({"name": label, "version": str(deps[name]).lstrip("^~"), "confidence": "high"})
    composer = source_root / "composer.json"
    if composer.exists() or any(source_root.glob("*.php")):
        stack.append({"name": "PHP", "version": None, "confidence": "high"})
    return stack


def _run_semgrep(source_root: Path) -> list[dict]:
    if not ENABLE_EXTERNAL_SAST or shutil.which("semgrep") is None:
        return []
    try:
        completed = subprocess.run(
            ["semgrep", "--config", "auto", "--json", "--quiet", str(source_root)],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        return []
    findings = []
    for item in payload.get("results", [])[:20]:
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        cwes = metadata.get("cwe") or []
        cwe = cwes[0] if isinstance(cwes, list) and cwes else (cwes if isinstance(cwes, str) else "CWE-1035")
        path = item.get("path") or ""
        line_no = (item.get("start") or {}).get("line") or 1
        location = f"{path}:{line_no}"
        findings.append(
            make_finding(
                finding_id=stable_id("STA", "SEMGREP", location),
                title=(extra.get("message") or "Semgrep rule matched")[:120],
                severity="medium",
                confidence="medium",
                detection_type="static",
                owasp_id="A06:2021",
                cwe=str(cwe).split(":")[0],
                nist="SA-11",
                sans=str(cwe).split(":")[0] if str(cwe).startswith("CWE-") else "CWE-1035",
                location=location,
                description="Supplemental finding from local semgrep (WEBSET_EXTERNAL_SAST=1).",
                recommendation="Review the matched code and apply the rule's suggested fix.",
                evidence=redact_evidence(extra.get("lines") or ""),
            )
        )
    return findings


def _run_bandit(source_root: Path) -> list[dict]:
    if not ENABLE_EXTERNAL_SAST or shutil.which("bandit") is None:
        return []
    py_files = list(source_root.rglob("*.py"))
    if not py_files:
        return []
    try:
        completed = subprocess.run(
            ["bandit", "-r", str(source_root), "-f", "json", "-q"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        return []
    findings = []
    for item in payload.get("results", [])[:15]:
        location = f"{item.get('filename')}:{item.get('line_number')}"
        findings.append(
            make_finding(
                finding_id=stable_id("STA", "BANDIT", location),
                title=(item.get("issue_text") or "Bandit issue")[:120],
                severity="medium",
                confidence="medium",
                detection_type="static",
                owasp_id="A06:2021",
                cwe=f"CWE-{item.get('issue_cwe', {}).get('id')}" if item.get("issue_cwe") else "CWE-1035",
                nist="SA-11",
                sans="CWE-1035",
                location=location,
                description="Supplemental finding from local bandit (WEBSET_EXTERNAL_SAST=1).",
                recommendation="Review the Python issue and apply a safe alternative.",
                evidence=redact_evidence(item.get("code") or ""),
            )
        )
    return findings


def run_static(target_id: str, *, progress=None, cancelled=None) -> dict:
    source_root = LAB_SOURCES.get(target_id)
    empty = {
        "ran": False,
        "findings": [],
        "files_scanned": 0,
        "source_dir": str(source_root) if source_root else None,
        "tech_stack": [],
        "notes": "",
    }
    if source_root is None:
        empty["notes"] = "No lab source mapping for this target; static analysis skipped."
        return empty
    if not source_root.exists():
        empty["notes"] = (
            f"Static analysis skipped: source tree not found at {source_root}. "
            "Run python scripts/fetch-lab-sources.py to clone Juice Shop and DVWA."
        )
        return empty

    if progress:
        progress(5, f"Walking source tree ({source_root.name})")

    findings: list[dict] = []
    files_scanned = 0
    paths = list(iter_source_files(source_root))
    total = max(1, len(paths))
    for index, path in enumerate(paths, 1):
        if _cancelled(cancelled):
            raise ScanCancelled()
        files_scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        suffix = path.suffix.lower()
        if suffix in JS_EXTENSIONS:
            findings.extend(_apply_regex_rules(text, path, source_root, JS_RULES, "STA"))
        elif suffix in PHP_EXTENSIONS:
            findings.extend(_apply_regex_rules(text, path, source_root, PHP_RULES, "STA"))
            for line_no, line in php_taint_sql_lines(text)[:6]:
                location = _location(source_root, path, line_no)
                findings.append(
                    make_finding(
                        finding_id=stable_id("STA", "SQLI", location),
                        title="SQL statement interpolates variables in a request-handling file",
                        severity="critical",
                        confidence="medium",
                        detection_type="static",
                        owasp_id="A03:2021",
                        cwe="CWE-89",
                        nist="SI-10",
                        sans="CWE-89",
                        location=location,
                        description=(
                            "This PHP file reads request data and builds SQL with string interpolation."
                        ),
                        recommendation="Switch to prepared statements with bound parameters.",
                        evidence=redact_evidence(line),
                    )
                )
            for line_no, line in php_taint_cmd_lines(text)[:6]:
                location = _location(source_root, path, line_no)
                findings.append(
                    make_finding(
                        finding_id=stable_id("STA", "CMDI", location),
                        title="OS command executed in a request-handling PHP file",
                        severity="critical",
                        confidence="medium",
                        detection_type="static",
                        owasp_id="A03:2021",
                        cwe="CWE-78",
                        nist="SI-10",
                        sans="CWE-78",
                        location=location,
                        description="This PHP file both reads request data and invokes a shell command.",
                        recommendation="Do not pass request data to system/exec. Use a fixed command array.",
                        evidence=redact_evidence(line),
                    )
                )
        if progress and index % 25 == 0:
            progress(int(5 + 80 * (index / total)), f"Static analysis {index}/{total} files")
        if len(findings) >= STATIC_MAX_FINDINGS:
            break

    if _cancelled(cancelled):
        raise ScanCancelled()
    findings.extend(_run_semgrep(source_root))
    findings.extend(_run_bandit(source_root))

    # Stable de-dupe by finding_id
    unique: dict[str, dict] = {}
    for item in findings:
        unique.setdefault(item["finding_id"], item)
    findings = list(unique.values())[:STATIC_MAX_FINDINGS]

    if progress:
        progress(100, f"Static analysis complete ({files_scanned} files)")
    return {
        "ran": True,
        "findings": findings,
        "files_scanned": files_scanned,
        "source_dir": str(source_root),
        "tech_stack": _stack_from_source(source_root),
        "notes": f"Static analysis scanned {files_scanned} source files under {source_root.name}.",
    }
