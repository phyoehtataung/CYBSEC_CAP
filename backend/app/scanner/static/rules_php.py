from __future__ import annotations

import re
from dataclasses import dataclass

PHP_EXTENSIONS = {".php", ".phtml", ".inc"}


@dataclass(frozen=True)
class PatternRule:
    rule_id: str
    title: str
    severity: str
    confidence: str
    cwe: str
    owasp_id: str
    nist: str
    sans: str
    description: str
    recommendation: str
    pattern: str
    flags: int = re.IGNORECASE | re.MULTILINE


PHP_RULES: list[PatternRule] = [
    PatternRule(
        rule_id="SQLI",
        title="SQL query interpolates request data",
        severity="critical",
        confidence="medium",
        cwe="CWE-89",
        owasp_id="A03:2021",
        nist="SI-10",
        sans="CWE-89",
        description=(
            "User input from $_GET/$_POST/$_REQUEST is concatenated into a SQL statement. "
            "That is a textbook SQL injection sink."
        ),
        recommendation="Use prepared statements with bound parameters. Do not interpolate request variables into SQL.",
        pattern=r"(mysql_query|mysqli_query|->query|->prepare)\s*\([^;]{0,200}\$_(GET|POST|REQUEST)",
    ),
    PatternRule(
        rule_id="XSS",
        title="Request data written to the response without encoding",
        severity="high",
        confidence="medium",
        cwe="CWE-79",
        owasp_id="A03:2021",
        nist="SI-10",
        sans="CWE-79",
        description="echo/print of request parameters is a reflected XSS sink unless the value is encoded first.",
        recommendation="Encode output for HTML (htmlspecialchars) or use a templating engine that encodes by default.",
        pattern=r"(echo|print)\s+[^;]{0,200}\$_(GET|POST|REQUEST|COOKIE)",
    ),
    PatternRule(
        rule_id="CMDI",
        title="OS command executed with request data",
        severity="critical",
        confidence="high",
        cwe="CWE-78",
        owasp_id="A03:2021",
        nist="SI-10",
        sans="CWE-78",
        description="system/exec/shell_exec/passthru is called with request input. That is command injection.",
        recommendation="Do not pass request data to a shell. If a binary must run, use a fixed argument list.",
        pattern=r"(system|exec|shell_exec|passthru|popen|proc_open)\s*\([^;]{0,200}\$_(GET|POST|REQUEST)",
    ),
    PatternRule(
        rule_id="LFI",
        title="File include uses request data",
        severity="critical",
        confidence="high",
        cwe="CWE-98",
        owasp_id="A01:2021",
        nist="AC-3",
        sans="CWE-98",
        description="include/require of $_GET/$_POST lets an attacker choose which file is executed (LFI/RFI).",
        recommendation="Map request values to an allow-list of filenames. Never concatenate raw input into include paths.",
        pattern=r"(include|require)(_once)?\s*\(?\s*['\"]?[^;]{0,80}\$_(GET|POST|REQUEST)",
    ),
    PatternRule(
        rule_id="MD5PASS",
        title="Password or token hashed with MD5",
        severity="medium",
        confidence="medium",
        cwe="CWE-328",
        owasp_id="A02:2021",
        nist="IA-5",
        sans="CWE-328",
        description="MD5 is not suitable for password storage. DVWA and similar labs still use it as a teaching flaw.",
        recommendation="Use password_hash()/password_verify() (bcrypt/argon2). Never store raw or MD5 passwords.",
        pattern=r"md5\s*\(\s*(\$_(POST|GET|REQUEST)\s*\[|\$pass|\$password|\$pwd)",
    ),
    PatternRule(
        rule_id="EXTRACT",
        title="extract() on request data",
        severity="high",
        confidence="high",
        cwe="CWE-621",
        owasp_id="A01:2021",
        nist="SI-10",
        sans="CWE-621",
        description="extract() of $_GET/$_POST overwrites local variables from attacker-controlled keys.",
        recommendation="Do not extract request arrays. Read named keys explicitly.",
        pattern=r"extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
    ),
    PatternRule(
        rule_id="UNSERIALIZE",
        title="unserialize() of request data",
        severity="critical",
        confidence="high",
        cwe="CWE-502",
        owasp_id="A08:2021",
        nist="SI-10",
        sans="CWE-502",
        description="Deserialising untrusted PHP objects can run gadget chains (PHP object injection).",
        recommendation="Prefer json_decode. If unserialize is required, restrict allowed classes and never feed it request data.",
        pattern=r"unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
    ),
]


def php_taint_sql_lines(text: str) -> list[tuple[int, str]]:
    """If the file reads request data, flag SQL lines that interpolate variables."""
    if not re.search(r"\$_(GET|POST|REQUEST)", text):
        return []
    hits = []
    for index, line in enumerate(text.splitlines(), 1):
        if re.search(r"(?i)\b(SELECT|INSERT|UPDATE|DELETE)\b", line) and re.search(
            r"\$\w+|'\s*\.|\"\s*\.", line
        ):
            hits.append((index, line))
    return hits


def php_taint_cmd_lines(text: str) -> list[tuple[int, str]]:
    if not re.search(r"\$_(GET|POST|REQUEST)", text):
        return []
    hits = []
    for index, line in enumerate(text.splitlines(), 1):
        if re.search(r"(?i)\b(system|exec|shell_exec|passthru|popen)\s*\(", line) and "$" in line:
            hits.append((index, line))
    return hits
