from __future__ import annotations

import re
from dataclasses import dataclass

JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}


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
    flags: int = re.MULTILINE


JS_RULES: list[PatternRule] = [
    PatternRule(
        rule_id="SECRET",
        title="Hardcoded secret or JWT signing material",
        severity="high",
        confidence="medium",
        cwe="CWE-798",
        owasp_id="A07:2021",
        nist="IA-5",
        sans="CWE-798",
        description=(
            "A secret, private key, or JWT signing value appears to be embedded in source. "
            "Anyone with the client or repo can mint or forge tokens."
        ),
        recommendation=(
            "Load secrets from the environment or a secret manager. Use a high-entropy key, "
            "rotate it, and never commit private keys."
        ),
        pattern=(
            r"(?i)(jwtsecret|privatekey|secretorprivatekey|secret_key|api[_-]?key)\s*[:=]\s*['\"][^'\"]{6,}"
            r"|BEGIN (?:RSA |EC )?PRIVATE KEY"
        ),
        flags=re.MULTILINE,
    ),
    PatternRule(
        rule_id="EVAL",
        title="Dynamic code execution via eval or Function",
        severity="high",
        confidence="high",
        cwe="CWE-95",
        owasp_id="A03:2021",
        nist="SI-10",
        sans="CWE-95",
        description=(
            "eval() or new Function() executes a string as code. If any part of that string is "
            "attacker-controlled, this is remote code execution."
        ),
        recommendation="Remove eval/Function. Parse data with JSON.parse and keep executable code static.",
        pattern=r"(?<![\w$])eval\s*\(|new\s+Function\s*\(",
    ),
    PatternRule(
        rule_id="SQLI",
        title="SQL statement built with string concatenation or interpolation",
        severity="critical",
        confidence="medium",
        cwe="CWE-89",
        owasp_id="A03:2021",
        nist="SI-10",
        sans="CWE-89",
        description=(
            "A database query is constructed by concatenating or interpolating values into SQL. "
            "Untrusted input can change the query's meaning."
        ),
        recommendation="Use bound parameters or an ORM query builder. Never interpolate request data into SQL.",
        pattern=(
            r"(?i)(sequelize\.query|db\.query|connection\.query|knex\.raw)\s*\(\s*[`'\"].*(\$\{|\+)"
            r"|[`'\"]\s*(SELECT|INSERT|UPDATE|DELETE|DROP)\b[^`'\"\n]{0,180}(\$\{|\+\s*[\w.]+)"
        ),
    ),
    PatternRule(
        rule_id="CMDI",
        title="OS command invoked with interpolated input",
        severity="critical",
        confidence="medium",
        cwe="CWE-78",
        owasp_id="A03:2021",
        nist="SI-10",
        sans="CWE-78",
        description=(
            "child_process exec/spawn is called with a string that interpolates variables. "
            "That is the classic command-injection pattern."
        ),
        recommendation="Use execFile/spawn with a fixed argv array. Never pass a shell string built from request data.",
        pattern=r"(?i)(execSync|exec|spawnSync|spawn)\s*\(\s*[`'\"].*\$\{|(execSync|exec)\s*\(\s*[^)\n]*\+",
    ),
    PatternRule(
        rule_id="WEAKCRYPTO",
        title="Weak hash algorithm (MD5 or SHA-1)",
        severity="medium",
        confidence="high",
        cwe="CWE-328",
        owasp_id="A02:2021",
        nist="SC-13",
        sans="CWE-328",
        description="MD5 and SHA-1 are not acceptable for passwords or integrity protection.",
        recommendation="Use SHA-256+ for integrity and a dedicated KDF (Argon2, bcrypt, scrypt) for passwords.",
        pattern=r"(?i)createHash\s*\(\s*['\"](md5|sha1)['\"]|require\(\s*['\"]md5['\"]\s*\)",
    ),
    PatternRule(
        rule_id="TLSVERIFY",
        title="TLS certificate verification disabled",
        severity="high",
        confidence="high",
        cwe="CWE-295",
        owasp_id="A02:2021",
        nist="SC-8",
        sans="CWE-295",
        description="rejectUnauthorized: false accepts any certificate, enabling man-in-the-middle on HTTPS calls.",
        recommendation="Leave certificate verification enabled. Trust a specific CA bundle if you must use a lab CA.",
        pattern=r"rejectUnauthorized\s*:\s*false",
    ),
    PatternRule(
        rule_id="CORS",
        title="Permissive CORS origin allow-list",
        severity="medium",
        confidence="medium",
        cwe="CWE-942",
        owasp_id="A05:2021",
        nist="AC-3",
        sans="CWE-942",
        description="CORS is configured to allow any origin. Browser-based callers on other sites can read responses.",
        recommendation="Reflect only trusted origins. Avoid Access-Control-Allow-Origin: * on authenticated APIs.",
        pattern=r"(?i)origin\s*:\s*['\"]\*['\"]|Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*",
    ),
    PatternRule(
        rule_id="DOMXSS",
        title="Trusted-HTML bypass or unsafe innerHTML assignment",
        severity="high",
        confidence="medium",
        cwe="CWE-79",
        owasp_id="A03:2021",
        nist="SI-10",
        sans="CWE-79",
        description=(
            "The code bypasses Angular/React sanitisation or writes HTML from a string. "
            "That is a stored/DOM XSS sink if the string includes untrusted data."
        ),
        recommendation=(
            "Keep sanitisation enabled. Prefer textContent or framework bindings that encode by default."
        ),
        pattern=(
            r"dangerouslySetInnerHTML|bypassSecurityTrust(?:Html|Script|Url|ResourceUrl|Style)"
            r"|innerHTML\s*="
        ),
    ),
]
