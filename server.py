"""
Cybersecurity AI MCP Server - Security Intelligence Tools
Built by MEOK AI Labs | https://meok.ai

Vulnerability classification, CVE lookup, security header checking,
password strength analysis, and threat model generation.
"""

import time
import hashlib
import math
import re
from datetime import datetime, timezone
from typing import Optional

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "cybersecurity-ai",
    version="1.0.0",
    description="Cybersecurity AI - vulnerability classification, CVE lookup, headers, passwords, threat modeling",
)

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
_RATE_LIMITS = {"free": {"requests_per_hour": 60}, "pro": {"requests_per_hour": 5000}}
_request_log: list[float] = []
_tier = "free"


def _check_rate_limit() -> bool:
    now = time.time()
    _request_log[:] = [t for t in _request_log if now - t < 3600]
    if len(_request_log) >= _RATE_LIMITS[_tier]["requests_per_hour"]:
        return False
    _request_log.append(now)
    return True


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------
_VULN_CATEGORIES: dict[str, dict] = {
    "injection": {
        "cwes": ["CWE-89", "CWE-78", "CWE-79", "CWE-77", "CWE-94"],
        "owasp": "A03:2021 - Injection",
        "severity_default": "high",
        "description": "Untrusted data sent to an interpreter as part of a command or query",
        "mitigations": ["Use parameterized queries", "Input validation and sanitization", "Use ORMs", "Apply least privilege to DB accounts", "WAF rules"],
    },
    "broken_auth": {
        "cwes": ["CWE-287", "CWE-384", "CWE-613"],
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "severity_default": "critical",
        "description": "Authentication or session management flaws allowing identity compromise",
        "mitigations": ["Implement MFA", "Use strong password policies", "Rate limit login attempts", "Secure session management", "Use proven auth frameworks"],
    },
    "sensitive_data": {
        "cwes": ["CWE-311", "CWE-312", "CWE-319"],
        "owasp": "A02:2021 - Cryptographic Failures",
        "severity_default": "high",
        "description": "Sensitive data exposed due to weak or missing encryption",
        "mitigations": ["Encrypt data at rest and in transit", "Use TLS 1.3", "Don't store sensitive data unnecessarily", "Use strong key management", "Classify data sensitivity"],
    },
    "xxe": {
        "cwes": ["CWE-611"],
        "owasp": "A05:2021 - Security Misconfiguration",
        "severity_default": "high",
        "description": "XML External Entities processing allowing SSRF, file disclosure, DoS",
        "mitigations": ["Disable DTD processing", "Use JSON instead of XML", "Patch XML processors", "Input validation", "Use SAST tools"],
    },
    "broken_access": {
        "cwes": ["CWE-200", "CWE-284", "CWE-285", "CWE-639"],
        "owasp": "A01:2021 - Broken Access Control",
        "severity_default": "critical",
        "description": "Users can act outside their intended permissions",
        "mitigations": ["Deny by default", "Implement RBAC", "Disable directory listing", "Log access control failures", "Rate limit API access"],
    },
    "misconfig": {
        "cwes": ["CWE-16", "CWE-2"],
        "owasp": "A05:2021 - Security Misconfiguration",
        "severity_default": "medium",
        "description": "Missing security hardening, default configs, unnecessary features enabled",
        "mitigations": ["Automated hardening process", "Remove unused features", "Review cloud permissions", "Security headers", "Regular config audits"],
    },
    "xss": {
        "cwes": ["CWE-79"],
        "owasp": "A03:2021 - Injection",
        "severity_default": "medium",
        "description": "Cross-site scripting allows execution of scripts in victim's browser",
        "mitigations": ["Context-aware output encoding", "Content Security Policy", "Use modern frameworks with auto-escaping", "Sanitize HTML input", "HTTPOnly cookies"],
    },
    "deserialization": {
        "cwes": ["CWE-502"],
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "severity_default": "high",
        "description": "Insecure deserialization leading to RCE, injection, or privilege escalation",
        "mitigations": ["Don't accept serialized objects from untrusted sources", "Use simple data formats (JSON)", "Implement integrity checks", "Isolate deserialization code", "Log deserialization exceptions"],
    },
}

_CVE_DB: dict[str, dict] = {
    "CVE-2024-3094": {"product": "xz-utils", "severity": "critical", "cvss": 10.0, "type": "supply_chain_backdoor", "affected_versions": "5.6.0, 5.6.1", "description": "Malicious backdoor in xz/liblzma compromising SSH authentication", "fix": "Downgrade to 5.4.x or update to patched version", "published": "2024-03-29"},
    "CVE-2023-44487": {"product": "HTTP/2", "severity": "high", "cvss": 7.5, "type": "denial_of_service", "affected_versions": "Multiple HTTP/2 implementations", "description": "Rapid Reset attack allowing DoS against HTTP/2 servers", "fix": "Apply vendor-specific patches, rate limit RST_STREAM frames", "published": "2023-10-10"},
    "CVE-2024-21762": {"product": "Fortinet FortiOS", "severity": "critical", "cvss": 9.8, "type": "remote_code_execution", "affected_versions": "FortiOS 7.4.0-7.4.2, 7.2.0-7.2.6, 7.0.0-7.0.13", "description": "Out-of-bounds write in FortiOS SSL VPN allowing RCE", "fix": "Upgrade to fixed FortiOS version", "published": "2024-02-08"},
    "CVE-2023-4966": {"product": "Citrix NetScaler", "severity": "critical", "cvss": 9.4, "type": "information_disclosure", "affected_versions": "NetScaler ADC and Gateway before 14.1-8.50", "description": "Sensitive information disclosure (Citrix Bleed)", "fix": "Apply Citrix security update, kill active sessions", "published": "2023-10-10"},
    "CVE-2024-0204": {"product": "GoAnywhere MFT", "severity": "critical", "cvss": 9.8, "type": "authentication_bypass", "affected_versions": "Before 7.4.1", "description": "Authentication bypass allowing admin account creation", "fix": "Upgrade to 7.4.1+, delete unauthorized admin accounts", "published": "2024-01-22"},
    "CVE-2023-36884": {"product": "Microsoft Office/Windows", "severity": "high", "cvss": 8.3, "type": "remote_code_execution", "affected_versions": "Multiple Windows and Office versions", "description": "HTML remote code execution via crafted Office documents", "fix": "Apply Microsoft security updates", "published": "2023-07-11"},
}

_SECURITY_HEADERS: dict[str, dict] = {
    "Strict-Transport-Security": {"importance": "critical", "recommended": "max-age=63072000; includeSubDomains; preload", "description": "Forces HTTPS connections"},
    "Content-Security-Policy": {"importance": "critical", "recommended": "default-src 'self'; script-src 'self'", "description": "Prevents XSS and data injection"},
    "X-Content-Type-Options": {"importance": "high", "recommended": "nosniff", "description": "Prevents MIME type sniffing"},
    "X-Frame-Options": {"importance": "high", "recommended": "DENY", "description": "Prevents clickjacking"},
    "X-XSS-Protection": {"importance": "medium", "recommended": "0", "description": "Disable (CSP is preferred); legacy browsers only"},
    "Referrer-Policy": {"importance": "medium", "recommended": "strict-origin-when-cross-origin", "description": "Controls referrer information"},
    "Permissions-Policy": {"importance": "medium", "recommended": "camera=(), microphone=(), geolocation=()", "description": "Restricts browser feature access"},
    "Cross-Origin-Opener-Policy": {"importance": "medium", "recommended": "same-origin", "description": "Isolates browsing context"},
    "Cross-Origin-Resource-Policy": {"importance": "medium", "recommended": "same-origin", "description": "Prevents cross-origin resource loading"},
}

_COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "password1",
    "iloveyou", "1234567", "sunshine", "princess", "admin", "welcome",
    "monkey", "dragon", "master", "letmein", "login", "football",
    "shadow", "trustno1", "baseball", "superman", "michael", "computer",
}


@mcp.tool()
def classify_vulnerability(
    description: str,
    affected_component: str = "",
    has_exploit: bool = False,
    network_accessible: bool = True,
    auth_required: bool = False,
) -> dict:
    """Classify a vulnerability by type, severity, and OWASP category.

    Args:
        description: Description of the vulnerability.
        affected_component: Component or service affected.
        has_exploit: Whether a known exploit exists.
        network_accessible: Whether the vuln is network-accessible.
        auth_required: Whether authentication is required to exploit.
    """
    if not _check_rate_limit():
        return {"error": "Rate limit exceeded. Upgrade to pro tier."}

    desc_lower = description.lower()

    # Match category by keywords
    keyword_map = {
        "injection": ["sql injection", "command injection", "inject", "sqli", "os command"],
        "xss": ["xss", "cross-site scripting", "script injection", "reflected", "stored xss"],
        "broken_auth": ["authentication bypass", "session", "credential", "login bypass", "brute force", "password"],
        "sensitive_data": ["data leak", "exposure", "plaintext", "unencrypted", "pii", "sensitive"],
        "broken_access": ["access control", "idor", "privilege escalation", "unauthorized", "permission"],
        "misconfig": ["misconfigur", "default password", "debug mode", "directory listing", "verbose error"],
        "xxe": ["xxe", "xml external", "dtd", "xml injection"],
        "deserialization": ["deserializ", "pickle", "marshal", "object injection"],
    }

    best_cat = "misconfig"
    best_score = 0
    for cat, keywords in keyword_map.items():
        score = sum(1 for kw in keywords if kw in desc_lower)
        if score > best_score:
            best_score = score
            best_cat = cat

    vuln_info = _VULN_CATEGORIES[best_cat]

    # CVSS-like scoring
    base_score = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 3.0}[vuln_info["severity_default"]]
    if has_exploit:
        base_score = min(10.0, base_score + 1.0)
    if network_accessible:
        base_score = min(10.0, base_score + 0.5)
    if not auth_required:
        base_score = min(10.0, base_score + 0.5)

    severity = "critical" if base_score >= 9.0 else "high" if base_score >= 7.0 else "medium" if base_score >= 4.0 else "low"

    return {
        "classification": {
            "category": best_cat,
            "owasp": vuln_info["owasp"],
            "cwes": vuln_info["cwes"],
            "severity": severity,
            "cvss_estimate": round(base_score, 1),
        },
        "description": vuln_info["description"],
        "affected_component": affected_component,
        "exploit_available": has_exploit,
        "attack_vector": "network" if network_accessible else "local",
        "authentication_required": auth_required,
        "mitigations": vuln_info["mitigations"],
        "priority": "P1 - Fix immediately" if severity == "critical" else "P2 - Fix this sprint" if severity == "high" else "P3 - Planned fix" if severity == "medium" else "P4 - Backlog",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@mcp.tool()
def lookup_cve(
    cve_id: Optional[str] = None,
    product: Optional[str] = None,
    severity: Optional[str] = None,
) -> dict:
    """Look up CVE details from the vulnerability database.

    Args:
        cve_id: Specific CVE identifier (e.g. CVE-2024-3094).
        product: Product name to search for.
        severity: Filter by severity (critical|high|medium|low).
    """
    if not _check_rate_limit():
        return {"error": "Rate limit exceeded. Upgrade to pro tier."}

    results = []

    if cve_id:
        cve = _CVE_DB.get(cve_id.upper())
        if cve:
            results.append({"cve_id": cve_id.upper(), **cve})
        else:
            return {"error": f"CVE {cve_id} not found in database.", "note": "This is a demo database with select high-profile CVEs."}
    else:
        for cid, cve in _CVE_DB.items():
            if product and product.lower() not in cve["product"].lower():
                continue
            if severity and cve["severity"] != severity.lower():
                continue
            results.append({"cve_id": cid, **cve})

    results.sort(key=lambda c: c.get("cvss", 0), reverse=True)

    return {
        "results": results,
        "count": len(results),
        "note": "Demo database with select high-profile CVEs. Use NVD API for comprehensive data.",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@mcp.tool()
def check_security_headers(
    headers: dict,
) -> dict:
    """Analyze HTTP security headers against best practices.

    Args:
        headers: Dict of HTTP response headers. Example: {"Strict-Transport-Security": "max-age=31536000"}.
    """
    if not _check_rate_limit():
        return {"error": "Rate limit exceeded. Upgrade to pro tier."}

    headers_lower = {k.lower(): v for k, v in headers.items()}
    results = []
    score = 0
    max_score = 0

    for header_name, info in _SECURITY_HEADERS.items():
        weight = {"critical": 3, "high": 2, "medium": 1}[info["importance"]]
        max_score += weight

        present = header_name.lower() in headers_lower
        value = headers_lower.get(header_name.lower(), "")

        if present:
            # Basic value validation
            is_good = True
            notes = "Present"

            if header_name == "Strict-Transport-Security":
                if "max-age=" not in value.lower():
                    is_good = False
                    notes = "Missing max-age directive"
                elif "max-age=0" in value:
                    is_good = False
                    notes = "max-age=0 disables HSTS"
                else:
                    try:
                        age_val = int(value.lower().split("max-age=")[1].split(";")[0].strip())
                        if age_val < 31536000:
                            notes = f"max-age={age_val} is below recommended 1 year (31536000)"
                    except (ValueError, IndexError):
                        pass

            if is_good:
                score += weight
                status = "pass"
            else:
                score += weight * 0.5
                status = "warn"
        else:
            status = "fail"
            notes = "Missing"

        results.append({
            "header": header_name,
            "status": status,
            "importance": info["importance"],
            "current_value": value if present else None,
            "recommended_value": info["recommended"],
            "description": info["description"],
            "notes": notes,
        })

    grade_pct = round((score / max_score) * 100) if max_score else 0
    grade = "A" if grade_pct >= 90 else "B" if grade_pct >= 75 else "C" if grade_pct >= 60 else "D" if grade_pct >= 40 else "F"

    missing_critical = [r["header"] for r in results if r["status"] == "fail" and r["importance"] == "critical"]

    return {
        "grade": grade,
        "score_pct": grade_pct,
        "headers_checked": len(results),
        "passed": sum(1 for r in results if r["status"] == "pass"),
        "warnings": sum(1 for r in results if r["status"] == "warn"),
        "failed": sum(1 for r in results if r["status"] == "fail"),
        "results": results,
        "critical_missing": missing_critical,
        "top_priority": f"Add {missing_critical[0]}" if missing_critical else "All critical headers present",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@mcp.tool()
def analyze_password_strength(
    password: str,
) -> dict:
    """Analyze password strength and provide improvement suggestions.

    Args:
        password: The password to analyze (processed locally, never stored or transmitted).
    """
    if not _check_rate_limit():
        return {"error": "Rate limit exceeded. Upgrade to pro tier."}

    length = len(password)
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?~`]", password))
    has_space = " " in password

    # Character set size
    charset = 0
    if has_lower: charset += 26
    if has_upper: charset += 26
    if has_digit: charset += 10
    if has_special: charset += 32
    if has_space: charset += 1

    # Entropy
    entropy = round(length * math.log2(max(1, charset)), 1) if charset > 0 else 0

    # Check patterns
    is_common = password.lower() in _COMMON_PASSWORDS
    has_sequential = any(password[i:i+3].isdigit() and int(password[i+1]) == int(password[i]) + 1 and int(password[i+2]) == int(password[i]) + 2 for i in range(len(password)-2) if password[i:i+3].isdigit())
    has_repeated = bool(re.search(r"(.)\1{2,}", password))

    # Score
    score = 0
    if length >= 8: score += 1
    if length >= 12: score += 1
    if length >= 16: score += 1
    if has_upper: score += 1
    if has_lower: score += 1
    if has_digit: score += 1
    if has_special: score += 1
    if entropy >= 60: score += 1
    if not is_common: score += 1
    if not has_sequential and not has_repeated: score += 1

    max_score = 10
    strength = "very_strong" if score >= 9 else "strong" if score >= 7 else "moderate" if score >= 5 else "weak" if score >= 3 else "very_weak"

    # Crack time estimate (simplified)
    guesses = charset ** length if charset else 0
    crack_seconds = guesses / 1e10  # 10 billion guesses/sec (GPU)
    if crack_seconds < 1:
        crack_time = "instant"
    elif crack_seconds < 3600:
        crack_time = f"{round(crack_seconds / 60)} minutes"
    elif crack_seconds < 86400:
        crack_time = f"{round(crack_seconds / 3600)} hours"
    elif crack_seconds < 31536000:
        crack_time = f"{round(crack_seconds / 86400)} days"
    elif crack_seconds < 31536000 * 100:
        crack_time = f"{round(crack_seconds / 31536000)} years"
    else:
        crack_time = "centuries+"

    suggestions = []
    if length < 12:
        suggestions.append("Increase length to at least 12 characters")
    if not has_upper:
        suggestions.append("Add uppercase letters")
    if not has_special:
        suggestions.append("Add special characters (!@#$%^&*)")
    if is_common:
        suggestions.append("This is a commonly used password - choose something unique")
    if has_sequential:
        suggestions.append("Avoid sequential numbers (123, 456)")
    if has_repeated:
        suggestions.append("Avoid repeated characters (aaa, 111)")
    if not suggestions:
        suggestions.append("Password meets all strength criteria")

    return {
        "strength": strength,
        "score": f"{score}/{max_score}",
        "entropy_bits": entropy,
        "crack_time_estimate": crack_time,
        "analysis": {
            "length": length,
            "has_uppercase": has_upper,
            "has_lowercase": has_lower,
            "has_digits": has_digit,
            "has_special_chars": has_special,
            "is_common_password": is_common,
            "has_sequential_patterns": has_sequential,
            "has_repeated_chars": has_repeated,
        },
        "charset_size": charset,
        "suggestions": suggestions,
        "note": "Password analyzed locally. Never stored or transmitted.",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@mcp.tool()
def generate_threat_model(
    system_name: str,
    components: list[str],
    data_types: list[str],
    external_interfaces: Optional[list[str]] = None,
    authentication_method: str = "password",
    deployment: str = "cloud",
) -> dict:
    """Generate a STRIDE-based threat model for a system.

    Args:
        system_name: Name of the system being modeled.
        components: System components (e.g. web_app, api_server, database, cache).
        data_types: Types of data processed (e.g. pii, financial, health, credentials).
        external_interfaces: External integrations (e.g. payment_gateway, email_service).
        authentication_method: password | mfa | sso | api_key | oauth.
        deployment: cloud | on_premise | hybrid | serverless.
    """
    if not _check_rate_limit():
        return {"error": "Rate limit exceeded. Upgrade to pro tier."}

    external_interfaces = external_interfaces or []

    _STRIDE = {
        "Spoofing": {"description": "Impersonating a user or system", "targets": ["authentication", "api_endpoints", "external_interfaces"]},
        "Tampering": {"description": "Modifying data in transit or at rest", "targets": ["database", "api_server", "file_storage", "cache"]},
        "Repudiation": {"description": "Denying actions without proof", "targets": ["api_server", "web_app", "payment_gateway"]},
        "Information Disclosure": {"description": "Exposing data to unauthorized parties", "targets": ["database", "api_server", "logs", "cache", "web_app"]},
        "Denial of Service": {"description": "Making the system unavailable", "targets": ["web_app", "api_server", "database", "load_balancer"]},
        "Elevation of Privilege": {"description": "Gaining unauthorized access levels", "targets": ["api_server", "web_app", "database", "admin_panel"]},
    }

    data_sensitivity = "critical" if any(d in data_types for d in ["credentials", "financial", "health"]) else "high" if "pii" in data_types else "medium"
    auth_strength = {"password": 2, "api_key": 3, "oauth": 4, "sso": 4, "mfa": 5}.get(authentication_method, 2)

    threats = []
    all_components = set(components + external_interfaces)

    for stride_cat, info in _STRIDE.items():
        affected = [c for c in all_components if c in info["targets"] or any(t in c for t in info["targets"])]
        if not affected:
            affected = list(all_components)[:2]

        likelihood = 3
        if stride_cat == "Spoofing" and auth_strength < 4:
            likelihood = 4
        if stride_cat == "Information Disclosure" and data_sensitivity == "critical":
            likelihood = 4

        impact = 4 if data_sensitivity == "critical" else 3 if data_sensitivity == "high" else 2
        risk_score = likelihood * impact

        threats.append({
            "category": stride_cat,
            "description": info["description"],
            "affected_components": affected,
            "likelihood": likelihood,
            "impact": impact,
            "risk_score": risk_score,
            "severity": "critical" if risk_score >= 16 else "high" if risk_score >= 9 else "medium",
        })

    threats.sort(key=lambda t: t["risk_score"], reverse=True)

    mitigations = {
        "Spoofing": f"Implement {('MFA' if auth_strength < 5 else 'certificate-based auth')} and rate limiting",
        "Tampering": "Use TLS everywhere, implement integrity checks, database audit logging",
        "Repudiation": "Implement comprehensive audit logging with tamper-proof storage",
        "Information Disclosure": f"Encrypt {', '.join(data_types)} at rest and in transit, implement RBAC",
        "Denial of Service": "Rate limiting, CDN, auto-scaling, circuit breakers",
        "Elevation of Privilege": "Least privilege principle, RBAC, input validation, container isolation",
    }

    return {
        "system": system_name,
        "deployment": deployment,
        "data_sensitivity": data_sensitivity,
        "authentication_strength": f"{auth_strength}/5 ({authentication_method})",
        "components": components,
        "external_interfaces": external_interfaces,
        "stride_analysis": threats,
        "mitigations": mitigations,
        "top_risks": [t["category"] for t in threats[:3]],
        "recommendations": [
            "Upgrade authentication to MFA" if auth_strength < 5 else "Authentication is strong",
            f"Encrypt all {data_sensitivity}-sensitivity data types",
            "Implement WAF and rate limiting on all public endpoints",
            "Regular penetration testing and vulnerability scanning",
            "Security incident response plan and runbook",
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


if __name__ == "__main__":
    mcp.run()
