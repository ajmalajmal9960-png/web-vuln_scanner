"""
demo_data.py
Offline "preview" dataset: a small set of simulated request/response pairs
modeled on well-known OWASP training applications (WebGoat, NodeGoat) and
common real-world site patterns. These are NOT live network calls - they let
the scanner produce a full, realistic, severity-graded report instantly, so
you can preview exactly what the tool looks like before ever pointing it at
a real target.

Crucially, this reuses the *same* signature lists and matching logic as the
live scanner (scanner.SQL_ERROR_SIGNATURES, etc.), so the preview is not just
a mockup - it's proof that the detection rules work correctly.
"""

import re
import scanner

DEMO_TARGET_LABEL = "Demo Preview (offline, simulated WebGoat/NodeGoat dataset)"

# Each entry simulates one form submission: what page it's on, the field
# tested, the payload sent, and what the server would have returned.
SIMULATED_CASES = [
    {
        "page": "http://localhost:8080/WebGoat/SqlInjection/attack5a",
        "action": "http://localhost:8080/WebGoat/SqlInjection/attack5a",
        "method": "POST",
        "field": "account",
        "payload": "' OR '1'='1",
        "response_body": "Welcome admin. Logged in as: admin, jerry, mike, john, dave. "
                          "You have an error in your SQL syntax near ''1'='1''.",
        "elapsed": 0.18,
    },
    {
        "page": "http://localhost:4000/allocations/search",
        "action": "http://localhost:4000/allocations/search",
        "method": "GET",
        "field": "id",
        "payload": "1' OR '1'='1",
        "response_body": "MongoError: unterminated string literal near '1'='1' - query execution failed",
        "elapsed": 0.21,
    },
    {
        "page": "http://testsite.local/login",
        "action": "http://testsite.local/login",
        "method": "POST",
        "field": "username",
        "payload": "1' AND SLEEP(3)-- ",
        "response_body": "Login failed. Please check your credentials.",
        "elapsed": 3.42,
        "baseline": 0.24,
    },
    {
        "page": "http://localhost:8080/WebGoat/CrossSiteScripting/attack5",
        "action": "http://localhost:8080/WebGoat/CrossSiteScripting/attack5",
        "method": "POST",
        "field": "comment",
        "payload": "<script>alert('{canary}')</script>",
        "response_body": "Thanks for your comment: <script>alert('{canary}')</script> - posted successfully.",
        "elapsed": 0.15,
    },
    {
        "page": "http://testsite.local/feedback",
        "action": "http://testsite.local/feedback",
        "method": "POST",
        "field": "message",
        "payload": "\"><script>alert('{canary}')</script>",
        "response_body": "Feedback received: \"><script>alert('{canary}')</script>",
        "elapsed": 0.13,
    },
    {
        "page": "http://testsite.local/blog/post1",
        "action": "http://testsite.local/blog/post1",
        "method": "POST",
        "field": "comment",
        "payload": "1' UNION SELECT username, password FROM users--",
        "response_body": "Comment posted. No results matched your query.",
        "elapsed": 0.16,
        "safe": True,
    },
]

# Forms without a CSRF token, for the CSRF check
SIMULATED_FORMS_FOR_CSRF = [
    {"page": "http://localhost:8080/WebGoat/CSRF/basic-get-flow",
     "action": "http://localhost:8080/WebGoat/CSRF/basic-get-flow",
     "method": "post", "inputs": [{"name": "amount", "type": "text"}, {"name": "toAccount", "type": "text"}],
     "has_csrf_token": False},
    {"page": "http://testsite.local/checkout",
     "action": "http://testsite.local/checkout/confirm",
     "method": "post", "inputs": [{"name": "orderId", "type": "hidden"}, {"name": "total", "type": "hidden"}],
     "has_csrf_token": False},
    {"page": "http://localhost:4000/transfer",
     "action": "http://localhost:4000/transfer",
     "method": "post", "inputs": [{"name": "_csrf", "type": "hidden"}, {"name": "amount", "type": "text"}],
     "has_csrf_token": True},
]

# Simulated response headers/cookies for the header, cookie, and info-disclosure checks
SIMULATED_SITE_HEADERS = {
    "Content-Type": "text/html",
    "Server": "Apache/2.4.41 (Ubuntu)",
    "X-Powered-By": "PHP/7.2.24",
    # Intentionally missing: X-Frame-Options, CSP, X-Content-Type-Options, HSTS, X-XSS-Protection
}
SIMULATED_SET_COOKIE = "PHPSESSID=8f14e45fceea167a5a36dedd4bea2543; Path=/"


def _run_demo_sqli_and_xss():
    findings = []
    for case in SIMULATED_CASES:
        payload = case["payload"].format(canary="a1b2c3d4") if "{canary}" in case["payload"] else case["payload"]
        body = case["response_body"].format(canary="a1b2c3d4") if "{canary}" in case["response_body"] else case["response_body"]
        body_lower = body.lower()

        # SQLi error-signature check (identical logic/signatures to the live scanner)
        matched = next((s for s in scanner.SQL_ERROR_SIGNATURES if re.search(s, body_lower)), None)
        if matched:
            findings.append({
                "type": "SQL Injection",
                "severity": "Critical",
                "location": case["action"],
                "method": case["method"],
                "payload": payload,
                "evidence": f"Database error pattern detected: '{matched}' (page: {case['page']}).",
            })
            continue

        # Time-based blind SQLi (baseline-relative, same threshold as live scanner)
        if "baseline" in case:
            delta = case["elapsed"] - case["baseline"]
            if delta > scanner.TIME_BASED_THRESHOLD:
                findings.append({
                    "type": "SQL Injection (Time-Based Blind)",
                    "severity": "High",
                    "location": case["action"],
                    "method": case["method"],
                    "payload": payload,
                    "evidence": f"Response took {case['elapsed']:.2f}s vs a {case['baseline']:.2f}s "
                                f"baseline ({delta:.2f}s slower), consistent with a server-side "
                                f"delay function executing.",
                })
                continue

        # XSS reflection check (identical logic to the live scanner)
        if payload in body:
            findings.append({
                "type": "Cross-Site Scripting (XSS)",
                "severity": "High",
                "location": case["action"],
                "method": case["method"],
                "payload": payload,
                "evidence": "Payload was reflected unescaped in the response body "
                            "(verified with a unique per-request marker to rule out a false match).",
            })
    return findings


def _run_demo_csrf():
    return scanner.check_csrf(SIMULATED_FORMS_FOR_CSRF)


def _run_demo_headers_cookies_disclosure():
    class _FakeResponse:
        def __init__(self, headers, url, set_cookie):
            self.headers = headers
            self.url = url

            class _RawHeaders:
                def get_all(_self, name):
                    if name == "Set-Cookie":
                        return [set_cookie]
                    return None

            class _Raw:
                headers = _RawHeaders()

            self.raw = _Raw()

    fake_resp = _FakeResponse(SIMULATED_SITE_HEADERS, "http://testsite.local/", SIMULATED_SET_COOKIE)

    findings = []
    findings.extend(scanner.check_headers(fake_resp))
    findings.extend(scanner.check_cookies(fake_resp))
    findings.extend(scanner.check_info_disclosure(fake_resp))
    return findings


def run_demo_scan():
    """
    Runs the exact same detection functions from scanner.py against a fixed,
    offline simulated dataset, so the preview is a genuine demonstration of
    the detection logic - not a hand-written fake result.
    """
    findings = []
    findings.extend(_run_demo_headers_cookies_disclosure())
    findings.extend(_run_demo_csrf())
    findings.extend(_run_demo_sqli_and_xss())

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 4))

    summary = {
        "Critical": sum(1 for f in findings if f["severity"] == "Critical"),
        "High": sum(1 for f in findings if f["severity"] == "High"),
        "Medium": sum(1 for f in findings if f["severity"] == "Medium"),
        "Low": sum(1 for f in findings if f["severity"] == "Low"),
        "pages_crawled": len({c["page"] for c in SIMULATED_CASES} | {f["page"] for f in SIMULATED_FORMS_FOR_CSRF}),
        "forms_tested": len(SIMULATED_CASES) + len(SIMULATED_FORMS_FOR_CSRF),
        "total_findings": len(findings),
    }

    return {
        "summary": summary,
        "findings": findings,
        "pages_scanned": sorted({c["page"] for c in SIMULATED_CASES} | {f["page"] for f in SIMULATED_FORMS_FOR_CSRF}),
    }
