"""
scanner.py
Core real-time scanning engine: crawls a target website, extracts HTML forms
and URL parameters, and tests them for common OWASP Top 10 issues:
SQL Injection (error-based + baseline-relative time-based), Cross-Site
Scripting, CSRF, insecure security headers, insecure cookie flags, and
server/version information disclosure.

INTENDED USE: authorized testing only, against apps you own or deliberately
vulnerable training targets such as OWASP WebGoat / OWASP NodeGoat.
"""

import re
import time
import uuid
import urllib3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse

# Self-signed certs are common on local training targets (e.g. WebGoat over HTTPS)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT = "Mozilla/5.0 (EducationalVulnScanner/1.0; +authorized-testing-only)"
REQUEST_TIMEOUT = 10
POLITENESS_DELAY = 0.15   # seconds between requests, so real sites aren't hammered
MAX_CRAWL_PAGES = 6       # keep crawling bounded and fast
TIME_BASED_THRESHOLD = 2.0  # seconds slower than baseline to flag as suspicious

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    '" OR "1"="1',
    "' OR 1=1--",
    "1' AND SLEEP(3)-- ",
    "'; WAITFOR DELAY '0:0:3'--",
]

XSS_PAYLOAD_VARIANTS = [
    "<script>alert('{canary}')</script>",
    "\"><script>alert('{canary}')</script>",
    "'><img src=x onerror=alert('{canary}')>",
    "<svg onload=alert('{canary}')>",
]

# Error-signature patterns for a broad range of database engines, so the
# scanner isn't blind to any one backend. Each is a regex, matched against
# the lower-cased response body.
SQL_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"mysql_fetch_(array|assoc|row|object)",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"sql syntax.*mysql",
    r"ora-\d{5}",
    r"pg_query\(\)",
    r"postgresql.*error",
    r"sqlite3\.operationalerror",
    r"sqlstate\[\w+\]",
    r"microsoft ole db provider",
    r"unclosed quotation mark after the character string",
    r"incorrect syntax near",
    r"mongoerror",
    r"unterminated string literal",
    r"syntax error at or near",
    r"division by zero",
    r"supplied argument is not a valid mysql",
]

SECURITY_HEADERS = {
    "X-Frame-Options": "Missing X-Frame-Options header allows clickjacking attacks.",
    "Content-Security-Policy": "Missing Content-Security-Policy header increases XSS risk.",
    "X-Content-Type-Options": "Missing X-Content-Type-Options header allows MIME-sniffing attacks.",
    "Strict-Transport-Security": "Missing HSTS header allows protocol downgrade attacks.",
    "X-XSS-Protection": "Missing X-XSS-Protection header (legacy browser mitigation).",
}

# Response headers that leak server/software version info to attackers
INFO_DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def get_page(url, timeout=REQUEST_TIMEOUT):
    headers = {"User-Agent": USER_AGENT}
    return requests.get(url, headers=headers, timeout=timeout, verify=False)


def _same_domain(url, root_netloc):
    try:
        return urlparse(url).netloc == root_netloc
    except ValueError:
        return False


def discover_pages(start_url, max_pages=MAX_CRAWL_PAGES):
    """
    Lightweight same-domain crawl (depth 1): fetches the start page, then
    follows a handful of same-domain links so forms on other pages
    (login, search, contact, etc.) get tested too - not just the homepage.
    Bounded and polite so it stays fast and doesn't hammer the target.
    """
    root_netloc = urlparse(start_url).netloc
    visited = []
    to_visit = [start_url]

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        try:
            resp = get_page(url)
        except requests.RequestException:
            continue

        visited.append(url)
        time.sleep(POLITENESS_DELAY)

        if len(visited) >= max_pages:
            break

        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            continue

        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"]).split("#")[0]
            if _same_domain(link, root_netloc) and link not in visited and link not in to_visit:
                to_visit.append(link)

    return visited


# ---------------------------------------------------------------------------
# Form & parameter extraction
# ---------------------------------------------------------------------------

def extract_forms(html, base_url):
    """Parse all <form> elements on a page into a scan-friendly structure."""
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or base_url
        method = (form.get("method") or "get").lower()
        full_action = urljoin(base_url, action)

        inputs = []
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if name:
                inputs.append({"name": name, "type": tag.get("type", "text")})

        has_csrf_token = any(
            "csrf" in (i["name"] or "").lower()
            or "token" in (i["name"] or "").lower()
            or "authenticity" in (i["name"] or "").lower()
            for i in inputs
        )

        forms.append(
            {
                "page": base_url,
                "action": full_action,
                "method": method,
                "inputs": inputs,
                "has_csrf_token": has_csrf_token,
            }
        )
    return forms


def extract_url_params(url):
    """
    If the URL itself carries query parameters (e.g. ?q=search&id=5), treat
    them as a pseudo-GET-form so the scanner also tests URLs that are
    parameterized directly, not only <form> elements.
    """
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    if not query:
        return None

    inputs = [{"name": k, "type": "text"} for k in query.keys()]
    base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
    return {
        "page": url,
        "action": base,
        "method": "get",
        "inputs": inputs,
        "has_csrf_token": True,  # N/A for a bare query string, don't flag as CSRF
    }


# ---------------------------------------------------------------------------
# Payload submission
# ---------------------------------------------------------------------------

def submit_form(form, payload, timeout=REQUEST_TIMEOUT):
    """Fill every field in a form with `payload` and submit it."""
    data = {}
    for field in form["inputs"]:
        if field["type"] in ("submit", "button", "hidden", "checkbox", "radio"):
            data[field["name"]] = "1"
        else:
            data[field["name"]] = payload

    headers = {"User-Agent": USER_AGENT}
    try:
        if form["method"] == "post":
            return requests.post(
                form["action"], data=data, headers=headers,
                timeout=timeout, verify=False,
            )
        return requests.get(
            form["action"], params=data, headers=headers,
            timeout=timeout, verify=False,
        )
    except requests.RequestException:
        return None


def _baseline_time(form, samples=1):
    """Send the form with a harmless value first, to get a normal response
    time baseline. Blind time-based SQLi is only reported if the payload is
    meaningfully slower than this baseline - not just an absolute threshold -
    which cuts down false positives on naturally slow endpoints."""
    times = []
    for _ in range(samples):
        start = time.time()
        resp = submit_form(form, "baseline_test_value")
        if resp is not None:
            times.append(time.time() - start)
    if not times:
        return None
    return sum(times) / len(times)


# ---------------------------------------------------------------------------
# Detection checks
# ---------------------------------------------------------------------------

def check_sql_injection(forms):
    findings = []
    for form in forms:
        if not form["inputs"]:
            continue

        baseline = _baseline_time(form)
        found_for_form = False

        for payload in SQLI_PAYLOADS:
            if found_for_form:
                break
            start = time.time()
            resp = submit_form(form, payload)
            elapsed = time.time() - start
            if resp is None:
                continue

            body_lower = resp.text.lower()
            matched = next((s for s in SQL_ERROR_SIGNATURES if re.search(s, body_lower)), None)

            if matched:
                findings.append({
                    "type": "SQL Injection",
                    "severity": "Critical",
                    "location": form["action"],
                    "method": form["method"].upper(),
                    "payload": payload,
                    "evidence": f"Database error pattern detected: '{matched}' "
                                f"(page: {form.get('page', form['action'])}).",
                })
                found_for_form = True
                continue

            is_timing_payload = "sleep" in payload.lower() or "waitfor" in payload.lower()
            if is_timing_payload and baseline is not None and (elapsed - baseline) > TIME_BASED_THRESHOLD:
                findings.append({
                    "type": "SQL Injection (Time-Based Blind)",
                    "severity": "High",
                    "location": form["action"],
                    "method": form["method"].upper(),
                    "payload": payload,
                    "evidence": f"Response took {elapsed:.2f}s vs a {baseline:.2f}s baseline "
                                f"({elapsed - baseline:.2f}s slower), consistent with a "
                                f"server-side delay function executing.",
                })
                found_for_form = True
    return findings


def check_xss(forms):
    findings = []
    for form in forms:
        if not form["inputs"]:
            continue

        # Unique per-form canary so a match can't be confused with unrelated
        # page content that happens to already contain the word "alert".
        canary = uuid.uuid4().hex[:8]

        for variant in XSS_PAYLOAD_VARIANTS:
            payload = variant.format(canary=canary)
            resp = submit_form(form, payload)
            if resp is None:
                continue

            if payload in resp.text:
                findings.append({
                    "type": "Cross-Site Scripting (XSS)",
                    "severity": "High",
                    "location": form["action"],
                    "method": form["method"].upper(),
                    "payload": payload,
                    "evidence": "Payload was reflected unescaped in the response body "
                                "(verified with a unique per-request marker to rule out "
                                "a false match).",
                })
                break
    return findings


def check_csrf(forms):
    findings = []
    for form in forms:
        if form["method"] == "post" and not form["has_csrf_token"]:
            findings.append({
                "type": "Cross-Site Request Forgery (CSRF)",
                "severity": "Medium",
                "location": form["action"],
                "method": form["method"].upper(),
                "payload": "N/A",
                "evidence": f"POST form on {form.get('page', form['action'])} has no "
                            f"visible CSRF token field.",
            })
    return findings


def check_headers(response):
    findings = []
    for header, description in SECURITY_HEADERS.items():
        if header not in response.headers:
            severity = "Medium" if header in ("Content-Security-Policy", "X-Frame-Options") else "Low"
            findings.append({
                "type": f"Insecure Header: {header}",
                "severity": severity,
                "location": response.url,
                "method": "GET",
                "payload": "N/A",
                "evidence": description,
            })
    return findings


def check_cookies(response):
    """Flag session/auth cookies missing HttpOnly, Secure, or SameSite flags."""
    findings = []
    raw_cookie_headers = []
    try:
        raw_cookie_headers = response.raw.headers.get_all("Set-Cookie") or []
    except Exception:
        combined = response.headers.get("Set-Cookie")
        raw_cookie_headers = [combined] if combined else []

    for cookie_str in raw_cookie_headers:
        if not cookie_str:
            continue
        name = cookie_str.split("=")[0].strip()
        lower = cookie_str.lower()
        missing = []
        if "httponly" not in lower:
            missing.append("HttpOnly")
        if "secure" not in lower:
            missing.append("Secure")
        if "samesite" not in lower:
            missing.append("SameSite")

        if missing:
            findings.append({
                "type": f"Insecure Cookie: {name}",
                "severity": "Medium" if "HttpOnly" in missing else "Low",
                "location": response.url,
                "method": "GET",
                "payload": "N/A",
                "evidence": f"Cookie '{name}' is missing: {', '.join(missing)}. This "
                            f"increases risk of session hijacking or CSRF.",
            })
    return findings


def check_info_disclosure(response):
    """Flag headers that leak server software/version information."""
    findings = []
    for header in INFO_DISCLOSURE_HEADERS:
        value = response.headers.get(header)
        if value:
            findings.append({
                "type": f"Information Disclosure: {header}",
                "severity": "Low",
                "location": response.url,
                "method": "GET",
                "payload": "N/A",
                "evidence": f"Server exposes '{header}: {value}', which can help an "
                            f"attacker fingerprint software versions to target known exploits.",
            })
    return findings


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_full_scan(url, crawl=True):
    """
    Run the complete check suite against a target website and return a
    severity-graded report. When `crawl` is True, a bounded same-domain
    crawl also tests a handful of linked pages, not just the given URL,
    for more realistic real-world coverage.
    """
    response = get_page(url)

    pages_to_scan = discover_pages(url) if crawl else [url]
    if url not in pages_to_scan:
        pages_to_scan.insert(0, url)

    all_forms = []
    for page_url in pages_to_scan:
        try:
            page_resp = response if page_url == url else get_page(page_url)
        except requests.RequestException:
            continue

        all_forms.extend(extract_forms(page_resp.text, page_url))

        url_param_pseudo_form = extract_url_params(page_url)
        if url_param_pseudo_form:
            all_forms.append(url_param_pseudo_form)

    findings = []
    findings.extend(check_headers(response))
    findings.extend(check_cookies(response))
    findings.extend(check_info_disclosure(response))
    findings.extend(check_csrf(all_forms))
    findings.extend(check_sql_injection(all_forms))
    findings.extend(check_xss(all_forms))

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 4))

    summary = {
        "Critical": sum(1 for f in findings if f["severity"] == "Critical"),
        "High": sum(1 for f in findings if f["severity"] == "High"),
        "Medium": sum(1 for f in findings if f["severity"] == "Medium"),
        "Low": sum(1 for f in findings if f["severity"] == "Low"),
        "pages_crawled": len(pages_to_scan),
        "forms_tested": len(all_forms),
        "total_findings": len(findings),
    }

    return {"summary": summary, "findings": findings, "pages_scanned": pages_to_scan}
