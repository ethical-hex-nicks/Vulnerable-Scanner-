#!/usr/bin/env python3

import os
import sys
import requests
import urllib.parse
import mimetypes
import socket
import re
from datetime import datetime
from colorama import Fore, Back, Style, init

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────

BANNER = r"""
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""

def print_banner():
    print(Fore.RED + BANNER)
    print(Fore.YELLOW + "  Web Vulnerability Scanner v1.0")
    print(Fore.RED + "  ⚠  FOR AUTHORIZED PENETRATION TESTING ONLY")
    print(Fore.RED + "  ⚠  UNAUTHORIZED USE IS ILLEGAL")
    print(Fore.YELLOW + "  " + "─" * 60)
    print()

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

results_log = []

def log(status, message):
    results_log.append((status, message))

def section(title):
    print(Fore.CYAN + f"\n[*] {title}")
    print(Fore.CYAN + "    " + "─" * 50)

def found(msg):
    print(Fore.RED + f"    [!] {msg}")
    log("VULN", msg)

def warn(msg):
    print(Fore.YELLOW + f"    [~] {msg}")
    log("WARN", msg)

def safe(msg):
    print(Fore.GREEN + f"    [✓] {msg}")

def error(msg):
    print(Fore.MAGENTA + f"    [ERR] {msg}")

def get_target():
    url = input(Fore.YELLOW + "\n[+] Target URL: " + Style.RESET_ALL).strip()
    if not url.startswith("http"):
        url = "https://" + url
    return url.rstrip("/")

def safe_get(url, timeout=10):
    try:
        return requests.get(url, timeout=timeout, verify=False, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 (VulnScan/1.0)"})
    except:
        return None

def safe_post(url, data, timeout=10):
    try:
        return requests.post(url, data=data, timeout=timeout, verify=False,
                             headers={"User-Agent": "Mozilla/5.0 (VulnScan/1.0)"})
    except:
        return None

# ─────────────────────────────────────────────
#  1. SSL CHECK
# ─────────────────────────────────────────────

def check_ssl(url):
    section("SSL / TLS Check")
    if url.startswith("http://"):
        found("Site is using HTTP — data transmitted in plaintext!")
        https_url = "https://" + url[7:]
        r = safe_get(https_url)
        if r and r.status_code < 400:
            warn(f"HTTPS available at: {https_url} but not enforced")
        else:
            found("HTTPS not available at all")
    else:
        safe("Site is using HTTPS")

# ─────────────────────────────────────────────
#  2. SECURITY HEADERS
# ─────────────────────────────────────────────

def check_headers(url):
    section("Security Headers")
    r = safe_get(url)
    if not r:
        error("Could not fetch headers")
        return {}

    headers = r.headers

    required = {
        "X-Frame-Options":         "Clickjacking Protection",
        "X-XSS-Protection":        "XSS Filter Header",
        "X-Content-Type-Options":  "MIME Sniffing Protection",
        "Content-Security-Policy": "Content Security Policy (CSP)",
        "Strict-Transport-Security": "HTTP Strict Transport Security (HSTS)",
        "Referrer-Policy":         "Referrer Policy",
        "Permissions-Policy":      "Permissions Policy",
    }

    for header, desc in required.items():
        if header in headers:
            safe(f"{desc}: {headers[header][:80]}")
        else:
            found(f"MISSING {desc} ({header})")

    # Server disclosure
    if "Server" in headers:
        warn(f"Server Disclosure: {headers['Server']}")
    if "X-Powered-By" in headers:
        found(f"X-Powered-By Disclosure: {headers['X-Powered-By']}")

    return headers

# ─────────────────────────────────────────────
#  3. SERVER / TECHNOLOGY FINGERPRINT
# ─────────────────────────────────────────────

def fingerprint(url):
    section("Server Fingerprinting")
    r = safe_get(url)
    if not r:
        error("Could not fingerprint")
        return

    h = r.headers
    tech = []

    if "Server" in h:
        tech.append(f"Server: {h['Server']}")
    if "X-Powered-By" in h:
        tech.append(f"Powered By: {h['X-Powered-By']}")
    if "X-Generator" in h:
        tech.append(f"Generator: {h['X-Generator']}")
    if "x-drupal-cache" in h:
        tech.append("CMS: Drupal")
    if "x-shopify-stage" in h:
        tech.append("Platform: Shopify")

    body = r.text.lower()
    if "wp-content" in body or "wp-includes" in body:
        tech.append("CMS: WordPress")
    if "joomla" in body:
        tech.append("CMS: Joomla")
    if "drupal" in body:
        tech.append("CMS: Drupal")
    if "laravel" in body:
        tech.append("Framework: Laravel")
    if "django" in body:
        tech.append("Framework: Django")

    if tech:
        for t in tech:
            warn(t)
    else:
        safe("No tech stack disclosed in headers/body")

# ─────────────────────────────────────────────
#  4. WORDPRESS DETECTION + VULNS
# ─────────────────────────────────────────────

def check_wordpress(url):
    section("WordPress Detection")

    wp_paths = [
        "/wp-login.php",
        "/wp-admin/",
        "/wp-content/",
        "/xmlrpc.php",
        "/wp-includes/",
        "/readme.html",
        "/license.txt",
    ]

    is_wp = False
    for path in wp_paths:
        r = safe_get(url + path)
        if r and r.status_code in [200, 301, 302, 403]:
            warn(f"WordPress Path Found: {url + path} [{r.status_code}]")
            is_wp = True

    if is_wp:
        found("WordPress Detected — running WordPress-specific checks...")
        check_wordpress_vulns(url)
    else:
        safe("No WordPress detected")

def check_wordpress_vulns(url):
    section("WordPress Vulnerability Checks")

    # User enumeration via REST API
    r = safe_get(url + "/wp-json/wp/v2/users")
    if r and r.status_code == 200:
        found(f"User Enumeration via REST API: {url}/wp-json/wp/v2/users")
        try:
            users = r.json()
            for user in users:
                warn(f"  User → name: {user.get('name')} | slug: {user.get('slug')}")
        except:
            pass

    # User enumeration via ?author=
    for i in range(1, 4):
        r = safe_get(url + f"/?author={i}")
        if r and r.status_code == 301:
            location = r.headers.get("Location", "")
            if "/author/" in location:
                found(f"User Enumeration via ?author={i} → {location}")

    # XML-RPC enabled
    r = safe_post(url + "/xmlrpc.php",
                  data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>')
    if r and r.status_code == 200 and "methodResponse" in r.text:
        found(f"XML-RPC Enabled (Brute Force / DDoS Risk): {url}/xmlrpc.php")

    # wp-config exposed
    r = safe_get(url + "/wp-config.php")
    if r and r.status_code == 200 and "DB_" in r.text:
        found(f"wp-config.php EXPOSED with credentials: {url}/wp-config.php")

    # Vulnerable plugins check
    vuln_plugins = [
        ("/wp-content/plugins/revslider/", "Revolution Slider (CVE-2014-9734)"),
        ("/wp-content/plugins/wp-file-manager/", "WP File Manager (CVE-2020-25213)"),
        ("/wp-content/plugins/duplicator/", "Duplicator (CVE-2020-11738)"),
        ("/wp-content/plugins/contact-form-7/", "Contact Form 7"),
        ("/wp-content/plugins/elementor/", "Elementor"),
        ("/wp-content/plugins/woocommerce/", "WooCommerce"),
        ("/wp-content/plugins/yoast-seo/", "Yoast SEO"),
        ("/wp-content/plugins/wordfence/", "Wordfence (Security plugin — check version)"),
        ("/wp-content/plugins/wpforms-lite/", "WPForms Lite"),
        ("/wp-content/plugins/all-in-one-seo-pack/", "All-in-One SEO"),
    ]

    section("WordPress Plugin Detection")
    for path, name in vuln_plugins:
        r = safe_get(url + path)
        if r and r.status_code in [200, 403]:
            warn(f"Plugin Found: {name} → {url + path} [{r.status_code}]")

# ─────────────────────────────────────────────
#  5. XSS TESTING
# ─────────────────────────────────────────────

def test_xss(url):
    section("XSS — Cross-Site Scripting")

    payloads = [
        "<script>alert(1)</script>",
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        '"><img src=x onerror=alert(1)>',
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        '"><svg/onload=alert(1)>',
        "{{7*7}}",  # Template injection probe
    ]

    test_params = ["q", "s", "search", "query", "id", "page", "name", "input", "text", "keyword"]
    base = url + ("&" if "?" in url else "?")

    found_xss = False
    for param in test_params:
        for payload in payloads:
            try:
                test_url = base + param + "=" + urllib.parse.quote(payload)
                r = safe_get(test_url)
                if r and (payload in r.text or urllib.parse.unquote(payload) in r.text):
                    found(f"Reflected XSS Found!")
                    found(f"  Param: {param}")
                    found(f"  Payload: {payload}")
                    found(f"  URL: {test_url}")
                    found_xss = True
                    break
            except:
                pass
        if found_xss:
            break

    if not found_xss:
        safe("No reflected XSS detected via URL params")

# ─────────────────────────────────────────────
#  6. SQL INJECTION
# ─────────────────────────────────────────────

def test_sqli(url):
    section("SQL Injection")

    payloads = [
        "'",
        '"',
        "' OR '1'='1",
        "' OR 1=1--",
        '" OR 1=1--',
        "1' ORDER BY 1--",
        "1 AND 1=2",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "1; DROP TABLE users--",
        "admin'--",
        "' OR SLEEP(5)--",
    ]

    sql_errors = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "sql syntax",
        "mysql_fetch",
        "pg_exec",
        "pg_query",
        "sqlite_",
        "ora-01756",
        "microsoft sql",
        "odbc sql",
        "syntax error",
        "mysql error",
        "division by zero",
        "supplied argument is not a valid mysql",
        "invalid query",
        "sql command not properly ended",
    ]

    test_params = ["id", "page", "cat", "item", "product", "search", "user", "p", "q"]
    base = url + ("&" if "?" in url else "?")

    found_sqli = False
    for param in test_params:
        for payload in payloads:
            try:
                test_url = base + param + "=" + urllib.parse.quote(payload)
                r = safe_get(test_url)
                if r:
                    body_lower = r.text.lower()
                    for err in sql_errors:
                        if err in body_lower:
                            found(f"SQL Injection Detected!")
                            found(f"  Param: {param}")
                            found(f"  Payload: {payload}")
                            found(f"  Error: {err}")
                            found(f"  URL: {test_url}")
                            found_sqli = True
                            break
                if found_sqli:
                    break
            except:
                pass
        if found_sqli:
            break

    if not found_sqli:
        safe("No error-based SQL Injection detected")

# ─────────────────────────────────────────────
#  7. SENSITIVE FILES
# ─────────────────────────────────────────────

def check_exposed_files(url):
    section("Sensitive File / Directory Exposure")

    targets = [
        ("/.env",                "Environment Variables"),
        ("/.git/config",         "Git Config (Source Code Leak)"),
        ("/.git/HEAD",           "Git HEAD"),
        ("/config.php",          "PHP Config"),
        ("/config.json",         "JSON Config"),
        ("/database.php",        "Database Config"),
        ("/db.php",              "Database File"),
        ("/backup.sql",          "SQL Backup"),
        ("/backup.zip",          "Backup Archive"),
        ("/backup.tar.gz",       "Backup Archive"),
        ("/.htaccess",           "Apache htaccess"),
        ("/phpinfo.php",         "PHP Info (Version Disclosure)"),
        ("/info.php",            "PHP Info"),
        ("/test.php",            "Test File"),
        ("/admin/",              "Admin Panel"),
        ("/administrator/",      "Administrator Panel"),
        ("/phpmyadmin/",         "phpMyAdmin"),
        ("/pma/",                "phpMyAdmin (short)"),
        ("/robots.txt",          "Robots.txt"),
        ("/sitemap.xml",         "Sitemap"),
        ("/.DS_Store",           "macOS DS_Store"),
        ("/web.config",          "IIS Web Config"),
        ("/composer.json",       "Composer (PHP Dependencies)"),
        ("/package.json",        "NPM Package Info"),
        ("/error_log",           "Error Log"),
        ("/access_log",          "Access Log"),
        ("/wp-config.php.bak",   "WordPress Config Backup"),
        ("/server-status",       "Apache Server Status"),
        ("/api/",                "API Endpoint"),
        ("/v1/",                 "API v1"),
        ("/swagger.json",        "Swagger API Docs"),
        ("/openapi.json",        "OpenAPI Docs"),
        ("/graphql",             "GraphQL Endpoint"),
    ]

    any_found = False
    for path, desc in targets:
        r = safe_get(url + path)
        if r:
            if r.status_code == 200:
                found(f"{desc} EXPOSED: {url + path} [{len(r.content)} bytes]")
                any_found = True
            elif r.status_code == 403:
                warn(f"{desc} EXISTS (Forbidden): {url + path}")
                any_found = True

    if not any_found:
        safe("No sensitive files or directories exposed")

# ─────────────────────────────────────────────
#  8. OPEN REDIRECT
# ─────────────────────────────────────────────

def check_open_redirect(url):
    section("Open Redirect")

    params = ["url", "redirect", "next", "return", "goto", "dest",
              "destination", "redir", "redirect_uri", "continue", "target", "link"]
    payloads = [
        "https://evil.com",
        "//evil.com",
        "//evil.com/%2f..",
        "https:evil.com",
    ]

    found_redirect = False
    for param in params:
        for payload in payloads:
            try:
                test_url = url + ("&" if "?" in url else "?") + param + "=" + urllib.parse.quote(payload)
                r = requests.get(test_url, timeout=10, verify=False, allow_redirects=False,
                                 headers={"User-Agent": "Mozilla/5.0 (VulnScan/1.0)"})
                if r and r.status_code in [301, 302, 303, 307, 308]:
                    location = r.headers.get("Location", "")
                    if "evil.com" in location:
                        found(f"Open Redirect Found!")
                        found(f"  Param: {param} → Redirects to: {location}")
                        found_redirect = True
                        break
            except:
                pass
        if found_redirect:
            break

    if not found_redirect:
        safe("No Open Redirect detected")

# ─────────────────────────────────────────────
#  9. CLICKJACKING
# ─────────────────────────────────────────────

def check_clickjacking(url):
    section("Clickjacking")
    r = safe_get(url)
    if not r:
        error("Could not check clickjacking")
        return

    h = r.headers
    xfo = "X-Frame-Options" in h
    csp = "Content-Security-Policy" in h
    csp_frame = csp and "frame-ancestors" in h.get("Content-Security-Policy", "").lower()

    if not xfo and not csp_frame:
        found("CLICKJACKING VULNERABLE — No X-Frame-Options or CSP frame-ancestors!")
    else:
        safe("Clickjacking protection present")

# ─────────────────────────────────────────────
#  10. CORS MISCONFIGURATION
# ─────────────────────────────────────────────

def check_cors(url):
    section("CORS Misconfiguration")
    try:
        r = requests.get(url, timeout=10, verify=False,
                         headers={
                             "User-Agent": "Mozilla/5.0 (VulnScan/1.0)",
                             "Origin": "https://evil.com"
                         })
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            warn("CORS: Wildcard (*) origin allowed — may expose public APIs")
        elif "evil.com" in acao:
            found(f"CORS MISCONFIGURATION: Reflects attacker origin → {acao}")
            if acac.lower() == "true":
                found("CORS + Credentials = Critical! Cookies/auth can be stolen cross-origin!")
        else:
            safe(f"CORS properly configured: {acao or 'Not set'}")
    except Exception as e:
        error(str(e))

# ─────────────────────────────────────────────
#  11. CVE / VERSION-BASED FINGERPRINT
# ─────────────────────────────────────────────

def check_cve_fingerprint(url):
    section("CVE / Version Fingerprinting")

    r = safe_get(url)
    if not r:
        error("Could not fingerprint")
        return

    body = r.text
    headers = r.headers

    patterns = [
        (r"WordPress (\d+\.\d+[\.\d]*)", "WordPress"),
        (r"Joomla[! ](\d+\.\d+)", "Joomla"),
        (r"Drupal (\d+\.\d+)", "Drupal"),
        (r"Apache[/ ](\d+\.\d+[\.\d]*)", "Apache"),
        (r"nginx[/ ](\d+\.\d+[\.\d]*)", "nginx"),
        (r"PHP[/ ](\d+\.\d+[\.\d]*)", "PHP"),
        (r"OpenSSL[/ ](\d+\.\d+[\.\da-z]*)", "OpenSSL"),
        (r"IIS[/ ](\d+\.\d+)", "Microsoft IIS"),
    ]

    found_versions = False
    server_header = headers.get("Server", "") + " " + headers.get("X-Powered-By", "")
    full_text = server_header + " " + body[:5000]

    for pattern, tech in patterns:
        match = re.search(pattern, full_text, re.IGNORECASE)
        if match:
            version = match.group(1)
            found(f"{tech} version disclosed: {version} — Check NVD/CVE for known vulnerabilities")
            found_versions = True

    if not found_versions:
        safe("No version strings found in headers or body")

# ─────────────────────────────────────────────
#  12. SUMMARY REPORT
# ─────────────────────────────────────────────

def print_summary(target):
    print()
    print(Fore.CYAN + "═" * 62)
    print(Fore.YELLOW + "  SCAN SUMMARY")
    print(Fore.CYAN + "═" * 62)
    print(Fore.YELLOW + f"  Target : {target}")
    print(Fore.YELLOW + f"  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(Fore.CYAN + "─" * 62)

    vulns  = [r for r in results_log if r[0] == "VULN"]
    warns  = [r for r in results_log if r[0] == "WARN"]

    print(Fore.RED    + f"  Critical/High  : {len(vulns)} issues")
    print(Fore.YELLOW + f"  Warnings       : {len(warns)} items")
    print(Fore.CYAN + "─" * 62)

    if vulns:
        print(Fore.RED + "\n  [VULNERABILITIES FOUND]")
        for _, msg in vulns:
            print(Fore.RED + f"    ✗ {msg}")

    if warns:
        print(Fore.YELLOW + "\n  [WARNINGS]")
        for _, msg in warns:
            print(Fore.YELLOW + f"    ~ {msg}")

    if not vulns and not warns:
        print(Fore.GREEN + "\n  No critical issues found!")

    print()
    print(Fore.CYAN + "═" * 62)
    print(Fore.RED + "  ⚠  Use only on authorized targets.")
    print(Fore.CYAN + "═" * 62)
    print()

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    print_banner()

    url = get_target()

    print(Fore.YELLOW + f"\n[*] Scanning: {url}")
    print(Fore.YELLOW + f"[*] Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    check_ssl(url)
    check_headers(url)
    fingerprint(url)
    check_cve_fingerprint(url)
    check_wordpress(url)
    test_xss(url)
    test_sqli(url)
    check_exposed_files(url)
    check_open_redirect(url)
    check_clickjacking(url)
    check_cors(url)

    print_summary(url)

if __name__ == "__main__":
    main()
