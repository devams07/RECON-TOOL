import socket
import asyncio
import aiohttp
import requests
import dns.resolver
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import re


# -----------------------------
# Clean domain
# -----------------------------
def clean_domain(domain):
    for p in ["https://", "http://"]:
        domain = domain.replace(p, "")
    return domain.replace("www.", "").strip()


# -----------------------------
# ASYNC REQUEST (FAST)
# -----------------------------
async def async_fetch(domain):
    headers = {"User-Agent": "Mozilla/5.0"}

    urls = [f"https://{domain}", f"http://{domain}"]

    async with aiohttp.ClientSession(headers=headers) as session:
        for url in urls:
            try:
                async with session.get(url, timeout=8) as res:
                    return {
                        "html": await res.text(),
                        "headers": dict(res.headers),
                        "status": res.status
                    }
            except:
                continue

    return None


# -----------------------------
# FALLBACK REQUEST (STABLE)
# -----------------------------
def fallback_fetch(domain):
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        r = requests.get(f"https://{domain}", headers=headers, timeout=8)
    except:
        try:
            r = requests.get(f"http://{domain}", headers=headers, timeout=8)
        except:
            return None

    return {
        "html": r.text,
        "headers": dict(r.headers),
        "status": r.status_code
    }


# -----------------------------
# HYBRID FETCH
# -----------------------------
def get_response(domain):
    try:
        res = asyncio.run(async_fetch(domain))
        if res and res["html"]:
            return res
    except:
        pass

    # fallback
    return fallback_fetch(domain)


# -----------------------------
# DNS
# -----------------------------
def get_dns(domain):
    records = {}
    for r in ['A', 'MX', 'NS']:
        try:
            answers = dns.resolver.resolve(domain, r)
            records[r] = [str(a) for a in answers]
        except:
            records[r] = []
    return records


# -----------------------------
# PORT SCAN (THREAD)
# -----------------------------
import socket
from concurrent.futures import ThreadPoolExecutor

# Common ports with names
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


def scan_port(ip, port):
    s = socket.socket()
    s.settimeout(1)

    try:
        s.connect((ip, port))

        # Try to grab banner
        banner = ""
        try:
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        except:
            banner = ""

        service = COMMON_PORTS.get(port, "Unknown")

        return {
            "port": port,
            "service": service,
            "banner": banner[:100]  # limit size
        }

    except:
        return None

    finally:
        s.close()


def scan_ports(ip, ports=None):
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    results = []

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan_port, ip, p) for p in ports]

        for f in futures:
            res = f.result()
            if res:
                results.append(res)

    return results

# -----------------------------
# TECH DETECTION (IMPROVED)
# -----------------------------
import re

def detect_tech(headers, html):
    tech = {}
    html_lower = html.lower()

    # normalize headers
    headers = {k.lower(): v.lower() for k, v in headers.items()}

    def add(name, reason):
        tech.setdefault(name, []).append(reason)

    # -------------------------
    # 1. HEADERS
    # -------------------------
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")

    if "nginx" in server:
        add("Nginx", "Server header")
    if "apache" in server:
        add("Apache", "Server header")
    if "cloudflare" in server:
        add("Cloudflare", "Server header")

    if "php" in powered:
        add("PHP", "X-Powered-By")
    if "asp.net" in powered:
        add("ASP.NET", "X-Powered-By")

    # CDN detection
    if "cf-ray" in headers or "cf-cache-status" in headers:
        add("Cloudflare CDN", "CF headers")

    # -------------------------
    # 2. META TAGS
    # -------------------------
    if 'name="generator"' in html_lower:
        add("CMS", "Meta generator tag")

    if "wordpress" in html_lower:
        add("WordPress", "HTML keyword")

    # -------------------------
    # 3. FRAMEWORK DETECTION
    # -------------------------
    if "react" in html_lower:
        add("React", "HTML/script match")

    if "angular" in html_lower:
        add("Angular", "HTML match")

    if "vue" in html_lower:
        add("Vue.js", "HTML match")

    # -------------------------
    # 4. LIBRARIES
    # -------------------------
    if "jquery" in html_lower:
        add("jQuery", "JS library")

    if "bootstrap" in html_lower:
        add("Bootstrap", "CSS/JS")

    # -------------------------
    # 5. SCRIPT URL DETECTION
    # -------------------------
    if "cdn.jsdelivr.net" in html_lower:
        add("jsDelivr", "CDN")

    if "cdnjs.cloudflare.com" in html_lower:
        add("Cloudflare CDN", "CDN")

    if "ajax.googleapis.com" in html_lower:
        add("Google CDN", "CDN")

    # -------------------------
    # 6. COOKIE BASED DETECTION
    # -------------------------
    cookies = headers.get("set-cookie", "")

    if "phpsessid" in cookies:
        add("PHP", "Session cookie")

    if "jsessionid" in cookies:
        add("Java (JSP)", "Session cookie")

    # -------------------------
    # 7. FINAL OUTPUT
    # -------------------------
    if not tech:
        return ["Unknown / Hidden"]

    # flatten result
    result = []
    for k in tech:
        result.append(k)

    return result

# -----------------------------
# SUBDOMAINS
# -----------------------------
from concurrent.futures import ThreadPoolExecutor
import socket
import requests

def get_subdomains(domain):
    subs = set()

    try:
        res = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=5
        ).json()

        for entry in res:
            name = entry.get("name_value", "")
            if domain in name:
                subs.add(name.strip())

    except:
        pass

    return list(subs)   # ✅ always list


def check_subdomain(sub):
    try:
        socket.gethostbyname(sub)
        return sub
    except:
        return None


def brute_subdomains(domain, wordlist_file="subdomain_wordlist.txt"):
    try:
        with open(wordlist_file, "r") as f:
            # remove empty lines + spaces
            words = [w.strip() for w in f if w.strip()]
    except Exception as e:
        print("[!] Wordlist not found:", e)
        return []   # ✅ always return list

    # build subdomains safely
    subs = [f"{word}.{domain}" for word in words]

    found = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(check_subdomain, subs)

        for r in results:
            if r:
                found.append(r)

    # remove duplicates
    return list(set(found))
# -----------------------------
# DIRECTORIES
# -----------------------------
def find_directories(domain):
    paths = ["admin", "login", "api"]
    found = []

    for p in paths:
        try:
            r = requests.get(f"https://{domain}/{p}", timeout=5)
            if r.status_code == 200:
                found.append(f"/{p}")
        except:
            pass

    return found


# -----------------------------
# EMAILS
# -----------------------------
def extract_emails(html):
    return list(set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", html)))
def generate_smart_emails(domain, names):
    patterns = []

    for name in names:
        name = name.lower()

        patterns.extend([
            f"{name}@{domain}",
            f"{name}.admin@{domain}",
            f"{name}.support@{domain}",
            f"{name}.help@{domain}",
            f"{name}123@{domain}",
        ])

    return patterns
def generate_emails(domain, wordlist_file="email_wordlist.txt"):
    emails = []

    try:
        with open(wordlist_file) as f:
            words = [w.strip() for w in f if w.strip()]
    except:
        return []

    # only top words
    words = words[:50]

    for w in words:
        emails.append(f"{w}@{domain}")

    # smart patterns
    base = domain.split('.')[0]

    patterns = [
        f"{base}@{domain}",
        f"{base}.admin@{domain}",
        f"admin.{base}@{domain}",
        f"support.{base}@{domain}"
    ]

    emails.extend(patterns)

    return list(set(emails))
def clean_emails(emails):
    return [e for e in emails if len(e.split('@')[0]) < 20]

import socket

def check_mail_server(domain):
    try:
        records = dns.resolver.resolve(domain, 'MX')
        return [str(r.exchange) for r in records]
    except:
        return []


# -----------------------------
# MAIN ENGINE
# -----------------------------
def recon_data(domain):
    domain = clean_domain(domain)
    data = {"domain": domain}

    print(f"[+] Scanning: {domain}")

    # IP
    try:
        ip = socket.gethostbyname(domain)
    except:
        ip = None

    data["ip"] = ip

    # DNS
    data["dns"] = get_dns(domain)

    # HTTP (HYBRID)
    res = get_response(domain)

    if not res:
        print("[!] Request failed")
        html, headers = "", {}
    else:
        html = res["html"]
        headers = res["headers"]
        print("[+] HTTP:", res["status"])

    data["headers"] = headers

    # Ports
    data["ports"] = scan_ports(ip) if ip else []

    # Title
    try:
        soup = BeautifulSoup(html, "html.parser")
        data["title"] = soup.title.string if soup.title else ""
    except:
        data["title"] = ""

    # Subdomains
    subs1 = get_subdomains(domain) or []
    subs2 = brute_subdomains(domain) or []

    # ensure both are lists
    if not isinstance(subs1, list):
        subs1 = []
    if not isinstance(subs2, list):
        subs2 = []

    data["subdomains"] = list(set(subs1 + subs2))

    # Tech
    data["tech"] = detect_tech(headers, html)

    # Directories
    data["directories"] = find_directories(domain)

    # Emails
# Emails
    emails_found = extract_emails(html)
    emails_generated = generate_emails(domain)

    data["emails"] = clean_emails(
        list(set(emails_found + emails_generated))
    )
    return data


# -----------------------------
# TEST
# -----------------------------
if __name__ == "__main__":
    target = input("Enter domain: ")
    result = recon_data(target)

    import json
    print(json.dumps(result, indent=2))