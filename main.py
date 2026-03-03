import sys
import time
import sqlite3
import subprocess
import os
import re
import random
import string
import html as _html_module
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Tee: write stdout to file AND terminal simultaneously
# ---------------------------------------------------------------------------

class _Tee:
    """Wraps sys.stdout to mirror all output into a log file."""
    def __init__(self, filepath: str):
        self._term = sys.__stdout__
        self._file = open(filepath, "a", encoding="utf-8")

    def write(self, data: str):
        self._term.write(data)
        # Strip ANSI color codes for the file
        import re
        self._file.write(re.sub(r"\033\[[0-9;]*m", "", data))

    def flush(self):
        self._term.flush()
        self._file.flush()

    def close(self):
        self._file.close()

    def fileno(self):
        return self._term.fileno()

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    MAGENTA= "\033[95m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

    @staticmethod
    def red(s):     return f"{C.RED}{s}{C.RESET}"
    @staticmethod
    def green(s):   return f"{C.GREEN}{s}{C.RESET}"
    @staticmethod
    def yellow(s):  return f"{C.YELLOW}{s}{C.RESET}"
    @staticmethod
    def cyan(s):    return f"{C.CYAN}{s}{C.RESET}"
    @staticmethod
    def magenta(s): return f"{C.MAGENTA}{s}{C.RESET}"
    @staticmethod
    def bold(s):    return f"{C.BOLD}{s}{C.RESET}"

# Use the system CA bundle so that institutional CAs (e.g. HARICA) are trusted.
# A custom bundle (ca-bundle-custom.pem) next to this script takes priority –
# useful when a server omits intermediate certs that Firefox fetches via AIA.
# To create it:
#   curl -s http://crt.harica.gr/HARICA-GEANT-TLS-E1.cer -o /tmp/int.cer
#   openssl x509 -inform DER -in /tmp/int.cer -out /tmp/int.pem
#   cat /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /tmp/int.pem > ca-bundle-custom.pem
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_SYSTEM_CA_PATHS = [
    os.path.join(_SCRIPT_DIR, "ca-bundle-custom.pem"),    # local custom bundle (highest priority)
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # Fedora / RHEL
    "/etc/ssl/certs/ca-certificates.crt",                  # Debian / Ubuntu
    "/etc/ssl/cert.pem",                                   # Alpine / macOS
]

def _find_ca_bundle():
    for path in _SYSTEM_CA_PATHS:
        if os.path.isfile(path):
            return path
    return True  # fall back to certifi

CA_BUNDLE = _find_ca_bundle()

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

DB_FILE = "crawler.db"


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS pages (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            url       TEXT    NOT NULL,
            canonical TEXT    UNIQUE NOT NULL,
            visited   INTEGER NOT NULL DEFAULT 0
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS findings (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            url        TEXT NOT NULL,
            param      TEXT NOT NULL,
            value      TEXT NOT NULL
        )"""
    )
    # --- migration: add canonical column to old DBs that only have url UNIQUE ---
    cols = {row[1] for row in conn.execute("PRAGMA table_info(pages)").fetchall()}
    if "canonical" not in cols:
        conn.execute("ALTER TABLE pages ADD COLUMN canonical TEXT")
        rows = conn.execute("SELECT id, url FROM pages").fetchall()
        for row_id, url in rows:
            conn.execute(
                "UPDATE pages SET canonical = ? WHERE id = ?",
                (canonical_url(url), row_id),
            )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_pages_canonical ON pages (canonical)"
        )
    conn.commit()
    return conn


def add_url(conn: sqlite3.Connection, url: str):
    """Insert url if its canonical form doesn't exist yet."""
    conn.execute(
        "INSERT OR IGNORE INTO pages (url, canonical, visited) VALUES (?, ?, 0)",
        (url, canonical_url(url)),
    )
    conn.commit()


def mark_visited(conn: sqlite3.Connection, url: str):
    conn.execute("UPDATE pages SET visited = 1 WHERE canonical = ?", (canonical_url(url),))
    conn.commit()


def is_visited(conn: sqlite3.Connection, url: str) -> bool:
    row = conn.execute(
        "SELECT visited FROM pages WHERE canonical = ?", (canonical_url(url),)
    ).fetchone()
    return row is not None and row[0] == 1


def url_known(conn: sqlite3.Connection, url: str) -> bool:
    """True if a URL with the same canonical form (path + param names) is known."""
    row = conn.execute(
        "SELECT id FROM pages WHERE canonical = ?", (canonical_url(url),)
    ).fetchone()
    return row is not None


def save_finding(conn: sqlite3.Connection, url: str, param: str, value: str):
    conn.execute(
        "INSERT INTO findings (url, param, value) VALUES (?, ?, ?)",
        (url, param, value),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------


def canonical_url(url: str) -> str:
    """
    Normalize a URL for deduplication.
    Keeps scheme + netloc + path + *sorted parameter names* (no values).
    Drops fragment.

    Examples (same canonical → treated as one URL):
      index.php?name=SONST&age=20  →  index.php?name&age
      index.php?name=BLA&age=3   →  index.php?name&age

    Different canonicals (counted separately):
      index.php                     →  index.php
      index.php?name=SONST           →  index.php?name
      index.php?age=20            →  index.php?age
      index.php?name=SONST&age=20  →  index.php?name&age
    """
    parsed = urlparse(url)
    param_names = sorted(parse_qs(parsed.query).keys())
    return parsed._replace(query="&".join(param_names), fragment="").geturl()


def same_domain(base_url: str, url: str) -> bool:
    base_host = urlparse(base_url).netloc
    target_host = urlparse(url).netloc
    return base_host == target_host


def extract_links(html: str, base_url: str):
    """Return absolute URLs found in <a href=...> tags."""
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        # resolve relative URLs
        full = urljoin(base_url, href)
        parsed = urlparse(full)
        # only http(s)
        if parsed.scheme in ("http", "https"):
            links.add(full)
    return links


def extract_get_params(url: str):
    """Return dict of GET parameters found in *url*."""
    parsed = urlparse(url)
    return parse_qs(parsed.query)


# ---------------------------------------------------------------------------
# Analyzer (called as subprocess)
# ---------------------------------------------------------------------------

def analyze_url(url: str):
    """
    Fetch *url*, extract GET params, store new links in DB.
    This function is invoked in a subprocess.
    """
    conn = get_db()

    print(C.cyan(f"[ANALYZE]") + f" {url}")

    # ---- check / report GET parameters already visible in the URL ----------
    params = extract_get_params(url)
    if params:
        for param, values in params.items():
            for val in values:
                print(C.yellow(f"  [GET PARAM]") + f" {param}={val}  (url: {url})")
                save_finding(conn, url, param, val)

    # ---- fetch page --------------------------------------------------------
    try:
        resp = requests.get(url, timeout=10, verify=CA_BUNDLE, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"})
        resp.raise_for_status()
        content_type = resp.headers.get("Content-Type", "")
        if "html" not in content_type:
            print(f"  [SKIP] Non-HTML content ({content_type.split(';')[0].strip()})")
            mark_visited(conn, url)
            conn.close()
            return
        html = resp.text
    except Exception as exc:
        print(C.red(f"  [ERROR]") + f" Could not fetch {url}: {exc}")
        mark_visited(conn, url)
        conn.close()
        return

    # ---- extract links from page -------------------------------------------
    links = extract_links(html, url)
    new_count = 0
    for link in links:
        if not url_known(conn, link):
            add_url(conn, link)
            new_count += 1
            # also check GET params right in the href
            link_params = extract_get_params(link)
            if link_params:
                for param, values in link_params.items():
                    for val in values:
                        print(C.yellow(f"  [GET PARAM in link]") + f" {param}={val}  (url: {link})")
                        save_finding(conn, link, param, val)

    print(f"  [LINKS] found {len(links)} links, " + C.green(f"{new_count} new"))

    # ---- mark as done ------------------------------------------------------
    mark_visited(conn, url)
    conn.close()


# ---------------------------------------------------------------------------
# Crawler (main loop)
# ---------------------------------------------------------------------------

def crawl(start_url: str, stay_on_domain: bool = True, delay: float = 0.5):
    conn = get_db()
    add_url(conn, start_url)

    try:
        while True:
            # Pull next unvisited URL directly from DB – no in-memory queue
            row = conn.execute(
                "SELECT url FROM pages WHERE visited = 0 LIMIT 1"
            ).fetchone()
            if not row:
                break
            url = row[0]

            if stay_on_domain and not same_domain(start_url, url):
                mark_visited(conn, url)
                continue

            # ---- spawn subprocess to analyze the URL -----------------------
            subprocess.run(
                [sys.executable, __file__, "--analyze", url],
                capture_output=False,
            )

            time.sleep(delay)

    except KeyboardInterrupt:
        print(C.yellow("\n\n[INTERRUPTED]") + " Crawl stopped by user. Saving report…")
    finally:
        conn.close()
        print(C.green("\n[DONE]") + " Crawl finished.")
        print_findings(start_url)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_findings(start_url: str = ""):
    conn = get_db()

    base_host = urlparse(start_url).netloc if start_url else ""

    total_pages = conn.execute("SELECT COUNT(*) FROM pages WHERE visited = 1").fetchone()[0]
    finding_rows = conn.execute(
        "SELECT url, param, value FROM findings ORDER BY url, param"
    ).fetchall()
    affected_urls = conn.execute(
        "SELECT COUNT(DISTINCT url) FROM findings"
    ).fetchone()[0]

    # all visited pages for this base domain
    if base_host:
        visited_pages = [
            row[0] for row in conn.execute(
                "SELECT url FROM pages WHERE visited = 1 ORDER BY url"
            ).fetchall()
            if urlparse(row[0]).netloc == base_host
        ]
    else:
        visited_pages = [
            row[0] for row in conn.execute(
                "SELECT url FROM pages WHERE visited = 1 ORDER BY url"
            ).fetchall()
        ]

    conn.close()

    sep = C.bold("=" * 60)
    print(f"\n{sep}")
    print(C.bold("CRAWL REPORT"))
    print(sep)
    print(f"  Base domain            : {C.cyan(base_host or '(all)')}")
    print(f"  Pages crawled          : {C.bold(str(total_pages))}")
    print(f"  GET parameters found   : {C.yellow(str(len(finding_rows)))}")
    print(f"  URLs with parameters   : {C.yellow(str(affected_urls))}")

    print(C.bold("\n----- CRAWLED PAGES -----"))
    for page_url in visited_pages:
        print(f"  {page_url}")

    if not finding_rows:
        print(C.green("\n  No GET parameters found."))
        print(sep)
        return

    print(C.bold("\n----- GET PARAMETER FINDINGS -----"))
    current_url = None
    for url, param, value in finding_rows:
        if url != current_url:
            if current_url is not None:
                print()
            print(f"  URL   : {C.cyan(url)}")
            current_url = url
        print(f"    Param : {C.yellow(param)} = {value}")
    print()
    print(sep)


# ---------------------------------------------------------------------------
# XSS scanner
# ---------------------------------------------------------------------------

XSS_WORDLIST = "/usr/share/wordlists/xss.txt"


def _load_wordlist_samples(n: int = 2) -> list[str]:
    """Pick n evenly-spaced raw payloads from the wordlist for extra coverage."""
    try:
        with open(XSS_WORDLIST, encoding="utf-8", errors="ignore") as f:
            lines = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return []
    if not lines:
        return []
    step = max(1, (len(lines) - 1) // max(n - 1, 1))
    return [lines[min(i * step, len(lines) - 1)] for i in range(n)]


def _check_reflection_context(html_text: str, canary: str) -> list[tuple[str, bool]]:
    """
    Analyse where/how *canary* appears in *html_text*.
    Returns list of (description, exploitable) tuples.
    """
    results: list[tuple[str, bool]] = []

    if canary not in html_text:
        # Check HTML-entity-encoded version (server escaped output)
        if _html_module.escape(canary) in html_text:
            results.append(("HTML-entity encoded – server escapes output (not exploitable)", False))
        # Check URL-encoded (e.g. %3Cscript%3E)
        url_enc = canary.replace("<", "%3C").replace(">", "%3E").replace("\"", "%22")
        if url_enc.lower() in html_text.lower():
            results.append(("URL-encoded reflection – filtered (not exploitable)", False))
        return results

    # Raw canary present – analyse context
    try:
        soup = BeautifulSoup(html_text, "html.parser")
    except Exception:
        results.append(("raw reflection in body (parse error, context unknown)", True))
        return results

    found_specific = False

    # 1. Inside <script> blocks → JS execution context
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            continue  # external script
        content = script.string or ""
        if canary in content:
            results.append(("inside <script> block – JS execution likely", True))
            found_specific = True

    # 2. Inside event-handler attributes (onclick, onerror, …)
    for tag in soup.find_all(True):
        for attr, val in tag.attrs.items():
            v = val if isinstance(val, str) else " ".join(val)
            if canary in v:
                if attr.lower().startswith("on"):
                    results.append((f"in event attribute <{tag.name} {attr}=> – JS execution likely", True))
                    found_specific = True
                elif attr.lower() in ("href", "src", "action", "formaction", "data"):
                    results.append((f"in navigation attribute <{tag.name} {attr}=> – may be exploitable", True))
                    found_specific = True
                else:
                    results.append((f"in attribute <{tag.name} {attr}=>", True))
                    found_specific = True

    # 3. Raw reflection in body (outside tags)
    if not found_specific and canary in html_text:
        results.append(("raw reflection in HTML body", True))

    return results


def run_xss_scan(start_url: str):
    """Test all known parameterised URLs for reflected and stored XSS."""
    # ---- unique per-scan canary so we can detect partial/mangled reflection --
    canary = "xsstest" + "".join(random.choices(string.ascii_lowercase, k=6))

    # 5 payloads of increasing sophistication, all embed the canary
    built_in_payloads: list[tuple[str, str]] = [
        (canary,                                                    "1-raw canary"),
        (f"<{canary}>",                                             "2-HTML tag"),
        (f"<script>alert('{canary}')</script>",                     "3-script tag"),
        (f'"><img src=x onerror=alert(\'{canary}\')>',              "4-attribute breakout"),
        (f"';alert('{canary}');//",                                 "5-JS string breakout"),
    ]
    # Augment with 2 raw wordlist payloads (no canary – verbatim tests)
    wordlist_extras = _load_wordlist_samples(2)

    conn = get_db()
    base_host = urlparse(start_url).netloc

    # Collect unique parameterised URLs for this domain
    rows = conn.execute("SELECT DISTINCT url FROM findings ORDER BY url").fetchall()
    target_urls = [r[0] for r in rows if urlparse(r[0]).netloc == base_host]

    # All visited pages (for stored XSS check)
    all_visited = [
        r[0] for r in conn.execute(
            "SELECT url FROM pages WHERE visited = 1 ORDER BY url"
        ).fetchall()
        if urlparse(r[0]).netloc == base_host
    ]
    conn.close()

    if not target_urls:
        print(C.yellow("[XSS] No parameterised URLs found in DB. Run a crawl first."))
        return

    sep = C.bold("=" * 60)
    print(f"\n{sep}")
    print(C.bold("XSS SCAN"))
    print(sep)
    print(f"  Target domain : {C.cyan(base_host)}")
    print(f"  Canary token  : {C.magenta(canary)}")
    print(f"  URLs to test  : {C.bold(str(len(target_urls)))}")
    print(f"  Built-in payloads ({len(built_in_payloads)}):")
    for _, label in built_in_payloads:
        print(f"    [{label}]")
    if wordlist_extras:
        print(f"  Wordlist payloads ({len(wordlist_extras)}): verbatim from {XSS_WORDLIST}")
    print()

    # (url, param, payload_label, context_description, exploitable)
    reflected_hits: list[tuple[str, str, str, str, bool]] = []
    stored_hits:   list[str] = []          # pages where canary was found after injection

    HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"}

    try:
        # ── Phase 1: Reflected XSS ───────────────────────────────────────────
        print(C.bold("--- Phase 1: Reflected XSS ---"))
        for base_url in target_urls:
            parsed = urlparse(base_url)
            params = parse_qs(parsed.query)
            print(C.cyan("[XSS TEST]") + f" {base_url}")

            for param in params:
                param_hit = False

                # Built-in canary payloads
                for payload, label in built_in_payloads:
                    if param_hit:
                        break
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url = parsed._replace(query=urlencode(test_params)).geturl()

                    try:
                        resp = requests.get(test_url, timeout=10, verify=CA_BUNDLE,
                                            headers=HEADERS, allow_redirects=True)
                        contexts = _check_reflection_context(resp.text, canary)

                        if not contexts:
                            print(C.green("  [safe]") + f" param={param} [{label}]")
                        else:
                            for desc, exploitable in contexts:
                                icon = C.red("[VULNERABLE]") if exploitable else C.yellow("[FILTERED]")
                                print(f"  {icon} param={C.yellow(param)} [{label}]")
                                print(f"    Context : {desc}")
                                if exploitable:
                                    reflected_hits.append((base_url, param, label, desc, True))
                                    param_hit = True
                                else:
                                    reflected_hits.append((base_url, param, label, desc, False))
                    except Exception as exc:
                        print(C.red("  [ERROR]") + f" {exc}")

                # Wordlist verbatim payloads (no canary – exact-match check)
                for payload in wordlist_extras:
                    if param_hit:
                        break
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url = parsed._replace(query=urlencode(test_params)).geturl()
                    try:
                        resp = requests.get(test_url, timeout=10, verify=CA_BUNDLE,
                                            headers=HEADERS, allow_redirects=True)
                        if payload in resp.text:
                            print(C.red("  [VULNERABLE]") + f" param={C.yellow(param)} [wordlist] verbatim reflected")
                            print(f"    Payload : {payload[:80]} ... (full payload may be longer)")
                            reflected_hits.append((base_url, param, "wordlist", "verbatim reflection", True))
                            param_hit = True
                        else:
                            print(C.green("  [safe]") + f" param={param} [wordlist]")
                    except Exception as exc:
                        print(C.red("  [ERROR]") + f" {exc}")

        # ── Phase 2: Stored XSS ──────────────────────────────────────────────
        print()
        print(C.bold(f"--- Phase 2: Stored XSS (checking {len(all_visited)} visited pages for canary) ---"))
        for page_url in all_visited:
            try:
                resp = requests.get(page_url, timeout=10, verify=CA_BUNDLE,
                                    headers=HEADERS, allow_redirects=True)
                if canary in resp.text:
                    contexts = _check_reflection_context(resp.text, canary)
                    for desc, exploitable in contexts:
                        icon = C.red("[STORED XSS]") if exploitable else C.yellow("[STORED/FILTERED]")
                        print(f"  {icon} {C.cyan(page_url)}")
                        print(f"    Context : {desc}")
                    stored_hits.append(page_url)
                else:
                    print(C.green("  [clean]") + f" {page_url}")
            except Exception as exc:
                print(C.red("  [ERROR]") + f" {page_url}: {exc}")

    except KeyboardInterrupt:
        print(C.yellow("\n\n[INTERRUPTED]") + " XSS scan stopped by user. Printing partial report…")

    # ── Report ───────────────────────────────────────────────────────────────
    exploitable = [(u, p, l, d) for u, p, l, d, ex in reflected_hits if ex]
    filtered    = [(u, p, l, d) for u, p, l, d, ex in reflected_hits if not ex]

    print(f"\n{sep}")
    print(C.bold("XSS SCAN REPORT"))
    print(sep)
    print(f"  Canary : {C.magenta(canary)}")
    print()

    print(C.bold("Reflected XSS:"))
    if not exploitable and not filtered:
        print(C.green("  No reflected XSS detected."))
    else:
        if exploitable:
            print(C.red(C.bold(f"  {len(exploitable)} exploitable reflection(s):")))
            shown: set[str] = set()
            for url, param, label, desc in exploitable:
                if url not in shown:
                    print(f"    {C.cyan(url)}")
                    shown.add(url)
                print(f"      " + C.red("VULNERABLE") + f" param={C.yellow(param)} [{label}]")
                print(f"      Context : {desc}")
            print()
        if filtered:
            print(C.yellow(f"  {len(filtered)} filtered/encoded reflection(s) – output is escaped:"))
            for url, param, label, desc in filtered:
                print(f"    param={param} [{label}] – {desc}")

    print()
    print(C.bold("Stored XSS:"))
    if not stored_hits:
        print(C.green("  No stored XSS detected."))
    else:
        print(C.red(C.bold(f"  Canary found on {len(stored_hits)} page(s) after injection!")))
        for page_url in stored_hits:
            print(f"    {C.cyan(page_url)}")
    print()
    print(sep)


# ---------------------------------------------------------------------------
# Helper: recrawl (reset DB for domain, then crawl)
# ---------------------------------------------------------------------------

def recrawl(start_url: str, stay_on_domain: bool = True):
    """Delete all DB entries for start_url's domain, then crawl fresh."""
    conn = get_db()
    base_host = urlparse(start_url).netloc

    # Remove pages and findings belonging to this domain
    pages = conn.execute("SELECT id, url FROM pages").fetchall()
    ids_to_delete = [str(pid) for pid, url in pages if urlparse(url).netloc == base_host]
    if ids_to_delete:
        conn.execute(f"DELETE FROM pages WHERE id IN ({','.join(ids_to_delete)})")
    findings = conn.execute("SELECT id, url FROM findings").fetchall()
    fids = [str(fid) for fid, url in findings if urlparse(url).netloc == base_host]
    if fids:
        conn.execute(f"DELETE FROM findings WHERE id IN ({','.join(fids)})")
    conn.commit()
    conn.close()

    print(C.yellow(f"[RECRAWL]") + f" Reset {len(ids_to_delete)} pages for {C.cyan(base_host)}")
    crawl(start_url, stay_on_domain=stay_on_domain)


# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

def show_help():
    prog = os.path.basename(sys.argv[0])
    print(f"""
{C.bold('Usage:')}
  python {prog} {C.cyan('<start_url>')} [options]

{C.bold('Options:')}
  {C.cyan('(none)')}          Crawl start_url, stay on same domain
  {C.cyan('--all-domains')}   Follow links to other domains too
  {C.cyan('--recrawl')}       Reset DB for start_url's domain and re-crawl
  {C.cyan('--xss')}           Run reflected XSS tests on stored parameterised URLs
  {C.cyan('--help')}          Show this help

{C.bold('Examples:')}
  python {prog} https://example.com
  python {prog} https://example.com --recrawl
  python {prog} https://example.com --xss
  python {prog} https://example.com --all-domains
""")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    args = sys.argv[1:]

    # Internal subprocess mode (no tee – output is already captured by parent)
    if len(sys.argv) == 3 and sys.argv[1] == "--analyze":
        analyze_url(sys.argv[2])
        sys.exit(0)

    # Help
    if "--help" in args or "-h" in args or not args:
        show_help()
        sys.exit(0)

    # Determine start URL (first non-flag argument)
    start = next((a for a in args if not a.startswith("--")), None)
    if not start:
        show_help()
        sys.exit(1)

    # Set up output tee → <domain>.txt
    domain_name = urlparse(start).netloc.replace(":", "_") or "output"
    log_path = os.path.join(_SCRIPT_DIR, f"{domain_name}.txt")
    tee = _Tee(log_path)
    sys.stdout = tee
    print(f"[LOG] Output mirrored to {log_path}")

    stay = "--all-domains" not in args

    try:
        if "--recrawl" in args:
            recrawl(start, stay_on_domain=stay)
        elif "--xss" in args:
            run_xss_scan(start)
        else:
            crawl(start, stay_on_domain=stay)
    finally:
        sys.stdout = sys.__stdout__
        tee.close()