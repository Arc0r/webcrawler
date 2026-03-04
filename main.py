import sys
import time
import sqlite3
import subprocess
import os
import re
import random
import string
import html as _html_module
import threading
import concurrent.futures
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

_RESULTS_DIR = os.path.join(_SCRIPT_DIR, "results")
os.makedirs(_RESULTS_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

DB_FILE = "crawler.db"


def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")  # allow concurrent subprocess writes
    conn.execute(
        """CREATE TABLE IF NOT EXISTS pages (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT    NOT NULL,
            canonical   TEXT    UNIQUE NOT NULL,
            visited     INTEGER NOT NULL DEFAULT 0,
            status_code INTEGER NOT NULL DEFAULT 0,
            skip_reason TEXT    NOT NULL DEFAULT ''
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
    if "status_code" not in cols:
        conn.execute("ALTER TABLE pages ADD COLUMN status_code INTEGER NOT NULL DEFAULT 0")
    if "skip_reason" not in cols:
        conn.execute("ALTER TABLE pages ADD COLUMN skip_reason TEXT NOT NULL DEFAULT ''")
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


def set_page_status(conn: sqlite3.Connection, url: str, status_code: int, skip_reason: str = ""):
    """Record the HTTP status code and optional skip reason for a page."""
    conn.execute(
        "UPDATE pages SET status_code = ?, skip_reason = ? WHERE canonical = ?",
        (status_code, skip_reason, canonical_url(url)),
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


_IGNORED_EXTENSIONS = {
    # media
    ".mp4", ".m4v", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm",
    ".mp3", ".ogg", ".wav", ".flac", ".aac",
    # images
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp", ".ico", ".tif", ".tiff",
    # documents
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods",
    # archives
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".rar", ".7z",
    # code / data
    ".js", ".css", ".json", ".xml", ".csv", ".woff", ".woff2", ".ttf", ".eot",
}

# Ignore patterns set by --ignore flag; inherited by subprocesses via env var.
import fnmatch as _fnmatch
_IGNORE_PATTERNS: list[str] = [
    p for p in os.environ.get("CRAWLER_IGNORE", "").split(",") if p
]


def _is_crawlable(url: str) -> bool:
    """Return False if the URL matches an ignored extension or user pattern.

    Pattern prefixes:
      param:NAME  – skip any URL whose query string contains a parameter named NAME
      (no prefix) – substring or glob match against the full URL
    """
    path = urlparse(url).path.lower().split("?")[0]
    _, ext = os.path.splitext(path)
    if ext in _IGNORED_EXTENSIONS:
        return False
    url_params = set(parse_qs(urlparse(url).query).keys())
    for pat in _IGNORE_PATTERNS:
        if pat.startswith("param:"):
            param_name = pat[len("param:"):]
            if param_name in url_params:
                return False
        elif _fnmatch.fnmatch(url, pat) or pat in url:
            return False
    return True


def extract_links(html: str, base_url: str):
    """Return absolute URLs found in <a href=...> tags."""
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        # resolve relative URLs
        full = urljoin(base_url, href)
        parsed = urlparse(full)
        # only http(s) and crawlable file types
        if parsed.scheme in ("http", "https") and _is_crawlable(full):
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
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as http_err:
            status = resp.status_code
            print(C.red(f"  [HTTP {status}]") + f" {url}")
            set_page_status(conn, url, status)
            mark_visited(conn, url)
            conn.close()
            return
        content_type = resp.headers.get("Content-Type", "")
        if "html" not in content_type:
            ct_short = content_type.split(";")[0].strip()
            print(f"  [SKIP] Non-HTML content ({ct_short})")
            set_page_status(conn, url, resp.status_code, f"media:{ct_short}")
            mark_visited(conn, url)
            conn.close()
            return
        set_page_status(conn, url, resp.status_code)
        html = resp.text
    except requests.exceptions.HTTPError:
        pass  # handled above
    except Exception as exc:
        print(C.red(f"  [ERROR]") + f" Could not fetch {url}: {exc}")
        set_page_status(conn, url, 0, f"error:{exc}")
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

def crawl(start_url: str, stay_on_domain: bool = True, delay: float = 0.5, workers: int = 1):
    conn = get_db()
    add_url(conn, start_url)
    _db_lock = threading.Lock()  # guards parent-side DB reads/claims

    def _claim_next() -> str | None:
        """Atomically grab and pre-mark one unvisited URL. Returns None if queue empty."""
        with _db_lock:
            while True:
                row = conn.execute(
                    "SELECT url FROM pages WHERE visited = 0 LIMIT 1"
                ).fetchone()
                if not row:
                    return None
                url = row[0]
                # Pre-mark as visited so no other worker claims the same URL
                conn.execute(
                    "UPDATE pages SET visited = 1 WHERE canonical = ?",
                    (canonical_url(url),),
                )
                conn.commit()
                if stay_on_domain and not same_domain(start_url, url):
                    continue  # already marked, skip silently
                if not _is_crawlable(url):
                    continue  # matches --ignore pattern or bad extension
                return url

    def _run_worker(url: str):
        subprocess.run(
            [sys.executable, __file__, "--analyze", url],
            capture_output=False,
        )
        time.sleep(delay)

    if workers > 1:
        print(C.cyan(f"[CRAWL]") + f" Starting with {C.bold(str(workers))} parallel workers")

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            pending: set[concurrent.futures.Future] = set()

            while True:
                # Fill worker slots with freshly claimed URLs
                while len(pending) < workers:
                    url = _claim_next()
                    if url is None:
                        break
                    pending.add(executor.submit(_run_worker, url))

                if not pending:
                    break  # nothing running and nothing left in DB

                # Wait for at least one worker to finish (may have added new URLs)
                done, pending = concurrent.futures.wait(
                    pending, return_when=concurrent.futures.FIRST_COMPLETED
                )
                # Propagate any worker exceptions
                for f in done:
                    f.result()

    except KeyboardInterrupt:
        print(C.yellow("\n\n[INTERRUPTED]") + " Crawl stopped by user. Saving report…")
    finally:
        conn.close()
        print(C.green("\n[DONE]") + " Crawl finished.")
        print_findings(start_url)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# HTML Crawl Report
# ---------------------------------------------------------------------------

_HTML_STYLE = """
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e;
    --green: #3fb950; --yellow: #d29922; --red: #f85149;
    --blue: #58a6ff; --purple: #bc8cff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }
  h1 { color: var(--blue); font-size: 1.8rem; margin-bottom: 0.25rem; }
  .subtitle { color: var(--muted); margin-bottom: 2rem; font-size: 0.9rem; }
  .stats-grid { display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 2rem; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
                padding: 1rem 1.5rem; min-width: 160px; }
  .stat-card .label { color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .stat-card .value { font-size: 1.8rem; font-weight: bold; margin-top: 0.2rem; }
  .value.green { color: var(--green); } .value.yellow { color: var(--yellow); }
  .value.red { color: var(--red); } .value.blue { color: var(--blue); }
  details { margin: 0.75rem 0; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
  summary { padding: 0.8rem 1.2rem; cursor: pointer; background: var(--surface);
             display: flex; align-items: center; gap: 0.6rem; font-weight: 600;
             list-style: none; user-select: none; }
  summary::-webkit-details-marker { display: none; }
  summary::before { content: '▶'; font-size: 0.7rem; transition: transform 0.2s; color: var(--muted); }
  details[open] summary::before { transform: rotate(90deg); }
  summary .badge { margin-left: auto; background: var(--border); border-radius: 999px;
                   padding: 0.15rem 0.6rem; font-size: 0.75rem; font-weight: 700; }
  summary.red   { border-left: 4px solid var(--red); }    summary.red .badge   { background: var(--red); color: #fff; }
  summary.yellow{ border-left: 4px solid var(--yellow); } summary.yellow .badge{ background: var(--yellow); color: #000; }
  summary.green { border-left: 4px solid var(--green); }  summary.green .badge { background: var(--green); color: #000; }
  summary.blue  { border-left: 4px solid var(--blue); }   summary.blue .badge  { background: var(--blue); color: #000; }
  summary.muted { border-left: 4px solid var(--muted); }
  .detail-body { padding: 0.5rem 1.2rem 1rem; background: var(--bg); }
  .url-list { list-style: none; }
  .url-list li { padding: 0.35rem 0; border-bottom: 1px solid var(--border); font-size: 0.85rem;
                  display: flex; flex-direction: column; gap: 0.1rem; word-break: break-all; }
  .url-list li:last-child { border-bottom: none; }
  a { color: var(--blue); text-decoration: none; } a:hover { text-decoration: underline; }
  .tag { display: inline-block; font-size: 0.72rem; padding: 0.1rem 0.45rem; border-radius: 4px;
          font-weight: 600; margin-right: 0.3rem; }
  .tag.red    { background: rgba(248,81,73,0.2); color: var(--red); }
  .tag.yellow { background: rgba(210,153,34,0.2); color: var(--yellow); }
  .tag.green  { background: rgba(63,185,80,0.2);  color: var(--green); }
  .tag.blue   { background: rgba(88,166,255,0.2); color: var(--blue); }
  .tag.muted  { background: rgba(139,148,158,0.2); color: var(--muted); }
  .param-row { color: var(--purple); font-size: 0.8rem; }
  .empty { color: var(--muted); font-style: italic; padding: 0.5rem 0; }
  .xss-block { padding: 0.6rem; margin: 0.4rem 0; border-radius: 6px; border: 1px solid var(--border); background: var(--surface); }
  .xss-block .ctx  { font-size: 0.8rem; color: var(--muted); margin-top: 0.3rem; }
  .xss-block .turl { font-size: 0.78rem; color: var(--blue); margin-top: 0.2rem; word-break: break-all; }
</style>
"""

def _html_section(title: str, items: list[str], color: str = "muted", open_by_default: bool = False) -> str:
    """Render a collapsible <details> section with an <ul> of raw HTML item strings."""
    open_attr = " open" if open_by_default else ""
    badge = f'<span class="badge">{len(items)}</span>'
    header = f'<summary class="{color}">{title}{badge}</summary>'
    if not items:
        body = '<div class="detail-body"><p class="empty">None found.</p></div>'
    else:
        rows = "\n".join(f"<li>{item}</li>" for item in items)
        body = f'<div class="detail-body"><ul class="url-list">{rows}</ul></div>'
    return f"<details{open_attr}>{header}{body}</details>"


def generate_crawl_report_html(start_url: str, out_path: str):
    """Query the DB and write a self-contained HTML crawl report to *out_path*."""
    import datetime
    conn = get_db()
    base_host = urlparse(start_url).netloc if start_url else ""

    all_pages = conn.execute(
        "SELECT url, visited, status_code, skip_reason FROM pages ORDER BY url"
    ).fetchall()
    findings = conn.execute(
        "SELECT url, param, value FROM findings ORDER BY url, param"
    ).fetchall()
    conn.close()

    # Partition pages
    pages_404, pages_403, pages_other_err, pages_media, pages_error = [], [], [], [], []
    pages_ok, pages_external = [], []

    for url, visited, status_code, skip_reason in all_pages:
        is_internal = not base_host or urlparse(url).netloc == base_host
        if not is_internal:
            pages_external.append(url)
            continue
        if status_code == 404:
            pages_404.append(url)
        elif status_code == 403:
            pages_403.append(url)
        elif status_code and status_code >= 400:
            pages_other_err.append((url, status_code))
        elif skip_reason.startswith("media:"):
            ct = skip_reason[len("media:"):]
            pages_media.append((url, ct))
        elif skip_reason.startswith("error:"):
            pages_error.append((url, skip_reason[len("error:"):]))
        elif visited:
            pages_ok.append(url)

    # GET-param findings grouped by URL
    params_by_url: dict[str, list[tuple[str, str]]] = {}
    for url, param, value in findings:
        if not base_host or urlparse(url).netloc == base_host:
            params_by_url.setdefault(url, []).append((param, value))

    total_crawled = len(pages_ok) + len(pages_404) + len(pages_403) + len(pages_other_err) + len(pages_media) + len(pages_error)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Build section items ────────────────────────────────────────────────
    def _url_link(u: str) -> str:
        safe = _html_module.escape(u)
        return f'<a href="{safe}" target="_blank">{safe}</a>'

    items_404   = [_url_link(u) for u in pages_404]
    items_403   = [_url_link(u) for u in pages_403]
    items_other = [f'<span class="tag red">HTTP {sc}</span>{_url_link(u)}' for u, sc in pages_other_err]
    items_media = [f'<span class="tag muted">{_html_module.escape(ct)}</span>{_url_link(u)}' for u, ct in pages_media]
    items_error = [f'<span class="tag red">error</span>{_url_link(u)}<span class="param-row">{_html_module.escape(e[:120])}</span>' for u, e in pages_error]
    items_ext   = [_url_link(u) for u in sorted(set(pages_external))]
    items_ok    = [_url_link(u) for u in pages_ok]

    # GET param items: one collapsible entry per URL
    param_items = []
    for url, param_list in sorted(params_by_url.items()):
        params_html = " ".join(
            f'<span class="tag yellow">{_html_module.escape(p)}</span><span class="param-row">={_html_module.escape(v[:60])}</span>'
            for p, v in param_list
        )
        param_items.append(f"{_url_link(url)}<div>{params_html}</div>")

    # ── Stat cards ─────────────────────────────────────────────────────────
    def _card(label: str, value, color: str = "blue") -> str:
        return (f'<div class="stat-card"><div class="label">{label}</div>'
                f'<div class="value {color}">{value}</div></div>')

    stats = (
        _card("Pages crawled", total_crawled, "blue") +
        _card("404 errors", len(pages_404), "red" if pages_404 else "green") +
        _card("403 forbidden", len(pages_403), "yellow" if pages_403 else "green") +
        _card("Media skipped", len(pages_media), "muted") +
        _card("External links", len(set(pages_external)), "blue") +
        _card("URLs w/ params", len(params_by_url), "yellow" if params_by_url else "green")
    )

    # ── Assemble HTML ──────────────────────────────────────────────────────
    sections = (
        _html_section("🔴 404 Not Found", items_404, "red") +
        _html_section("🟡 403 Forbidden", items_403, "yellow") +
        _html_section("⚠️ Other HTTP Errors", items_other, "red") +
        _html_section("🎞️ Media / Non-HTML (skipped)", items_media, "muted") +
        _html_section("❌ Fetch Errors", items_error, "red") +
        _html_section("🔗 External Links", items_ext, "blue") +
        _html_section("🔍 URLs with GET Parameters", param_items, "yellow", open_by_default=bool(param_items)) +
        _html_section("✅ Successfully Crawled Pages", items_ok, "green")
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Crawl Report – {_html_module.escape(base_host)}</title>
  {_HTML_STYLE}
</head>
<body>
  <h1>Crawl Report</h1>
  <p class="subtitle">Domain: <strong>{_html_module.escape(base_host)}</strong> &nbsp;|&nbsp; Generated: {timestamp}</p>
  <div class="stats-grid">{stats}</div>
  {sections}
</body>
</html>"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(C.green(f"[REPORT]") + f" HTML crawl report saved to {out_path}")


# ---------------------------------------------------------------------------
# HTML XSS Report
# ---------------------------------------------------------------------------

def generate_xss_report_html(
    start_url: str,
    canary: str,
    reflected_hits: list,  # (base_url, param, label, desc, exploitable, test_url)
    stored_hits: list[str],
    out_path: str,
):
    """Write a self-contained HTML XSS report to *out_path*."""
    import datetime
    base_host = urlparse(start_url).netloc if start_url else ""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    exploitable  = [(u, p, l, d, tu) for u, p, l, d, ex, tu in reflected_hits if ex]
    filtered_ref = [(u, p, l, d, tu) for u, p, l, d, ex, tu in reflected_hits if not ex]

    def _url_link(u: str) -> str:
        safe = _html_module.escape(u)
        return f'<a href="{safe}" target="_blank">{safe}</a>'

    # Reflected exploitable – group by base URL
    refl_by_url: dict[str, list] = {}
    for url, param, label, desc, test_url in exploitable:
        refl_by_url.setdefault(url, []).append((param, label, desc, test_url))

    refl_items = []
    for url, hits in sorted(refl_by_url.items()):
        inner = "".join(
            f'<div class="xss-block">'
            f'<span class="tag red">VULNERABLE</span>'
            f'<span class="tag yellow">param={_html_module.escape(p)}</span>'
            f'&nbsp;[{_html_module.escape(l)}]'
            f'<div class="ctx">{_html_module.escape(d)}</div>'
            f'<div class="turl"><a href="{_html_module.escape(tu)}" target="_blank">Test URL</a>: {_html_module.escape(tu)}</div>'
            f'</div>'
            for p, l, d, tu in hits
        )
        refl_items.append(f"{_url_link(url)}{inner}")

    # Reflected filtered
    filt_items = [
        f'<span class="tag muted">{_html_module.escape(p)}</span>&nbsp;[{_html_module.escape(l)}]'
        f'<div class="ctx">{_html_module.escape(d)}</div>'
        for _, p, l, d, _ in filtered_ref
    ]

    # Stored XSS
    stored_items = [_url_link(u) for u in stored_hits]

    # Stat cards
    def _card(label: str, value, color: str = "blue") -> str:
        return (f'<div class="stat-card"><div class="label">{label}</div>'
                f'<div class="value {color}">{value}</div></div>')

    total_vulns = len(exploitable) + len(stored_hits)
    stats = (
        _card("Exploitable (Reflected)", len(exploitable), "red" if exploitable else "green") +
        _card("Stored XSS", len(stored_hits), "red" if stored_hits else "green") +
        _card("Filtered (Reflected)", len(filtered_ref), "yellow" if filtered_ref else "green") +
        _card("Total Vulnerabilities", total_vulns, "red" if total_vulns else "green")
    )

    sections = (
        _html_section("🔴 Exploitable Reflected XSS", refl_items, "red", open_by_default=bool(refl_items)) +
        _html_section("💾 Stored XSS", stored_items, "red", open_by_default=bool(stored_items)) +
        _html_section("🟡 Filtered / Encoded Reflections", filt_items, "yellow")
    )

    verdict = (
        f'<p style="color:var(--red);font-size:1.1rem;font-weight:bold;margin-bottom:1.5rem">'
        f'⚠️ {total_vulns} exploitable vulnerability/ies found!</p>'
        if total_vulns else
        f'<p style="color:var(--green);font-size:1.1rem;font-weight:bold;margin-bottom:1.5rem">'
        f'✅ No exploitable XSS vulnerabilities found.</p>'
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>XSS Report – {_html_module.escape(base_host)}</title>
  {_HTML_STYLE}
</head>
<body>
  <h1>XSS Scan Report</h1>
  <p class="subtitle">Domain: <strong>{_html_module.escape(base_host)}</strong> &nbsp;|&nbsp; Canary: <code>{_html_module.escape(canary)}</code> &nbsp;|&nbsp; Generated: {timestamp}</p>
  {verdict}
  <div class="stats-grid">{stats}</div>
  {sections}
</body>
</html>"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(C.green(f"[REPORT]") + f" HTML XSS report saved to {out_path}")


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
    else:
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

    # Generate HTML crawl report
    if start_url:
        domain_name = urlparse(start_url).netloc.replace(":", "_") or "output"
        html_path = os.path.join(_RESULTS_DIR, f"{domain_name}_crawl_report.html")
        generate_crawl_report_html(start_url, html_path)


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


def _check_reflection_context(html_text: str, canary: str, payload: str = "") -> list[tuple[str, bool]]:
    """
    Analyse where/how *canary* appears in *html_text*.
    Returns list of (description, exploitable) tuples.

    Detection logic:
    - If canary absent: check for entity/URL-encoded forms → filtered
    - If payload had special chars (<>"') but they didn't survive: → filtered
    - If payload IS literal in raw html: parse and determine execution context
    """
    results: list[tuple[str, bool]] = []

    _html_special  = set('<>"\'')
    _breakout_chars = set('<>"\'\x00')
    _nav_attrs     = {"href", "src", "action", "formaction", "data"}
    payload_has_special = bool(payload and _html_special & set(payload))
    payload_specials    = _html_special & set(payload) if payload else set()

    # ── canary not in raw html at all ────────────────────────────────────────
    if canary not in html_text:
        if _html_module.escape(canary) in html_text:
            results.append(("HTML-entity encoded – server escapes output (not exploitable)", False))
        url_enc = canary.replace("<", "%3C").replace(">", "%3E").replace('"', "%22")
        if url_enc.lower() in html_text.lower():
            results.append(("URL-encoded reflection – filtered (not exploitable)", False))
        return results

    # ── canary present, but payload's special chars were encoded/stripped ────
    if payload_has_special and payload not in html_text:
        esc_payload = _html_module.escape(payload)          # e.g. &lt;canary&gt;
        url_payload = payload.replace("<", "%3C").replace(">", "%3E").replace('"', "%22")
        if esc_payload in html_text:
            results.append(("HTML-entity encoded – &lt; &gt; escaped by server (not exploitable)", False))
        elif url_payload.lower() in html_text.lower():
            results.append(("URL-encoded – %3C %3E present (not exploitable)", False))
        else:
            # Check each special char individually
            all_encoded = all(
                _html_module.escape(c) in html_text or c.replace("<", "%3C").replace(">", "%3E") in html_text
                for c in payload_specials
            )
            msg = ("special chars entity/URL-encoded by server (not exploitable)" if all_encoded
                   else "special chars stripped or mangled by server (not exploitable)")
            results.append((msg, False))
        return results

    # ── payload present literally – parse and classify context ───────────────
    try:
        soup = BeautifulSoup(html_text, "html.parser")
    except Exception:
        results.append(("raw reflection in body (parse error, context unknown)", True))
        return results

    found_specific = False

    def _canary_literally_in_raw(tag) -> bool:
        """
        True if canary appears in the re-serialised tag source WITHOUT being
        immediately preceded by & or % (which would indicate entity/URL-encoding).
        BS4's str() re-encodes < > & in attribute values, so if the server
        entity-encoded the canary, it'll appear as &lt;canary&gt; in str(tag).
        """
        raw = str(tag)
        idx = raw.find(canary)
        while idx != -1:
            before = raw[idx - 1] if idx > 0 else ""
            if before not in ("&", "%"):
                return True
            idx = raw.find(canary, idx + 1)
        return False

    # 1. Inside <script> blocks → JS execution context
    for script in soup.find_all("script"):
        if script.get("src"):
            continue
        content = script.string or ""
        if canary in content:
            results.append(("inside <script> block – JS execution likely", True))
            found_specific = True

    # 2. Inside attributes
    for tag in soup.find_all(True):
        for attr, val in tag.attrs.items():
            v = val if isinstance(val, str) else " ".join(val)
            if canary not in v:
                continue

            attr_l = attr.lower()

            if attr_l.startswith("on"):
                if _canary_literally_in_raw(tag):
                    results.append((f"in event attribute <{tag.name} {attr}=> – JS execution likely", True))
                    found_specific = True

            elif attr_l in _nav_attrs:
                if _canary_literally_in_raw(tag):
                    can_breakout = bool(payload and _breakout_chars & set(payload))
                    is_js = v.lstrip().lower().startswith("javascript:")
                    if can_breakout or is_js:
                        results.append((f"in navigation attribute <{tag.name} {attr}=> – breakout possible", True))
                    else:
                        results.append((f"reflected in <{tag.name} {attr}=> (no breakout chars – informational)", False))
                    found_specific = True
                else:
                    results.append((f"entity/URL-encoded in <{tag.name} {attr}=> – filtered (not exploitable)", False))
                    found_specific = True

            else:
                if _canary_literally_in_raw(tag):
                    results.append((f"in attribute <{tag.name} {attr}=>", True))
                    found_specific = True

    # 3. Canary injected as an actual HTML element, e.g. <canary> in the DOM
    if not found_specific:
        try:
            injected = soup.find(canary)
        except Exception:
            injected = None
        if injected is not None and f"<{canary}" in html_text:
            # Server did NOT escape <  – HTML injection confirmed.
            # Not directly executable by itself, but < > are unfiltered.
            results.append((
                f"HTML tag injected – <{canary}> element created in DOM – "
                "< not filtered (HTML injection, not directly executable)",
                True,
            ))
            found_specific = True

    # 4. Fallback: canary somewhere in raw html but no specific context found
    if not found_specific:
        results.append(("raw reflection in HTML body", True))

    return results


def _check_xss_context(html_text: str, payload: str) -> list[tuple[str, bool]]:
    """
    Determine whether a verbatim-reflected wordlist payload (no separate canary)
    is in an executable context.

    Returns a list of (description, exploitable) tuples, same as
    _check_reflection_context.
    """
    esc = _html_module.escape(payload)
    if esc in html_text and payload not in html_text:
        return [("HTML-entity encoded – filtered (not exploitable)", False)]
    if payload not in html_text:
        url_enc = payload.replace("<", "%3C").replace(">", "%3E").replace('"', "%22")
        if url_enc.lower() in html_text.lower():
            return [("URL-encoded reflection – filtered (not exploitable)", False)]
        return []

    pl = payload.lower()

    # script tag injected
    if "<script" in pl:
        soup = BeautifulSoup(html_text, "html.parser")
        for script in soup.find_all("script"):
            if not script.get("src") and payload[:30] in (script.string or ""):
                return [("payload inside <script> block – JS execution likely", True)]
        # script present in raw HTML and not entity-encoded
        if "<script" in html_text.lower():
            return [("<script> tag reflected unescaped – JS execution likely", True)]

    # event handler attributes
    for ev in ("onerror", "onload", "onclick", "onmouseover", "onfocus"):
        if f"{ev}=" in pl and f"{ev}=" in html_text.lower():
            return [(f"event handler ({ev}=) reflected unescaped – JS execution likely", True)]

    # javascript: URI
    if "javascript:" in pl and "javascript:" in html_text.lower():
        return [("javascript: URI reflected – JS execution possible", True)]

    # < and > are unescaped but no obviously executable pattern
    if "<" in payload and "<" in html_text:
        return [("HTML tag reflected unescaped (< not filtered) – potential HTML injection", True)]

    return [("verbatim reflection – no executable pattern detected", False)]


def run_advanced_scan(url: str, param: str | None = None):
    """
    Run ALL payloads from xss.txt plus the built-in canary suite against a
    single URL (and optionally a single named parameter).
    No DB / crawl required – call directly with the target URL.

    Example:
      python main.py --advancedscan "http://localhost/xss.php?test=foo"
      python main.py --advancedscan "http://localhost/xss.php?test=foo" test
    """
    canary = "xsstest" + "".join(random.choices(string.ascii_lowercase, k=6))

    built_in_payloads: list[tuple[str, str]] = [
        (canary,                                                    "1-raw canary"),
        (f"<{canary}>",                                             "2-HTML tag"),
        (f"<script>alert('{canary}')</script>",                     "3-script tag"),
        (f'"><img src=x onerror=alert(\'{canary}\')>',              "4-attribute breakout"),
        (f"';alert('{canary}');//",                                 "5-JS string breakout"),
    ]

    # Load ALL wordlist payloads
    wordlist_payloads: list[str] = []
    try:
        with open(XSS_WORDLIST, encoding="utf-8", errors="ignore") as f:
            wordlist_payloads = [ln.strip() for ln in f if ln.strip()]
    except FileNotFoundError:
        print(C.yellow(f"[WARNING] Wordlist {XSS_WORDLIST} not found – only built-in payloads will be used"))

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        print(C.red("[ERROR] No query parameters found in URL."))
        print(C.yellow("  Add the parameter you want to test, e.g.:  ?test=foo"))
        return

    # Which parameters to test
    if param:
        if param not in params:
            print(C.yellow(f"[WARNING] Parameter '{param}' not in URL; testing all params: {list(params.keys())}"))
            test_params_list = list(params.keys())
        else:
            test_params_list = [param]
    else:
        test_params_list = list(params.keys())

    HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"}
    total_tests = (len(built_in_payloads) + len(wordlist_payloads)) * len(test_params_list)

    sep = C.bold("=" * 60)
    print(f"\n{sep}")
    print(C.bold("ADVANCED XSS SCAN"))
    print(sep)
    print(f"  Target URL        : {C.cyan(url)}")
    print(f"  Parameters tested : {C.yellow(', '.join(test_params_list))}")
    print(f"  Canary token      : {C.magenta(canary)}")
    print(f"  Built-in payloads : {len(built_in_payloads)}")
    print(f"  Wordlist payloads : {len(wordlist_payloads)}  (from {XSS_WORDLIST})")
    print(f"  Total tests       : {C.bold(str(total_tests))}")
    print()

    # (test_param, label, exploitable, description, test_url)
    all_hits: list[tuple[str, str, bool, str, str]] = []

    try:
        for test_param in test_params_list:
            print(C.bold(f"--- Parameter: {test_param} ---"))

            # ── built-in canary payloads ──────────────────────────────────────
            for payload, label in built_in_payloads:
                test_p = {k: v[0] for k, v in params.items()}
                test_p[test_param] = payload
                test_url = parsed._replace(query=urlencode(test_p)).geturl()
                try:
                    resp = requests.get(test_url, timeout=10, verify=CA_BUNDLE,
                                        headers=HEADERS, allow_redirects=True)
                    contexts = _check_reflection_context(resp.text, canary, payload)
                    if not contexts:
                        print(C.green("  [safe]") + f" [{label}]")
                    else:
                        for desc, exploitable in contexts:
                            icon = C.red("[VULNERABLE]") if exploitable else C.yellow("[FILTERED]")
                            print(f"  {icon} [{label}]")
                            print(f"    Context  : {desc}")
                            print(f"    Payload  : {payload[:120]}")
                            if exploitable:
                                print(f"    Test URL : {C.magenta(test_url)}")
                            all_hits.append((test_param, label, exploitable, desc, test_url))
                except Exception as exc:
                    print(C.red("  [ERROR]") + f" [{label}] {exc}")

            # ── wordlist payloads ─────────────────────────────────────────────
            if wordlist_payloads:
                print(C.bold(f"  Running {len(wordlist_payloads)} wordlist payloads … (press Ctrl-C to stop early)"))
            vuln_count = 0
            safe_count = 0
            for i, payload in enumerate(wordlist_payloads, 1):
                test_p = {k: v[0] for k, v in params.items()}
                test_p[test_param] = payload
                test_url = parsed._replace(query=urlencode(test_p)).geturl()
                try:
                    resp = requests.get(test_url, timeout=10, verify=CA_BUNDLE,
                                        headers=HEADERS, allow_redirects=True)
                    if payload in resp.text:
                        contexts = _check_xss_context(resp.text, payload)
                        for desc, exploitable in contexts:
                            icon = C.red("[VULNERABLE]") if exploitable else C.yellow("[REFLECTED]")
                            print(f"  {icon} [wordlist #{i}] {payload[:70]}")
                            print(f"    Context  : {desc}")
                            if exploitable:
                                print(f"    Test URL : {C.magenta(test_url)}")
                            all_hits.append((test_param, f"wordlist#{i}", exploitable, desc, test_url))
                            vuln_count += 1
                    else:
                        safe_count += 1
                except Exception as exc:
                    print(C.red("  [ERROR]") + f" [wordlist #{i}] {exc}")
            if wordlist_payloads:
                print(f"  [wordlist done] {C.red(str(vuln_count))} reflected, {C.green(str(safe_count))} safe")

    except KeyboardInterrupt:
        print(C.yellow("\n\n[INTERRUPTED]") + " Advanced scan stopped by user. Printing partial report…")

    # ── Report ────────────────────────────────────────────────────────────────
    exploitable = [(p, l, d, tu) for p, l, ex, d, tu in all_hits if ex]
    filtered    = [(p, l, d, tu) for p, l, ex, d, tu in all_hits if not ex]

    print(f"\n{sep}")
    print(C.bold("ADVANCED XSS SCAN REPORT"))
    print(sep)
    print(f"  Canary : {C.magenta(canary)}")
    print()
    if not all_hits:
        print(C.green("  No XSS reflections detected."))
    else:
        if exploitable:
            print(C.red(C.bold(f"  {len(exploitable)} EXPLOITABLE reflection(s) found!")))
            for prm, label, desc, test_url in exploitable:
                print(f"    {C.red('VULNERABLE')} param={C.yellow(prm)} [{label}]")
                print(f"      Context  : {desc}")
                print(f"      Test URL : {C.magenta(test_url)}")
        else:
            print(C.green("  No exploitable XSS found."))
        if filtered:
            print(C.yellow(f"\n  {len(filtered)} filtered/encoded reflection(s) – output is escaped:"))
            for prm, label, desc, _ in filtered:
                print(f"    param={prm} [{label}] – {desc}")
    print()
    print(C.bold("=" * 60))


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

    # (base_url, param, label, desc, exploitable, test_url)
    reflected_hits: list[tuple[str, str, str, str, bool, str]] = []
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

                # Built-in canary payloads – always run ALL payloads so that
                # e.g. <script> execution is verified even if the raw canary
                # already reflected.
                for payload, label in built_in_payloads:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url = parsed._replace(query=urlencode(test_params)).geturl()

                    try:
                        resp = requests.get(test_url, timeout=10, verify=CA_BUNDLE,
                                            headers=HEADERS, allow_redirects=True)
                        contexts = _check_reflection_context(resp.text, canary, payload)

                        if not contexts:
                            print(C.green("  [safe]") + f" param={param} [{label}]")
                        else:
                            for desc, exploitable in contexts:
                                icon = C.red("[VULNERABLE]") if exploitable else C.yellow("[FILTERED]")
                                print(f"  {icon} param={C.yellow(param)} [{label}]")
                                print(f"    Context  : {desc}")
                                if exploitable:
                                    print(f"    Test URL : {C.magenta(test_url)}")
                                    reflected_hits.append((base_url, param, label, desc, True, test_url))
                                    param_hit = True
                                else:
                                    reflected_hits.append((base_url, param, label, desc, False, test_url))
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
                            contexts = _check_xss_context(resp.text, payload)
                            for desc, exploitable in contexts:
                                icon = C.red("[VULNERABLE]") if exploitable else C.yellow("[REFLECTED]")
                                print(f"  {icon} param={C.yellow(param)} [wordlist]")
                                print(f"    Payload  : {payload[:80]}")
                                print(f"    Context  : {desc}")
                                if exploitable:
                                    print(f"    Test URL : {C.magenta(test_url)}")
                                    reflected_hits.append((base_url, param, "wordlist", desc, True, test_url))
                                    param_hit = True
                                else:
                                    reflected_hits.append((base_url, param, "wordlist", desc, False, test_url))
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
                    contexts = _check_reflection_context(resp.text, canary, canary)
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
    exploitable = [(u, p, l, d, tu) for u, p, l, d, ex, tu in reflected_hits if ex]
    filtered    = [(u, p, l, d, tu) for u, p, l, d, ex, tu in reflected_hits if not ex]

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
            for url, param, label, desc, test_url in exploitable:
                if url not in shown:
                    print(f"    {C.cyan(url)}")
                    shown.add(url)
                print(f"      " + C.red("VULNERABLE") + f" param={C.yellow(param)} [{label}]")
                print(f"      Context  : {desc}")
                print(f"      Test URL : {C.magenta(test_url)}")
            print()
        if filtered:
            print(C.yellow(f"  {len(filtered)} filtered/encoded reflection(s) – output is escaped:"))
            for url, param, label, desc, test_url in filtered:
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

    # ── Consolidated vulnerability summary ───────────────────────────────────
    total_vulns = len(exploitable) + len(stored_hits)
    print()
    print(C.bold("=" * 60))
    if total_vulns == 0:
        print(C.green(C.bold("  SUMMARY: No exploitable XSS vulnerabilities found.")))
    else:
        print(C.red(C.bold(f"  SUMMARY: {total_vulns} EXPLOITABLE VULNERABILITY/IES FOUND")))
        print()
        idx = 1
        if exploitable:
            print(C.bold("  Reflected XSS:"))
            for url, param, label, desc, test_url in exploitable:
                print(f"    {idx}. {C.red('REFLECTED')}  param={C.yellow(param)}  [{label}]")
                print(f"       Context  : {desc}")
                print(f"       Test URL : {C.magenta(test_url)}")
                idx += 1
        if stored_hits:
            print(C.bold("  Stored XSS:"))
            for page_url in stored_hits:
                print(f"    {idx}. {C.red('STORED')}  {C.cyan(page_url)}")
                idx += 1
    print(C.bold("=" * 60))

    # Generate HTML XSS report
    domain_name = urlparse(start_url).netloc.replace(":", "_") or "output"
    html_path = os.path.join(_RESULTS_DIR, f"{domain_name}_xss_report.html")
    generate_xss_report_html(start_url, canary, reflected_hits, stored_hits, html_path)


# ---------------------------------------------------------------------------
# Helper: recrawl (reset DB for domain, then crawl)
# ---------------------------------------------------------------------------

def recrawl(start_url: str, stay_on_domain: bool = True, workers: int = 1):
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
    crawl(start_url, stay_on_domain=stay_on_domain, workers=workers)


# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

def show_help():
    prog = os.path.basename(sys.argv[0])
    print(f"""
{C.bold('Usage:')}
  python {prog} {C.cyan('<start_url>')} [options]

{C.bold('Options:')}
  {C.cyan('(none)')}              Crawl start_url, stay on same domain
  {C.cyan('--all-domains')}       Follow links to other domains too
  {C.cyan('--workers N')}         Fetch N pages in parallel (default: 1)
  {C.cyan('--ignore PATTERN')}    Skip URLs matching PATTERN (substring or glob, repeatable)
  {C.cyan('--recrawl')}           Reset DB for start_url's domain and re-crawl
  {C.cyan('--xss')}               Run reflected/stored XSS tests on stored URLs
  {C.cyan('--advancedscan URL')}  Run ALL xss.txt payloads on URL (+ optional param name)
  {C.cyan('--help')}              Show this help

{C.bold('--ignore examples:')}
  --ignore /logout              skip any URL containing /logout
  --ignore "*/admin/*"          skip URLs matching glob pattern
  --ignore param:action         skip any URL with a query param named "action"
  --ignore param:id             skip any URL with a query param named "id"
  --ignore /print --ignore /rss multiple patterns supported

{C.bold('Examples:')}
  python {prog} https://example.com
  python {prog} https://example.com --workers 5
  python {prog} https://example.com --ignore /logout --ignore /print
  python {prog} https://example.com --recrawl --workers 8
  python {prog} https://example.com --xss
  python {prog} https://example.com --all-domains
  python {prog} --advancedscan "http://localhost/xss.php?test=foo"
  python {prog} --advancedscan "http://localhost/xss.php?test=foo" test
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
    log_path = os.path.join(_RESULTS_DIR, f"{domain_name}.txt")
    tee = _Tee(log_path)
    sys.stdout = tee
    print(f"[LOG] Output mirrored to {log_path}")

    stay = "--all-domains" not in args

    # Parse --ignore PATTERN (repeatable)
    ignore_patterns: list[str] = []
    for i, a in enumerate(args):
        if a == "--ignore" and i + 1 < len(args):
            ignore_patterns.append(args[i + 1])
    if ignore_patterns:
        os.environ["CRAWLER_IGNORE"] = ",".join(ignore_patterns)
        print(C.yellow(f"[IGNORE]") + f" Active patterns: {ignore_patterns}")

    # Parse --workers N (default 1)
    workers = 1
    if "--workers" in args:
        idx = args.index("--workers")
        try:
            workers = max(1, int(args[idx + 1]))
        except (IndexError, ValueError):
            print(C.red("[ERROR]") + " --workers requires an integer argument")
            sys.exit(1)

    try:
        if "--recrawl" in args:
            recrawl(start, stay_on_domain=stay, workers=workers)
        elif "--xss" in args:
            run_xss_scan(start)
        elif "--advancedscan" in args:
            adv_idx = args.index("--advancedscan")
            # URL: next arg after --advancedscan if it looks like a URL, else use start
            _next = args[adv_idx + 1] if adv_idx + 1 < len(args) else ""
            if _next.startswith("http"):
                adv_url = _next
                # Optional param name immediately after the URL
                _after = args[adv_idx + 2] if adv_idx + 2 < len(args) else ""
                adv_param: str | None = _after if _after and not _after.startswith("--") else None
            else:
                # URL given as the positional start arg; treat _next as param name
                adv_url = start
                adv_param = _next if _next and not _next.startswith("--") else None
            run_advanced_scan(adv_url, adv_param)
        else:
            crawl(start, stay_on_domain=stay, workers=workers)
    finally:
        sys.stdout = sys.__stdout__
        tee.close()