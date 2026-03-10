# PyCrawler

A web crawler and XSS scanner written in Python. Crawls a target domain, discovers GET parameters, and can test them for reflected and stored XSS vulnerabilities.

---

## Features

- Crawls an entire domain, staying on the same host by default
- Discovers and records GET parameters from links
- Deduplicates URLs by **parameter names** (not values) — `?name=A&age=B` and `?name=X&age=Y` count as the same URL, but `?name=A` and `?name=A&age=B` are different
- Persists state in a local SQLite database (`crawler.db`) — interrupted crawls can be resumed
- **Referer tracking** — every discovered URL stores the page it was first found on (`referer` column)
- **Link topology** — all directed page→page link relationships are stored in a `links` table
- **Parallel crawling** via `--workers N` for faster coverage
- XSS scanner with canary-based detection, HTML context analysis, and stored XSS detection
- Colour-coded terminal output
- All output is simultaneously saved to `results/<domain>.txt` (ANSI codes stripped)
- Skips non-HTML content (videos, PDFs, etc.) automatically
- **HTML Crawl Report** generated automatically after every crawl (`results/<domain>_crawl_report.html`)
  - Includes an interactive **Site Topology graph** (force-directed canvas visualization)
- **HTML XSS Report** generated automatically after every XSS scan (`results/<domain>_xss_report.html`)
- Reports feature collapsible sections per finding category, dark-themed UI

---

## Requirements

```
Python 3.10+
requests
beautifulsoup4
```

Install dependencies:

```bash
pip install -r requirements.txt
```

### SSL / Custom CA

If the target site uses a certificate from an institutional CA not in Python's default bundle (e.g. HARICA used by German universities), create a custom CA bundle:

```bash
# Find the AIA URL from the server cert, e.g.:
curl -s http://crt.harica.gr/HARICA-GEANT-TLS-E1.cer -o /tmp/int.cer
openssl x509 -inform DER -in /tmp/int.cer -out /tmp/int.pem
cat /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /tmp/int.pem > ca-bundle-custom.pem
```

Place `ca-bundle-custom.pem` in the same directory as `main.py` — it will be picked up automatically.

---

## Usage

```
python main.py <start_url> [options]
```

| Option | Description |
|---|---|
| *(none)* | Crawl `start_url`, stay on same domain |
| `--all-domains` | Follow links to other domains too |
| `--workers N` | Fetch N pages in parallel (default: 1) |
| `--ignore PATTERN` | Skip URLs matching a substring, glob, or `param:NAME` (repeatable) |
| `--recrawl` | Reset DB entries for the domain and re-crawl from scratch |
| `--xss` | Run XSS scan against previously crawled parameterised URLs |
| `--advancedscan URL [param]` | Run the full `xss.txt` wordlist + built-in payloads against a single URL; no crawl required |
| `--help` | Show usage |

### `--ignore` patterns

`--ignore` can be specified multiple times. Each pattern is matched against the full URL:

| Pattern | Behaviour |
|---|---|
| `/logout` | Skips any URL whose string contains `/logout` |
| `*/admin/*` | Skips URLs matching the glob pattern |
| `param:NAME` | Skips any URL that has a query parameter named `NAME` (regardless of value) |

```bash
# Skip /logout and /print pages
python main.py https://example.com --ignore /logout --ignore /print

# Skip any URL with a "session" or "token" query parameter
python main.py https://example.com --ignore param:session --ignore param:token

# Combine URL and parameter patterns
python main.py https://example.com --ignore /admin --ignore param:debug
```

### Examples

```bash
# Basic crawl
python main.py https://example.com

# Crawl with 5 parallel workers
python main.py https://example.com --workers 5

# Crawl and follow all external links
python main.py https://example.com --all-domains

# Wipe previous data and re-crawl (with 8 workers)
python main.py https://example.com --recrawl --workers 8

# Run XSS scan after crawling
python main.py https://example.com --xss

# Targeted advanced scan on a single URL (all parameters)
python main.py --advancedscan "http://example.com/search.php?q=test"

# Same, but only test the "q" parameter
python main.py --advancedscan "http://example.com/search.php?q=test" q
```

---

## How It Works

### Crawling

1. The start URL is added to the SQLite database
2. The main loop claims unvisited URLs from the DB and dispatches them to a pool of worker threads
3. Each worker spawns a subprocess that fetches the page, extracts all `<a href>` links, saves new URLs to the DB, and records any GET parameters found
4. The loop ends when no unvisited URLs remain and all workers are idle
5. A final report is printed (and written to file)

State is stored in `crawler.db`. If you press **Ctrl+C**, the crawl stops cleanly and prints a report of everything collected so far. The next run will resume from where it left off. Use `--recrawl` to start fresh.

### Parallel Workers

`--workers N` runs N subprocesses concurrently. The main thread is the sole DB reader/claimer — it atomically pre-marks each URL as visited before dispatching it, so no two workers ever fetch the same page. SQLite WAL mode allows all subprocesses to write new URLs to the DB simultaneously without blocking each other.

Recommended values: `--workers 4` to `--workers 10`. Higher values may trigger rate-limiting on the target server.

### URL Deduplication

URLs are normalized to a *canonical* form for deduplication:

```
https://example.com/page.php?name=SONST&age=20
→ canonical: https://example.com/page.php?name&age
```

This means:
- `?name=SONST&age=20` and `?name=BLA&age=23` → **same URL** (skipped)
- `?name=SONST` and `?name=SONST&age=20` → **different URLs** (both crawled)

### Referer Tracking & Link Topology

Every time a new URL is discovered on a page, the **source page URL is stored as the referer** in the `pages` table.  
Additionally, *every* directed link relationship (`source → target`) is recorded in the `links` table — even if the target page was already known, so the complete link graph is captured.

The SQLite schema for topology data:

```sql
-- pages.referer: the first page this URL was seen on
ALTER TABLE pages ADD COLUMN referer TEXT NOT NULL DEFAULT '';

-- links: full directed edge list for topology
CREATE TABLE links (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    source  TEXT NOT NULL,   -- canonical source URL
    target  TEXT NOT NULL,   -- canonical target URL
    UNIQUE(source, target)
);
```

### Site Topology Graph

The HTML Crawl Report (`results/<domain>_crawl_report.html`) includes an interactive **Site Topology** section rendered directly in the browser — no external libraries required.

The graph uses a **force-directed layout** implemented in vanilla JavaScript on an HTML5 Canvas:

- **Nodes** represent crawled pages, coloured by HTTP status:
  - 🟢 Green — 200 OK
  - 🔴 Red — 4xx error or fetch failure
  - 🟡 Yellow — 3xx redirect
  - ⚫ Gray — skipped (media, non-HTML)
- **Edges** are the discovered links between pages (directed, source → target)
- **Hover** a node to see its full URL in a tooltip
- **Click** a node to open the page in a new tab
- Edges connected to the hovered node are highlighted in blue
- The simulation runs for ~12 seconds to reach a stable layout, then freezes (interaction remains active)
- Up to 600 internal nodes are shown (visited pages have priority if the site is larger)

### XSS Scanning (`--xss`)

Run after a crawl. Operates in two phases:

#### Phase 1 — Reflected XSS

For each parameterised URL found during crawling, injects payloads into each GET parameter and checks if they appear in the response.

**5 built-in payloads** (escalating difficulty), each containing a unique random canary token:

| # | Type |
|---|---|
| 1 | Raw canary — detects any plain reflection |
| 2 | `<canary>` — HTML tag injection |
| 3 | `<script>alert('canary')</script>` — script tag |
| 4 | `"><img src=x onerror=alert('canary')>` — attribute breakout |
| 5 | `';alert('canary');//` — JavaScript string breakout |

Plus **2 evenly-sampled payloads** from `/usr/share/wordlists/xss.txt` (verbatim, subjected to context analysis — see below).

**Context analysis** — when a reflection is found, the response is parsed to determine *where* the canary (or verbatim payload) landed and whether it could realistically execute:

| Context | Assessment |
|---|---|
| Inside `<script>` block | Exploitable — JS execution likely |
| In event attribute (`onclick`, `onerror`, …) | Exploitable — JS execution likely |
| In navigation attribute (`href`, `src`, …) | Potentially exploitable |
| HTML-entity encoded (`&lt;`, `&gt;`) | Filtered — server escapes output |
| URL-encoded (`%3C`, `%3E`) | Filtered |
| Raw in body (no special context) | Exploitable |

All 5 built-in payloads are **always tested**, even after an earlier payload already reflected. This ensures that e.g. the `<script>` payload is explicitly verified and not silently skipped because the raw canary reflected first.

#### Phase 2 — Stored XSS

After all injections, every previously visited page is re-fetched. If the canary appears on a page that was not the injection target, it indicates stored XSS (the payload was saved server-side and rendered elsewhere).

---

### Advanced Scan (`--advancedscan`)

Runs **every** payload from `/usr/share/wordlists/xss.txt` plus the 5 built-in canary payloads against a single URL and, optionally, a single named parameter. No prior crawl or database entry is required.

```bash
# Test all parameters in the URL
python main.py --advancedscan "http://example.com/vuln.php?name=foo&age=1"

# Test only the "name" parameter
python main.py --advancedscan "http://example.com/vuln.php?name=foo&age=1" name
```

Useful when you already know which page and parameter you want to probe (e.g. from manual reconnaissance) and do not want to crawl an entire site.

- Wordlist payloads are analysed with the same context engine as the built-in payloads — `<script>` tags, event handlers (`onerror=`, `onload=`, …), and `javascript:` URIs are flagged as exploitable; entity-encoded reflections are flagged as filtered.
- A progress summary `(N reflected, M safe)` is printed after the wordlist phase.
- The final report lists all exploitable hits with their injection context and a ready-to-use test URL.

---

#### Vulnerability Summary

At the end of every XSS scan a consolidated **SUMMARY** block is printed. Each exploitable finding — reflected or stored — gets a numbered entry with its type, affected parameter, injection context, and a ready-to-use test URL. If nothing exploitable was found, a single green confirmation line is shown instead.

---

## Output

All output is written to the terminal in colour and simultaneously appended to `results/<domain>.txt` (colour codes stripped). The `results/` directory is created automatically next to `main.py`.

### Files produced

| File | When created | Description |
|---|---|---|
| `results/<domain>.txt` | Every run | Full terminal log (ANSI codes stripped) |
| `results/<domain>_crawl_report.html` | After every crawl | Interactive HTML crawl report |
| `results/<domain>_xss_report.html` | After every `--xss` scan | Interactive HTML XSS report |

Pressing **Ctrl+C** during either phase still produces a partial report in all three files.

### HTML Crawl Report

A self-contained dark-themed HTML file with **collapsible sections** per finding category:

| Section | Contents |
|---|---|
| 🔴 404 Not Found | URLs that returned HTTP 404 |
| 🟡 403 Forbidden | URLs that returned HTTP 403 |
| ⚠️ Other HTTP Errors | Any other 4xx/5xx responses |
| 🎞️ Media / Non-HTML (skipped) | URLs skipped due to non-HTML content type |
| ❌ Fetch Errors | URLs that could not be reached |
| 🔗 External Links | Links pointing outside the crawled domain |
| 🔍 URLs with GET Parameters | Parameterised URLs with their parameter names/values |
| ✅ Successfully Crawled Pages | All pages that returned HTTP 200 HTML |

### HTML XSS Report

A self-contained dark-themed HTML file with **collapsible sections**:

| Section | Contents |
|---|---|
| 🔴 Exploitable Reflected XSS | Vulnerabilities grouped by URL, with injection context and test URL |
| 💾 Stored XSS | Pages where the canary was found after injection |
| 🟡 Filtered / Encoded Reflections | Reflections that are HTML/URL-encoded by the server |

---

## Database

SQLite file `crawler.db` in the working directory. Two tables:

- **pages** — all discovered URLs with visited status and canonical form
- **findings** — all GET parameters discovered, with URL and value

The DB persists between runs. Use `--recrawl` to reset a specific domain's data.

---

## Limitations

- XSS detection is heuristic — false negatives are possible (e.g. payloads reflected inside JS strings with different quoting, or server-side filtering that isn't exact HTML escaping)
- Does not handle JavaScript-rendered content (no headless browser)
- POST forms are not tested
- Only `<a href>` links are followed; JS navigation, redirects via meta tags, etc. are not discovered
