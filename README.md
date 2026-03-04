# PyCrawler

A web crawler and XSS scanner written in Python. Crawls a target domain, discovers GET parameters, and can test them for reflected and stored XSS vulnerabilities.

---

## Features

- Crawls an entire domain, staying on the same host by default
- Discovers and records GET parameters from links
- Deduplicates URLs by **parameter names** (not values) — `?name=A&age=B` and `?name=X&age=Y` count as the same URL, but `?name=A` and `?name=A&age=B` are different
- Persists state in a local SQLite database (`crawler.db`) — interrupted crawls can be resumed
- **Parallel crawling** via `--workers N` for faster coverage
- XSS scanner with canary-based detection, HTML context analysis, and stored XSS detection
- Colour-coded terminal output
- All output is simultaneously saved to `results/<domain>.txt` (ANSI codes stripped)
- Skips non-HTML content (videos, PDFs, etc.) automatically

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

Plus **2 raw payloads** from `/usr/share/wordlists/xss.txt` (verbatim exact-match check).

**Context analysis** — when a reflection is found, the response is parsed to determine *where* the canary landed:

| Context | Assessment |
|---|---|
| Inside `<script>` block | Exploitable — JS execution likely |
| In event attribute (`onclick`, `onerror`, …) | Exploitable — JS execution likely |
| In navigation attribute (`href`, `src`, …) | Potentially exploitable |
| HTML-entity encoded (`&lt;`, `&gt;`) | Filtered — server escapes output |
| URL-encoded (`%3C`, `%3E`) | Filtered |
| Raw in body (no special context) | Exploitable |

#### Phase 2 — Stored XSS

After all injections, every previously visited page is re-fetched. If the canary appears on a page that was not the injection target, it indicates stored XSS (the payload was saved server-side and rendered elsewhere).

#### Vulnerability Summary

At the end of every XSS scan a consolidated **SUMMARY** block is printed. Each exploitable finding — reflected or stored — gets a numbered entry with its type, affected parameter, injection context, and a ready-to-use test URL. If nothing exploitable was found, a single green confirmation line is shown instead.

---

## Output

All output is written to the terminal in colour and simultaneously appended to `results/<domain>.txt` (colour codes stripped). The `results/` directory is created automatically next to `main.py`.

Example log file: `results/www.example.com.txt`

Both the crawl report and XSS scan report are included in the same file. Pressing **Ctrl+C** during either phase still produces a partial report.

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
