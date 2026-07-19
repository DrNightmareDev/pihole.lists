# Combined Pi-hole Blocklist Action — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a GitHub Action that merges many Pi-hole blocklists into one deduplicated plain-domain list (split by size), subtracts whitelisted domains, refreshes weekly, and reads its sources from a tracked config file.

**Architecture:** A pure-logic Python module (`scripts/blocklist.py`, no network) holds parsing/selection/packing/README functions and is fully unit-tested. A thin IO orchestrator (`scripts/build.py`) does HTTP + GitHub API calls and wires the pure functions together. A workflow (`.github/workflows/update-lists.yml`) runs `build.py` weekly and commits changed outputs.

**Tech Stack:** Python 3 standard library only (no pip deps for the tool). pytest for tests. GitHub Actions with `actions/setup-python`.

## Global Constraints

- Python 3 **standard library only** for `blocklist.py` and `build.py` — no third-party imports (pytest is a dev/test dependency only).
- Output format: **plain domains**, one per line, lowercased, sorted ascending, trailing newline.
- Split threshold: **`MAX_BYTES = 45 * 1024 * 1024`** (45 MB). As few files as possible.
- Output naming: single file → `blocklist.txt`; split → `blocklist-01.txt`, `blocklist-02.txt`, … (no bare `blocklist.txt` when split). Delete stale `blocklist*.txt` not produced this run.
- Target repo raw base URL: `https://raw.githubusercontent.com/DrNightmareDev/pihole.lists/main`.
- Default branch: `main`.
- Build **fails (exit 1)** if zero domains are collected.
- A single source/repo that fails to fetch → warn to stderr and skip; never abort the whole build for one bad source.
- Local test runner is the **`py`** launcher: `py -m pytest`. CI uses `python` (via setup-python).
- README managed section is delimited by `<!-- BLOCKLIST:START -->` / `<!-- BLOCKLIST:END -->`.

---

## File Structure

- Create: `scripts/blocklist.py` — pure logic (parse_domain, parse_sources, select_repo_files, pack_domains, output_filenames, render_section, update_readme).
- Create: `scripts/build.py` — IO orchestration + `main(root, token)`.
- Create: `tests/test_parse.py`, `tests/test_sources.py`, `tests/test_repo_select.py`, `tests/test_pack.py`, `tests/test_readme.py`, `tests/test_build.py`.
- Create: `pytest.ini` — `pythonpath = scripts`.
- Create: `sources.txt` — source config.
- Create: `.github/workflows/update-lists.yml` — the scheduled workflow.
- Modify: `README.md` — add managed-section markers + usage.

---

### Task 1: Scaffolding + `parse_domain`

**Files:**
- Create: `pytest.ini`
- Create: `scripts/blocklist.py`
- Test: `tests/test_parse.py`

**Interfaces:**
- Produces: `parse_domain(line: str) -> str | None` — normalized domain, or `None` if the line is not a valid domain.

- [ ] **Step 1: Create `pytest.ini`**

```ini
[pytest]
pythonpath = scripts
testpaths = tests
```

- [ ] **Step 2: Write the failing test** — `tests/test_parse.py`

```python
import blocklist as bl


def test_plain_domain():
    assert bl.parse_domain("Example.COM") == "example.com"


def test_hosts_format():
    assert bl.parse_domain("0.0.0.0 ads.example.com") == "ads.example.com"
    assert bl.parse_domain("127.0.0.1 tracker.net") == "tracker.net"


def test_adblock_syntax():
    assert bl.parse_domain("||ad.example.org^") == "ad.example.org"


def test_leading_wildcard_and_dot():
    assert bl.parse_domain("*.ads.example.com") == "ads.example.com"
    assert bl.parse_domain(".example.com") == "example.com"


def test_inline_and_full_comments():
    assert bl.parse_domain("# a comment") is None
    assert bl.parse_domain("! adblock comment") is None
    assert bl.parse_domain("example.com # trailing note") == "example.com"


def test_blank_and_junk():
    assert bl.parse_domain("") is None
    assert bl.parse_domain("   ") is None
    assert bl.parse_domain("requests==2.31.0") is None
    assert bl.parse_domain("some random log line here") is None
    assert bl.parse_domain("1.2.3.4") is None  # bare IP, not a domain


def test_underscore_domain_allowed():
    assert bl.parse_domain("_dmarc.example.com") == "_dmarc.example.com"
```

- [ ] **Step 3: Run test to verify it fails**

Run: `py -m pytest tests/test_parse.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'blocklist'` (or `AttributeError: parse_domain`).

- [ ] **Step 4: Write minimal implementation** — create `scripts/blocklist.py`

```python
"""Pure logic for building a combined Pi-hole blocklist. Standard library only."""
import re
from collections import namedtuple

_DOMAIN_RE = re.compile(
    r"^(?!-)[a-z0-9_-]{1,63}(?<!-)(\.(?!-)[a-z0-9_-]{1,63}(?<!-))+$"
)
_HOSTS_PREFIXES = {"0.0.0.0", "127.0.0.1", "::", "::1", "255.255.255.255"}


def parse_domain(line):
    """Return a normalized domain from one source line, or None if not a domain."""
    s = line.strip()
    if not s or s[0] in "#!":
        return None
    hash_idx = s.find("#")
    if hash_idx != -1:
        s = s[:hash_idx].strip()
    if not s:
        return None

    parts = s.split()
    if len(parts) == 1:
        s = parts[0]
    elif parts[0] in _HOSTS_PREFIXES:
        s = parts[-1]
    else:
        return None  # unknown multi-token line

    if s.startswith("||"):
        s = s[2:]
    s = s.rstrip("^")
    if s.startswith("*."):
        s = s[2:]
    s = s.strip(".").lower()

    if len(s) > 253 or not _DOMAIN_RE.match(s):
        return None
    tld = s.rsplit(".", 1)[-1]
    if not any(c.isalpha() for c in tld):  # reject IP-like / numeric TLDs
        return None
    return s
```

- [ ] **Step 5: Run test to verify it passes**

Run: `py -m pytest tests/test_parse.py -v`
Expected: PASS (7 passed).

- [ ] **Step 6: Commit**

```bash
git add pytest.ini scripts/blocklist.py tests/test_parse.py
git commit -m "feat: add tolerant domain parser + test scaffolding"
```

---

### Task 2: `parse_sources`

**Files:**
- Modify: `scripts/blocklist.py`
- Test: `tests/test_sources.py`

**Interfaces:**
- Produces:
  - `Source = namedtuple("Source", ["kind", "target", "subpath", "is_whitelist"])` where `kind` is `"url"` or `"repo"`, `target` is a URL or `"owner/name"`, `subpath` is `None` or a `"path/"` prefix, `is_whitelist` is `bool`.
  - `parse_sources(text: str) -> list[Source]`.

- [ ] **Step 1: Write the failing test** — `tests/test_sources.py`

```python
import blocklist as bl


def test_parses_all_directive_types():
    text = """
    # a comment
    https://example.com/list.txt
    repo blocklistproject/Lists
    repo owner/name lists/
    whitelist https://example.com/allow.txt
    whitelist-repo owner/name sub/
    """
    got = bl.parse_sources(text)
    assert got == [
        bl.Source("url", "https://example.com/list.txt", None, False),
        bl.Source("repo", "blocklistproject/Lists", None, False),
        bl.Source("repo", "owner/name", "lists/", False),
        bl.Source("url", "https://example.com/allow.txt", None, True),
        bl.Source("repo", "owner/name", "sub/", True),
    ]


def test_subpath_gets_trailing_slash():
    got = bl.parse_sources("repo owner/name lists")
    assert got[0].subpath == "lists/"


def test_blank_and_comment_lines_ignored():
    assert bl.parse_sources("\n\n#only comments\n   \n") == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `py -m pytest tests/test_sources.py -v`
Expected: FAIL — `AttributeError: module 'blocklist' has no attribute 'Source'`.

- [ ] **Step 3: Write minimal implementation** — append to `scripts/blocklist.py`

```python
Source = namedtuple("Source", ["kind", "target", "subpath", "is_whitelist"])


def _repo_source(args, is_whitelist):
    target = args[0]
    subpath = args[1] if len(args) > 1 else None
    if subpath and not subpath.endswith("/"):
        subpath += "/"
    return Source("repo", target, subpath, is_whitelist)


def parse_sources(text):
    """Parse sources.txt content into a list of Source directives."""
    sources = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split()
        keyword = tokens[0].lower()
        if keyword == "repo":
            sources.append(_repo_source(tokens[1:], is_whitelist=False))
        elif keyword == "whitelist-repo":
            sources.append(_repo_source(tokens[1:], is_whitelist=True))
        elif keyword == "whitelist":
            sources.append(Source("url", tokens[1], None, True))
        else:
            sources.append(Source("url", tokens[0], None, False))
    return sources
```

- [ ] **Step 4: Run test to verify it passes**

Run: `py -m pytest tests/test_sources.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add scripts/blocklist.py tests/test_sources.py
git commit -m "feat: parse sources.txt directives"
```

---

### Task 3: `select_repo_files`

**Files:**
- Modify: `scripts/blocklist.py`
- Test: `tests/test_repo_select.py`

**Interfaces:**
- Produces: `select_repo_files(paths: list[str], subpath: str | None = None) -> list[str]` — filters a repo's blob paths to the `.txt` list files to include (root-only by default, or under `subpath`), excluding known non-lists.

- [ ] **Step 1: Write the failing test** — `tests/test_repo_select.py`

```python
import blocklist as bl

# Mirrors blocklistproject/Lists reality.
PATHS = [
    "ads.txt",
    "malware.txt",
    "requirements.txt",       # excluded: non-list prefix
    "cron_output.txt",        # excluded: non-list prefix
    "README.md",              # excluded: not .txt
    "whitelist.txt",          # excluded: contains 'whitelist'
    "dnsmasq-version/ads-dnsmasq.txt",  # excluded: subfolder
    "adguard/ads-ags.txt",    # excluded: subfolder
    "ads.txt.bak",            # excluded: not .txt
]


def test_root_only_selection():
    assert bl.select_repo_files(PATHS) == ["ads.txt", "malware.txt"]


def test_subpath_selection():
    paths = ["lists/a.txt", "lists/b.txt", "lists/sub/c.txt", "other/d.txt", "top.txt"]
    assert bl.select_repo_files(paths, "lists/") == ["lists/a.txt", "lists/b.txt"]


def test_excludes_readme_changelog_and_bak():
    paths = ["good.txt", "changelog.txt", "readme.txt", "notes.bak"]
    assert bl.select_repo_files(paths) == ["good.txt"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `py -m pytest tests/test_repo_select.py -v`
Expected: FAIL — `AttributeError: ... 'select_repo_files'`.

- [ ] **Step 3: Write minimal implementation** — append to `scripts/blocklist.py`

```python
_EXCLUDE_SUBSTRINGS = ("whitelist", "allow")
_EXCLUDE_PREFIXES = ("readme", "changelog", "requirements", "cron_output")


def select_repo_files(paths, subpath=None):
    """Filter repo blob paths to includable .txt list files."""
    selected = []
    for path in paths:
        if not path.endswith(".txt"):
            continue
        if subpath:
            if not path.startswith(subpath):
                continue
            rel = path[len(subpath):]
        else:
            rel = path
        if "/" in rel:
            continue
        name = rel.lower()
        if any(sub in name for sub in _EXCLUDE_SUBSTRINGS):
            continue
        if any(name.startswith(p) for p in _EXCLUDE_PREFIXES):
            continue
        selected.append(path)
    return selected
```

- [ ] **Step 4: Run test to verify it passes**

Run: `py -m pytest tests/test_repo_select.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add scripts/blocklist.py tests/test_repo_select.py
git commit -m "feat: select includable repo list files (root-only + denylist)"
```

---

### Task 4: `pack_domains` + `output_filenames`

**Files:**
- Modify: `scripts/blocklist.py`
- Test: `tests/test_pack.py`

**Interfaces:**
- Produces:
  - `pack_domains(domains: list[str], max_bytes: int) -> list[list[str]]` — greedily packs domains into chunks, each chunk's serialized size (`len(domain)+1` per line) staying ≤ `max_bytes` where possible.
  - `output_filenames(count: int) -> list[str]` — `["blocklist.txt"]` for 1; `["blocklist-01.txt", ...]` for many.

- [ ] **Step 1: Write the failing test** — `tests/test_pack.py`

```python
import blocklist as bl


def test_single_chunk_when_under_threshold():
    domains = ["a.com", "b.com", "c.com"]
    chunks = bl.pack_domains(domains, max_bytes=1000)
    assert chunks == [["a.com", "b.com", "c.com"]]


def test_splits_into_multiple_chunks():
    # each "aa.com\n" is 7 bytes; max_bytes=15 fits 2 per chunk
    domains = ["aa.com", "bb.com", "cc.com", "dd.com", "ee.com"]
    chunks = bl.pack_domains(domains, max_bytes=15)
    assert chunks == [["aa.com", "bb.com"], ["cc.com", "dd.com"], ["ee.com"]]


def test_empty_input():
    assert bl.pack_domains([], max_bytes=100) == []


def test_output_filenames():
    assert bl.output_filenames(1) == ["blocklist.txt"]
    assert bl.output_filenames(3) == [
        "blocklist-01.txt", "blocklist-02.txt", "blocklist-03.txt",
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `py -m pytest tests/test_pack.py -v`
Expected: FAIL — `AttributeError: ... 'pack_domains'`.

- [ ] **Step 3: Write minimal implementation** — append to `scripts/blocklist.py`

```python
def pack_domains(domains, max_bytes):
    """Greedily pack domains into chunks that serialize to <= max_bytes."""
    chunks = []
    current = []
    size = 0
    for domain in domains:
        line_size = len(domain.encode("utf-8")) + 1  # + newline
        if current and size + line_size > max_bytes:
            chunks.append(current)
            current = []
            size = 0
        current.append(domain)
        size += line_size
    if current:
        chunks.append(current)
    return chunks


def output_filenames(count):
    """Output file names: one bare file, or zero-padded numbered files."""
    if count <= 1:
        return ["blocklist.txt"]
    return [f"blocklist-{i:02d}.txt" for i in range(1, count + 1)]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `py -m pytest tests/test_pack.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add scripts/blocklist.py tests/test_pack.py
git commit -m "feat: pack domains into size-bounded output files"
```

---

### Task 5: `render_section` + `update_readme`

**Files:**
- Modify: `scripts/blocklist.py`
- Test: `tests/test_readme.py`

**Interfaces:**
- Produces:
  - `render_section(domain_count: int, filenames: list[str], sources_text: str, raw_base_url: str, timestamp: str) -> str` — the managed README block, delimited by the START/END markers.
  - `update_readme(existing: str, section: str) -> str` — replace the block between markers, or append it if absent.
  - Module constants `SECTION_START`, `SECTION_END`.

- [ ] **Step 1: Write the failing test** — `tests/test_readme.py`

```python
import blocklist as bl


def test_render_section_contains_key_facts():
    section = bl.render_section(
        domain_count=1234567,
        filenames=["blocklist-01.txt", "blocklist-02.txt"],
        sources_text="repo blocklistproject/Lists\n",
        raw_base_url="https://raw.example/main",
        timestamp="2026-07-19 06:00:00 UTC",
    )
    assert section.startswith(bl.SECTION_START)
    assert section.rstrip().endswith(bl.SECTION_END)
    assert "1,234,567" in section
    assert "2026-07-19 06:00:00 UTC" in section
    assert "https://raw.example/main/blocklist-01.txt" in section
    assert "https://raw.example/main/blocklist-02.txt" in section
    assert "repo blocklistproject/Lists" in section


def test_update_readme_replaces_between_markers():
    section = bl.render_section(1, ["blocklist.txt"], "x", "https://r/main", "T")
    existing = f"# Title\n\nintro\n\n{bl.SECTION_START}\nOLD\n{bl.SECTION_END}\n\ntail\n"
    updated = bl.update_readme(existing, section)
    assert "OLD" not in updated
    assert "# Title" in updated
    assert "tail" in updated
    assert updated.count(bl.SECTION_START) == 1


def test_update_readme_appends_when_no_markers():
    section = bl.render_section(1, ["blocklist.txt"], "x", "https://r/main", "T")
    updated = bl.update_readme("# Title\n", section)
    assert bl.SECTION_START in updated
    assert updated.startswith("# Title")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `py -m pytest tests/test_readme.py -v`
Expected: FAIL — `AttributeError: ... 'SECTION_START'`.

- [ ] **Step 3: Write minimal implementation** — append to `scripts/blocklist.py`

```python
SECTION_START = "<!-- BLOCKLIST:START -->"
SECTION_END = "<!-- BLOCKLIST:END -->"


def render_section(domain_count, filenames, sources_text, raw_base_url, timestamp):
    """Render the managed README block."""
    lines = [
        SECTION_START,
        "",
        "## Combined blocklist",
        "",
        f"- **Total domains:** {domain_count:,}",
        f"- **Last updated:** {timestamp}",
        f"- **Output files:** {len(filenames)}",
        "",
        "### Subscribe in Pi-hole",
        "",
        "Add these URLs as adlists (Settings → Lists):",
        "",
    ]
    lines += [f"- `{raw_base_url}/{name}`" for name in filenames]
    lines += ["", "### Sources", "", "```", sources_text.strip(), "```", "", SECTION_END]
    return "\n".join(lines)


def update_readme(existing, section):
    """Replace the managed block between markers, or append it if absent."""
    if SECTION_START in existing and SECTION_END in existing:
        before = existing.split(SECTION_START)[0]
        after = existing.split(SECTION_END, 1)[1]
        return before + section + after
    if existing and not existing.endswith("\n"):
        existing += "\n"
    return existing + "\n" + section + "\n"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `py -m pytest tests/test_readme.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add scripts/blocklist.py tests/test_readme.py
git commit -m "feat: render and splice managed README section"
```

---

### Task 6: `build.py` orchestrator + integration test

**Files:**
- Create: `scripts/build.py`
- Test: `tests/test_build.py`

**Interfaces:**
- Consumes: everything in `blocklist.py` (imported as `import blocklist as bl`).
- Produces:
  - `http_get(url, token=None, accept=None) -> str` (retrying HTTP GET).
  - `repo_default_branch(owner_name, token) -> str`, `repo_tree_paths(owner_name, token) -> list[str]`.
  - `source_urls(src, token) -> list[str]` (expands a `Source` to raw file URLs).
  - `main(root=REPO_ROOT, token=None) -> int` (0 success, 1 on empty output).
  - Module constants `REPO_ROOT`, `MAX_BYTES`, `RAW_BASE`.

- [ ] **Step 1: Write the failing test** — `tests/test_build.py`

```python
from pathlib import Path
import build


def test_main_writes_single_file_and_readme(tmp_path, monkeypatch):
    (tmp_path / "sources.txt").write_text(
        "repo owner/list\nwhitelist https://x/allow.txt\n", encoding="utf-8"
    )
    (tmp_path / "README.md").write_text("# pihole.lists\n", encoding="utf-8")

    def fake_source_urls(src, token):
        if src.kind == "repo":
            return ["https://raw/owner/list/main/ads.txt"]
        return [src.target]

    fetched = {
        "https://raw/owner/list/main/ads.txt": "0.0.0.0 ads.com\n0.0.0.0 keep.com\n# c\n",
        "https://x/allow.txt": "keep.com\n",
    }
    monkeypatch.setattr(build, "source_urls", fake_source_urls)
    monkeypatch.setattr(build, "http_get", lambda url, token=None, accept=None: fetched[url])

    rc = build.main(root=tmp_path, token=None)
    assert rc == 0

    out = (tmp_path / "blocklist.txt").read_text(encoding="utf-8")
    assert out == "ads.com\n"  # keep.com subtracted by whitelist
    readme = (tmp_path / "README.md").read_text(encoding="utf-8")
    assert build.bl.SECTION_START in readme
    assert "blocklist.txt" in readme


def test_main_fails_on_empty(tmp_path, monkeypatch):
    (tmp_path / "sources.txt").write_text("https://x/empty.txt\n", encoding="utf-8")
    monkeypatch.setattr(build, "source_urls", lambda src, token: [src.target])
    monkeypatch.setattr(build, "http_get", lambda url, token=None, accept=None: "# nothing\n")
    assert build.main(root=tmp_path, token=None) == 1


def test_main_skips_failing_source(tmp_path, monkeypatch):
    (tmp_path / "sources.txt").write_text(
        "https://good/list.txt\nhttps://bad/list.txt\n", encoding="utf-8"
    )
    (tmp_path / "README.md").write_text("# t\n", encoding="utf-8")

    def flaky_get(url, token=None, accept=None):
        if "bad" in url:
            raise RuntimeError("boom")
        return "good.com\n"

    monkeypatch.setattr(build, "source_urls", lambda src, token: [src.target])
    monkeypatch.setattr(build, "http_get", flaky_get)
    assert build.main(root=tmp_path, token=None) == 0
    assert (tmp_path / "blocklist.txt").read_text(encoding="utf-8") == "good.com\n"


def test_main_removes_stale_split_files(tmp_path, monkeypatch):
    (tmp_path / "sources.txt").write_text("https://x/list.txt\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# t\n", encoding="utf-8")
    (tmp_path / "blocklist-01.txt").write_text("old\n", encoding="utf-8")
    (tmp_path / "blocklist-02.txt").write_text("old\n", encoding="utf-8")
    monkeypatch.setattr(build, "source_urls", lambda src, token: [src.target])
    monkeypatch.setattr(build, "http_get", lambda url, token=None, accept=None: "a.com\nb.com\n")
    assert build.main(root=tmp_path, token=None) == 0
    assert (tmp_path / "blocklist.txt").exists()
    assert not (tmp_path / "blocklist-01.txt").exists()
    assert not (tmp_path / "blocklist-02.txt").exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `py -m pytest tests/test_build.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'build'`.

- [ ] **Step 3: Write minimal implementation** — create `scripts/build.py`

```python
#!/usr/bin/env python3
"""Fetch, merge, dedupe, and split Pi-hole blocklists. Standard library only."""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import blocklist as bl

REPO_ROOT = Path(__file__).resolve().parent.parent
MAX_BYTES = 45 * 1024 * 1024
RAW_BASE = "https://raw.githubusercontent.com/DrNightmareDev/pihole.lists/main"
_USER_AGENT = "pihole.lists-builder"


def http_get(url, token=None, accept=None):
    """HTTP GET returning decoded text, with a few retries."""
    headers = {"User-Agent": _USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if accept:
        headers["Accept"] = accept
    req = urllib.request.Request(url, headers=headers)
    last_err = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read().decode("utf-8", "replace")
        except (urllib.error.URLError, TimeoutError) as err:
            last_err = err
            time.sleep(2 * (attempt + 1))
    raise last_err


def _gh_api(path, token):
    text = http_get(
        f"https://api.github.com/{path}", token=token,
        accept="application/vnd.github+json",
    )
    return json.loads(text)


def repo_default_branch(owner_name, token):
    return _gh_api(f"repos/{owner_name}", token)["default_branch"]


def repo_tree_paths(owner_name, token):
    data = _gh_api(f"repos/{owner_name}/git/trees/HEAD?recursive=1", token)
    return [b["path"] for b in data.get("tree", []) if b.get("type") == "blob"]


def source_urls(src, token):
    """Expand a Source into a list of raw file URLs."""
    if src.kind == "url":
        return [src.target]
    branch = repo_default_branch(src.target, token)
    paths = repo_tree_paths(src.target, token)
    selected = bl.select_repo_files(paths, src.subpath)
    return [
        f"https://raw.githubusercontent.com/{src.target}/{branch}/"
        + urllib.parse.quote(p)
        for p in selected
    ]


def main(root=REPO_ROOT, token=None):
    root = Path(root)
    if token is None:
        token = os.environ.get("GITHUB_TOKEN")
    sources_file = root / "sources.txt"
    readme_file = root / "README.md"

    sources = bl.parse_sources(sources_file.read_text(encoding="utf-8"))
    block, white = set(), set()
    for src in sources:
        try:
            urls = source_urls(src, token)
        except Exception as err:  # noqa: BLE001 - one bad source must not abort
            print(f"WARN: could not expand {src.target}: {err}", file=sys.stderr)
            continue
        for url in urls:
            try:
                text = http_get(url, token=token)
            except Exception as err:  # noqa: BLE001
                print(f"WARN: failed to fetch {url}: {err}", file=sys.stderr)
                continue
            target = white if src.is_whitelist else block
            count = 0
            for line in text.splitlines():
                domain = bl.parse_domain(line)
                if domain:
                    target.add(domain)
                    count += 1
            print(f"  {url}: {count} domains", file=sys.stderr)

    domains = sorted(block - white)
    if not domains:
        print("ERROR: no domains collected; aborting", file=sys.stderr)
        return 1

    chunks = bl.pack_domains(domains, MAX_BYTES)
    names = bl.output_filenames(len(chunks))

    for stale in root.glob("blocklist*.txt"):
        if stale.name not in names:
            stale.unlink()
    for name, chunk in zip(names, chunks):
        (root / name).write_text("\n".join(chunk) + "\n", encoding="utf-8")

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    section = bl.render_section(
        len(domains), names, sources_file.read_text(encoding="utf-8"),
        RAW_BASE, timestamp,
    )
    existing = readme_file.read_text(encoding="utf-8") if readme_file.exists() else "# pihole.lists\n"
    readme_file.write_text(bl.update_readme(existing, section), encoding="utf-8")

    print(f"Wrote {len(domains):,} domains to {len(names)} file(s).", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `py -m pytest tests/test_build.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Run the full suite**

Run: `py -m pytest -v`
Expected: PASS (all tasks' tests green).

- [ ] **Step 6: Commit**

```bash
git add scripts/build.py tests/test_build.py
git commit -m "feat: build orchestrator (fetch, merge, whitelist, split, readme)"
```

---

### Task 7: `sources.txt`, workflow, README, and live smoke test

**Files:**
- Create: `sources.txt`
- Create: `.github/workflows/update-lists.yml`
- Modify: `README.md`

**Interfaces:**
- Consumes: `scripts/build.py` `main()` via `python scripts/build.py`.

- [ ] **Step 1: Create `sources.txt`**

```
# Blocklist sources — one directive per line. '#' begins a comment.
#
#   <url>                         fetch a single blocklist
#   repo <owner/name> [path/]     fetch every .txt in a repo (root-level by default)
#   whitelist <url>               allowlist, subtracted from the output
#   whitelist-repo <owner/name> [path/]
#
# See docs/superpowers/specs/2026-07-19-combined-blocklist-action-design.md

repo blocklistproject/Lists
```

- [ ] **Step 2: Create `.github/workflows/update-lists.yml`**

```yaml
name: Update blocklists

on:
  schedule:
    - cron: "0 6 * * 1"   # Mondays 06:00 UTC
  workflow_dispatch:

concurrency:
  group: update-lists
  cancel-in-progress: false

permissions:
  contents: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Build combined blocklist
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: python scripts/build.py

      - name: Commit updated lists
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add -A
          if git diff --cached --quiet; then
            echo "No changes to commit."
          else
            git commit -m "chore: update combined blocklist [skip ci]"
            git push
          fi
```

- [ ] **Step 3: Replace `README.md`** with usage + an empty managed block

```markdown
# pihole.lists

Automatically combined Pi-hole blocklists. A weekly GitHub Action fetches the
sources listed in [`sources.txt`](sources.txt), merges and de-duplicates them
into a single plain-domain blocklist (split across files only when needed to
stay under GitHub's size limit), subtracts any whitelisted domains, and commits
the result.

## Add your own sources

Edit [`sources.txt`](sources.txt). One directive per line:

| Directive | Effect |
|-----------|--------|
| `https://…/list.txt` | Fetch a single blocklist |
| `repo owner/name [path/]` | Fetch every `.txt` in a repo (root-level by default) |
| `whitelist https://…/allow.txt` | Allowlist, subtracted from the output |
| `whitelist-repo owner/name [path/]` | Allowlist from every `.txt` in a repo |

Then run the **Update blocklists** workflow (Actions tab → Run workflow), or wait
for the weekly run.

<!-- BLOCKLIST:START -->
<!-- BLOCKLIST:END -->
```

- [ ] **Step 4: Live smoke test with a small real source**

Temporarily verify end-to-end against one small list without committing outputs:

```bash
printf 'https://raw.githubusercontent.com/blocklistproject/Lists/master/vaping.txt\n' > /tmp/sources.txt
mkdir -p /tmp/smoke && cp /tmp/sources.txt /tmp/smoke/sources.txt && printf '# t\n' > /tmp/smoke/README.md
GITHUB_TOKEN="$(gh auth token)" py -c "import sys; sys.path.insert(0,'scripts'); import build; sys.exit(build.main(root='/tmp/smoke'))"
head -3 /tmp/smoke/blocklist.txt
wc -l /tmp/smoke/blocklist.txt
```

Expected: exit 0, `blocklist.txt` created with plausible domains (hundreds of lines), README managed block populated. This confirms real HTTP fetch + parse + write. (Uses `/tmp`, not the repo, so nothing to clean up in-tree.)

- [ ] **Step 5: Commit config + workflow + README**

```bash
git add sources.txt .github/workflows/update-lists.yml README.md
git commit -m "feat: add sources config, weekly workflow, and usage README"
```

- [ ] **Step 6: (Manual, by the user) Enable and trigger**

After pushing, the user runs the workflow once via **Actions → Update blocklists → Run workflow** to generate the first real `blocklist*.txt`. The first full run downloads ~144 MB and may take a few minutes; confirm it commits output and updates the README domain count.

---

## Notes for the implementer

- **Memory/time on CI:** the first real run holds a few million domain strings in a Python set (roughly 1–2 GB) and downloads ~144 MB. Fine on `ubuntu-latest` (7 GB RAM). If a future source pushes memory too high, switch the merge to stream through a temp file + `sort -u`; not needed now.
- **Token:** `GITHUB_TOKEN` is only needed to raise the GitHub **API** rate limit for `repo` expansion; raw file downloads work without it. Locally, `gh auth token` supplies one.
- **Branch name:** raw URLs are built from each source repo's own default branch (resolved via API), so `blocklistproject/Lists` resolving to `main`/`master` both work.

## Self-Review

- **Spec coverage:** merged+split output (Tasks 4/6), plain domains (Task 1/6), whitelist subtraction (Task 6 test), `sources.txt` config + repo/url/whitelist directives (Tasks 2/7), root-only repo scoping + denylist (Task 3), weekly + manual workflow (Task 7), fail-on-empty (Task 6), skip-bad-source (Task 6), stale-file cleanup (Task 6), README auto-update with counts + raw URLs (Task 5/6). All spec sections mapped.
- **Placeholder scan:** none — every code/test step contains complete content.
- **Type consistency:** `Source` fields, `parse_domain`, `select_repo_files`, `pack_domains`, `output_filenames`, `render_section`, `update_readme`, `SECTION_START/END`, `source_urls`, `main(root, token)` names are used identically across tasks.
