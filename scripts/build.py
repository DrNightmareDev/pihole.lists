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
