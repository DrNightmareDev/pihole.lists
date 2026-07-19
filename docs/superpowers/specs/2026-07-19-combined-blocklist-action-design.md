# Combined Pi-hole Blocklist — GitHub Action Design

**Date:** 2026-07-19
**Repo:** `DrNightmareDev/pihole.lists`

## Goal

Automatically fetch many Pi-hole blocklists, merge them into a single
deduplicated plain-domain blocklist (split into as few files as possible while
staying under GitHub's per-file size limit), subtract any whitelisted domains,
and refresh weekly via a GitHub Action. Sources are declared in a tracked config
file so new lists (direct URLs or whole repos) can be added without touching
code.

## Decisions (locked)

| Topic | Decision |
|-------|----------|
| Output structure | **One merged, deduplicated list**; split into `blocklist-NN.txt` only when size requires it |
| Output format | **Plain domains**, one per line (most compact; Pi-hole native) |
| Whitelist | **Subtracted** from output (capability; no default whitelist source configured yet) |
| Source config | **Tracked file** `sources.txt` at repo root |
| Schedule | **Weekly** (plus manual `workflow_dispatch`) |
| Output location | Repo **root** (clean raw URLs) |
| Default branch | `main` |
| Build tool | **Python 3 standard library only** (no pip installs) |
| Initial source | `blocklistproject/Lists` (mcintosh109 intentionally omitted for now) |

## Source repo facts (`blocklistproject/Lists`)

- Root-level `.txt` files are the canonical lists (`ads.txt`, `malware.txt`,
  `porn.txt`, `abuse.txt`, `fraud.txt`, `gambling.txt`, `phishing.txt`,
  `tracking.txt`, `redirect.txt`, `basic.txt`, `youtube.txt`, `facebook.txt`,
  `drugs.txt`, `scam.txt`, `tiktok.txt`, `ransomware.txt`, `torrent.txt`,
  `piracy.txt`, `twitter.txt`, `crypto.txt`, `adobe.txt`, `whatsapp.txt`,
  `vaping.txt`, `smart-tv.txt`, `fortnite.txt`).
- **Format is hosts**: `0.0.0.0 domain`, with `#` comment headers.
- The same lists are duplicated in subfolders (`dnsmasq-version/`, `adguard/`,
  `alt-version/`) and as `.bak` / `.ip` files — these MUST be excluded.
- Non-list junk at root exists (`requirements.txt`, `cron_output.txt`) — MUST be
  excluded.
- Root canonical lists total **~144 MB in hosts format**. Deduplicated plain
  domains are expected to produce roughly **2–3 output files** at the split
  threshold.
- No whitelist file ships in this repo.

## Components

### 1. `sources.txt` (repo root)

One directive per line. `#` begins a comment. Blank lines ignored.

```
# <url>                     fetch a single blocklist
# repo <owner/name> [path/] fetch every .txt in a repo (default: root-level only)
# whitelist <url>           allowlist, subtracted from output
# whitelist-repo <owner/name> [path/]
repo blocklistproject/Lists
```

**Repo expansion rules:**
- Query the repo tree via the GitHub API (branch-agnostic `HEAD`).
- Include `.txt` blobs only.
- Default scope is **root-level only** (path contains no `/`). An optional
  `path/` argument scopes to that prefix instead.
- Exclude by name (case-insensitive): anything matching `*whitelist*`,
  `*allow*`, `readme*`, `changelog*`, `requirements*`, `cron_output*`, and any
  `.bak` file.
- Use `GITHUB_TOKEN` for API calls to avoid rate limiting.

### 2. `scripts/build.py`

Pure Python 3 standard library. Pipeline:

1. Parse `sources.txt` into blocklist sources and whitelist sources.
2. Expand `repo` / `whitelist-repo` directives to concrete raw file URLs
   (resolving the repo's default branch via the API).
3. Download every source (with a couple of retries; a failed source logs a
   warning and is skipped — one dead source must not fail the whole build).
4. **Tolerant parse** each line into a domain:
   - strip inline/whole-line comments (`#`, `!`),
   - strip hosts prefixes (`0.0.0.0`, `127.0.0.1`, `::`, `::1`),
   - strip AdBlock syntax (`||domain^`),
   - strip a leading `*.`,
   - lowercase, trim whitespace,
   - **validate**: must be a plausible domain (labels of `[a-z0-9-]`, at least
     one dot, no spaces, total length sane). Invalid lines are dropped. This is
     the second line of defense against junk files.
5. Merge all blocklist domains into a set; **subtract** the whitelist set.
6. Sort ascending.
7. Write output at repo root:
   - If total size ≤ threshold → single `blocklist.txt`.
   - Else split into `blocklist-01.txt`, `blocklist-02.txt`, … packing each file
     up to the threshold (as few files as possible). Remove any stale
     higher-numbered split files from a previous larger run.
   - **Split threshold: 45 MB** (safely under GitHub's 50 MB warning / 100 MB
     hard limit).
8. Regenerate the managed section of `README.md`: total domain count,
   last-updated timestamp (UTC), the list of source directives, and the raw
   subscription URL(s) for Pi-hole.

Output file naming convention: if a single file, name it `blocklist.txt`. If
split, use only the numbered `blocklist-NN.txt` files (no bare `blocklist.txt`),
so the README's URL list is unambiguous. On each run, delete any output files
from the previous run that the current run did not produce (e.g. a bare
`blocklist.txt` left over when the list has since grown past the threshold).

### 3. `.github/workflows/update-lists.yml`

- **Triggers:** `schedule` (weekly, Monday) + `workflow_dispatch`.
- **Permissions:** `contents: write`.
- **Steps:** checkout → set up Python → run `scripts/build.py` (env
  `GITHUB_TOKEN`) → commit changed output + README **only if there is a diff**,
  with a bot author and a clear message.
- Concurrency guard so overlapping runs don't race.

## Data flow

```
sources.txt
   │  parse + expand repos (GitHub API)
   ▼
[ raw list URLs ]  ── download ──►  tolerant parse ──►  domain sets
                                                          │
                          blocklist ∪ ...  minus  whitelist ∪ ...
                                                          │  sort
                                                          ▼
                                        pack into ≤45MB files
                                                          ▼
                            blocklist.txt  (or blocklist-01.txt, -02.txt, …)
                                                          ▼
                                   README managed section (counts + raw URLs)
```

## Error handling

- A source that fails to download or returns non-200 → warn + skip; build
  continues with remaining sources.
- The GitHub API tree fetch failing for a `repo` directive → warn + skip that
  repo.
- If, after everything, zero domains were collected → **fail the build**
  (prevents publishing an empty list that would silently unblock everything).
- Commit step is a no-op when nothing changed.

## Testing

- Unit-test the line parser against representative inputs: plain domain, hosts
  `0.0.0.0`/`127.0.0.1`, AdBlock `||x^`, comment lines, blank lines, junk
  (`requirements.txt`-style content), uppercase, leading `*.`.
- Unit-test the splitter: total under threshold → one file; over → N files each
  ≤ threshold; stale-file cleanup.
- Unit-test whitelist subtraction and dedup.
- Smoke-test `build.py` against one small real list (e.g. `youtube.txt`) to
  confirm end-to-end parse/write.

## Output for Pi-hole users

Subscribe to each generated raw URL, e.g.:
`https://raw.githubusercontent.com/DrNightmareDev/pihole.lists/main/blocklist-01.txt`
(the README lists the current set automatically).

## Explicitly out of scope

- Per-category output files (single merged list was chosen).
- mcintosh109 repository (deferred).
- Git LFS / files above the 45 MB threshold in a single blob.
- Any format other than plain domains for output.
