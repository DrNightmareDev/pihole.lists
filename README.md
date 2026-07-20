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

## Combined blocklist

- **Total domains:** 4,835,687
- **Last updated:** 2026-07-20 08:46:53 UTC
- **Output files:** 3

### Subscribe in Pi-hole

Add these URLs as adlists (Settings → Lists):

- `https://raw.githubusercontent.com/DrNightmareDev/pihole.lists/main/blocklist-01.txt`
- `https://raw.githubusercontent.com/DrNightmareDev/pihole.lists/main/blocklist-02.txt`
- `https://raw.githubusercontent.com/DrNightmareDev/pihole.lists/main/blocklist-03.txt`

### Sources

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
# curated ads / coinmining / facebook, low false-positive
repo anudeepND/blacklist
# SmartTV / IoT / mobile tracking lists
repo Perflyst/PiHoleBlocklist
```

<!-- BLOCKLIST:END -->
