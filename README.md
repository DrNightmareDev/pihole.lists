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
