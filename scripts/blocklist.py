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
