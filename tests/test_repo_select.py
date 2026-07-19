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
