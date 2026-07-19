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
