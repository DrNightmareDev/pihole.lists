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
