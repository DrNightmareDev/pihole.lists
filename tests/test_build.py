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
