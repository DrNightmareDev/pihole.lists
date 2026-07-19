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
