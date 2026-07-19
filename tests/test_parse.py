import blocklist as bl


def test_plain_domain():
    assert bl.parse_domain("Example.COM") == "example.com"


def test_hosts_format():
    assert bl.parse_domain("0.0.0.0 ads.example.com") == "ads.example.com"
    assert bl.parse_domain("127.0.0.1 tracker.net") == "tracker.net"


def test_adblock_syntax():
    assert bl.parse_domain("||ad.example.org^") == "ad.example.org"


def test_leading_wildcard_and_dot():
    assert bl.parse_domain("*.ads.example.com") == "ads.example.com"
    assert bl.parse_domain(".example.com") == "example.com"


def test_inline_and_full_comments():
    assert bl.parse_domain("# a comment") is None
    assert bl.parse_domain("! adblock comment") is None
    assert bl.parse_domain("example.com # trailing note") == "example.com"


def test_blank_and_junk():
    assert bl.parse_domain("") is None
    assert bl.parse_domain("   ") is None
    assert bl.parse_domain("requests==2.31.0") is None
    assert bl.parse_domain("some random log line here") is None
    assert bl.parse_domain("1.2.3.4") is None  # bare IP, not a domain


def test_underscore_domain_allowed():
    assert bl.parse_domain("_dmarc.example.com") == "_dmarc.example.com"
