# Tests for resource origin classification (src/browser.py): first-party
# vs third-party vs tracker/ads. This directly backs the resource-origin
# breakdown reported in the thesis (Chapter 6), so it's worth pinning down.
from browser import _classify_resource, _registered_domain


def test_registered_domain_strips_subdomains():
    assert _registered_domain("static.files.bbci.co.uk") == "co.uk"
    assert _registered_domain("www.bbc.com") == "bbc.com"
    assert _registered_domain("bbc.com") == "bbc.com"


def test_same_registered_domain_is_first_party():
    origin = _classify_resource("https://www.bbc.com/news", "https://static.bbc.com/logo.png")
    assert origin == "first_party"


def test_different_domain_is_third_party():
    origin = _classify_resource("https://www.bbc.com/news", "https://cdn.example.com/lib.js")
    assert origin == "third_party"


def test_known_tracker_domain_is_classified_as_tracker_before_third_party():
    # doubleclick.net is in TRACKER_DOMAINS and is also, by definition, a
    # different domain from the visited site - it must be labeled as a
    # tracker, not fall through to the third_party bucket.
    origin = _classify_resource("https://www.bbc.com/news", "https://doubleclick.net/ad.js")
    assert origin == "tracker_or_ads"


def test_tracker_keyword_in_url_is_caught_even_off_known_domains():
    origin = _classify_resource("https://example.com", "https://cdn.example.com/pagead/script.js")
    assert origin == "tracker_or_ads"


def test_lookalike_word_is_not_misclassified_as_tracker():
    # "readspeaker.com" contains "ads" as a substring but isn't a tracker -
    # the keyword check must be specific enough to not match this.
    origin = _classify_resource("https://example.com", "https://readspeaker.com/audio.mp3")
    assert origin != "tracker_or_ads"


def test_resource_with_no_resolvable_host_is_unknown_origin():
    origin = _classify_resource("https://example.com", "data:image/png;base64,abcd")
    assert origin == "unknown_origin"
