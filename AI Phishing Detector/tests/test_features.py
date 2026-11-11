"""
Unit tests for PhishGuard Feature Extraction module.
Covers critical edge cases: IP URLs, @ trick, missing schemes, long URLs, ports, malformed inputs.
"""

import pytest
from feature_extraction import FEATURE_NAMES, explain_features, extract_features


def test_feature_names_integrity():
    """Verify exact 15 feature names are present and correctly spelled."""
    expected_15 = [
        "url_length",
        "domain_length",
        "num_dots",
        "num_hyphens",
        "num_at_symbols",
        "num_question_marks",
        "num_equal_signs",
        "num_underscores",
        "num_digits",
        "num_subdomains",
        "has_ip_address",
        "has_https",
        "path_length",
        "has_suspicious_word",
        "num_slashes",
    ]
    assert FEATURE_NAMES == expected_15
    assert len(FEATURE_NAMES) == 15


def test_standard_legitimate_url():
    """Test standard benign HTTPS URL."""
    url = "https://www.google.com/search?q=pytest"
    feats = extract_features(url)

    assert isinstance(feats, dict)
    assert len(feats) == 15
    assert feats["has_https"] == 1
    assert feats["has_ip_address"] == 0
    assert feats["num_at_symbols"] == 0
    assert feats["num_question_marks"] == 1
    assert feats["num_equal_signs"] == 1
    assert feats["url_length"] == len(url)
    assert feats["domain_length"] == len("www.google.com")
    assert feats["num_subdomains"] == 1  # 'www'


def test_raw_ip_address_url():
    """Test URL containing a raw IPv4 address."""
    url = "http://192.168.1.1:8080/admin/login.php"
    feats = extract_features(url)

    assert feats["has_ip_address"] == 1
    assert feats["num_digits"] == 12  # '192.168.1.1' (8) + '8080' (4)
    assert feats["has_https"] == 0
    assert feats["has_suspicious_word"] == 1  # 'login'
    assert feats["num_subdomains"] == 0


def test_at_symbol_spoofing():
    """Test URL containing @ symbol credential masquerading."""
    url = "https://legitimate-bank.com@malicious-attacker.xyz/auth"
    feats = extract_features(url)

    assert feats["num_at_symbols"] == 1
    assert feats["domain_length"] == len("malicious-attacker.xyz")
    assert feats["has_https"] == 1
    assert feats["has_suspicious_word"] == 1  # 'auth'


def test_no_scheme_url():
    """Test URL provided without explicit scheme (e.g. domain.com/path)."""
    url = "paypal-security-verification.com/login/update"
    feats = extract_features(url)

    assert feats["has_https"] == 0
    assert feats["domain_length"] == len("paypal-security-verification.com")
    assert feats["has_suspicious_word"] == 1
    assert feats["num_hyphens"] == 2
    assert feats["num_slashes"] == 2


def test_extremely_long_url():
    """Test unusually long URL (> 500 characters)."""
    long_tail = "a" * 800
    url = f"https://example.com/very/deep/path/{long_tail}"
    feats = extract_features(url)

    assert feats["url_length"] > 800
    assert feats["domain_length"] == len("example.com")
    assert feats["path_length"] > 800
    assert isinstance(feats["url_length"], int)


def test_subdomains_and_cctld():
    """Test subdomain calculation on standard domains and two-level ccTLDs."""
    # Standard: login.secure.brand.com -> 2 subdomains (login, secure)
    f1 = extract_features("https://login.secure.brand.com/")
    assert f1["num_subdomains"] == 2

    # Two-level ccTLD: login.portal.company.co.uk -> 2 subdomains
    f2 = extract_features("https://login.portal.company.co.uk/")
    assert f2["num_subdomains"] == 2

    # Root domain on ccTLD: company.co.uk -> 0 subdomains
    f3 = extract_features("https://company.co.uk/")
    assert f3["num_subdomains"] == 0


def test_malformed_input_no_crash():
    """Ensure malformed input, None, or empty strings never crash."""
    for bad in ["", "   ", None, "http://", "://broken", "http://[invalid-ipv6/path", 12345]:
        feats = extract_features(bad)
        assert isinstance(feats, dict)
        assert len(feats) == 15
        for val in feats.values():
            assert isinstance(val, int)


def test_explain_features_output():
    """Test human-readable reasons generated for explaining threat signals."""
    phish_feats = extract_features("http://192.168.1.1@evil-host.com/login-verify")
    reasons = explain_features(phish_feats, "http://192.168.1.1@evil-host.com/login-verify")

    assert isinstance(reasons, list)
    assert len(reasons) > 0
    reasons_text = " ".join(reasons)
    assert "@" in reasons_text or "login" in reasons_text or "HTTPS" in reasons_text

    # Benign reasons
    clean_feats = extract_features("https://www.wikipedia.org/wiki/Computer")
    clean_reasons = explain_features(clean_feats, "https://www.wikipedia.org/wiki/Computer")
    assert len(clean_reasons) > 0
    assert any("clean lexical structure" in r.lower() or "https" in r.lower() for r in clean_reasons)
