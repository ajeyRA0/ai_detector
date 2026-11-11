"""
PhishGuard - Lexical and Structural URL Feature Extraction
Extracts 15 lightweight, explainable features strictly from the URL string.
No network calls, WHOIS lookups, or page fetching are performed.
"""

import ipaddress
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

# Exact list of 15 feature names required by PhishGuard specification
FEATURE_NAMES: List[str] = [
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

# Common phishing keywords frequently observed in malicious URLs
SUSPICIOUS_KEYWORDS = (
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "update",
    "secure",
    "security",
    "account",
    "banking",
    "confirm",
    "password",
    "credential",
    "suspend",
    "suspended",
    "recover",
    "recovery",
    "wallet",
    "service",
    "alert",
    "support",
    "billing",
    "invoice",
    "auth",
    "authenticate",
    "client",
    "webscr",
    "ebayisapi",
    "paypal",
    "appleid",
    "passcode",
    "validate",
    "renew",
    "unlock",
)

# Common two-level ccTLD suffixes to ensure accurate subdomain counts
TWO_LEVEL_TLDS = (
    "co.uk",
    "com.au",
    "co.in",
    "net.in",
    "org.in",
    "edu.in",
    "gov.in",
    "org.uk",
    "ac.uk",
    "com.br",
    "co.nz",
    "co.za",
    "com.sg",
    "com.mx",
)


def _check_ip_address(domain_str: str) -> int:
    """Check if the extracted domain is a raw IPv4 or IPv6 address."""
    if not domain_str:
        return 0
    clean_host = domain_str.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return 1
    except ValueError:
        pass
    # Regex fallback for standard IPv4 notation
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", clean_host):
        return 1
    return 0


def _parse_url_safely(raw_url: str):
    """
    Safely parse URL components handling missing schemes, ports, credentials, and malformed inputs.
    Never throws an exception.
    """
    url_to_parse = raw_url.strip()
    has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url_to_parse))

    if not has_scheme:
        if url_to_parse.startswith("//"):
            url_to_parse = "http:" + url_to_parse
        else:
            url_to_parse = "http://" + url_to_parse

    try:
        parsed = urlparse(url_to_parse)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
    except Exception:
        # Fallback regex parsing if urlparse fails on edge-case malformed characters
        host_match = re.search(
            r"^(?:https?://)?(?:[^@/:]+@)?([^/:]+)", url_to_parse, re.IGNORECASE
        )
        hostname = host_match.group(1).lower() if host_match else ""
        path_match = re.search(
            r"^(?:https?://)?(?:[^@/:]+@)?[^/:]+(/.*)?$", url_to_parse, re.IGNORECASE
        )
        path = path_match.group(1) if (path_match and path_match.group(1)) else ""

    return hostname.lower(), path


def _calculate_subdomains(domain: str, is_ip: int) -> int:
    """Calculate the number of subdomains in a domain string."""
    if is_ip or not domain:
        return 0

    parts = [p for p in domain.split(".") if p]
    if len(parts) <= 2:
        return 0

    # Handle recognized two-level ccTLDs (e.g. example.co.uk)
    for tld in TWO_LEVEL_TLDS:
        if domain.endswith("." + tld):
            return max(0, len(parts) - 3)

    return max(0, len(parts) - 2)


def extract_features(url: Any) -> Dict[str, int]:
    """
    Extract the 15 required lexical and structural features from a URL.

    Parameters:
        url (str): The URL string to analyze.

    Returns:
        Dict[str, int]: Dictionary containing exact 15 feature keys with integer values.
    """
    if url is None:
        url_str = ""
    elif not isinstance(url, str):
        url_str = str(url)
    else:
        url_str = url.strip()

    # Feature 1: Total URL length
    url_length = len(url_str)

    # Detect HTTPS usage (original input must specify https scheme)
    has_https = 1 if url_str.lower().startswith("https://") else 0

    # Parse hostname and path safely
    domain, path = _parse_url_safely(url_str)

    # Feature 11: Raw IP address detection
    has_ip = _check_ip_address(domain)

    # Feature 2: Domain length
    domain_length = len(domain)

    # Feature 3: Dot count
    num_dots = url_str.count(".")

    # Feature 4: Hyphen count
    num_hyphens = url_str.count("-")

    # Feature 5: At symbol count (@ trick)
    num_at_symbols = url_str.count("@")

    # Feature 6: Question mark count
    num_question_marks = url_str.count("?")

    # Feature 7: Equal sign count
    num_equal_signs = url_str.count("=")

    # Feature 8: Underscore count
    num_underscores = url_str.count("_")

    # Feature 9: Digits count
    num_digits = sum(1 for c in url_str if c.isdigit())

    # Feature 10: Subdomain count
    num_subdomains = _calculate_subdomains(domain, has_ip)

    # Feature 13: Path length
    path_length = len(path)

    # Feature 14: Suspicious word check
    url_lower = url_str.lower()
    has_suspicious_word = 1 if any(word in url_lower for word in SUSPICIOUS_KEYWORDS) else 0

    # Feature 15: Slash count
    num_slashes = url_str.count("/")

    return {
        "url_length": int(url_length),
        "domain_length": int(domain_length),
        "num_dots": int(num_dots),
        "num_hyphens": int(num_hyphens),
        "num_at_symbols": int(num_at_symbols),
        "num_question_marks": int(num_question_marks),
        "num_equal_signs": int(num_equal_signs),
        "num_underscores": int(num_underscores),
        "num_digits": int(num_digits),
        "num_subdomains": int(num_subdomains),
        "has_ip_address": int(has_ip),
        "has_https": int(has_https),
        "path_length": int(path_length),
        "has_suspicious_word": int(has_suspicious_word),
        "num_slashes": int(num_slashes),
    }


def explain_features(features: Dict[str, int], url: str) -> List[str]:
    """
    Generate plain-language explanation reasons based on extracted features.
    Provides explainable AI (XAI) output suitable for viva presentation and end users.
    """
    reasons: List[str] = []

    if features.get("has_ip_address", 0) == 1:
        reasons.append("URL uses a raw IP address instead of a legitimate registered domain name.")

    if features.get("num_at_symbols", 0) > 0:
        reasons.append(
            f"URL contains the '@' symbol ({features['num_at_symbols']}x), which can spoof browser address display and obscure the real host."
        )

    if features.get("has_suspicious_word", 0) == 1:
        url_lower = url.lower()
        matched = [w for w in SUSPICIOUS_KEYWORDS if w in url_lower]
        reasons.append(
            f"URL contains sensitive phishing lure keywords: {', '.join(matched[:4])}."
        )

    if features.get("has_https", 0) == 0:
        reasons.append("URL does not use HTTPS secure transport protocol.")

    if features.get("num_subdomains", 0) >= 2:
        reasons.append(
            f"High subdomain count ({features['num_subdomains']} subdomains) detected, commonly used to masquerade under trusted brand names."
        )

    if features.get("num_hyphens", 0) >= 3:
        reasons.append(
            f"Excessive hyphens ({features['num_hyphens']}x) found in URL, a hallmark of typosquatting and deceptive domain naming."
        )

    if features.get("num_dots", 0) >= 4:
        reasons.append(
            f"Unusually high dot count ({features['num_dots']}x) indicating complex host nesting or obfuscated endpoints."
        )

    if features.get("url_length", 0) > 85:
        reasons.append(
            f"Abnormally long URL ({features['url_length']} characters), often used to hide the true destination or bypass security filters."
        )

    if features.get("num_digits", 0) >= 12:
        reasons.append(
            f"Elevated digit count ({features['num_digits']} numbers), characteristic of automated session IDs or dynamic phish generation."
        )

    if features.get("num_equal_signs", 0) >= 3 or features.get("num_question_marks", 0) >= 2:
        reasons.append("Heavy query string parameterization commonly associated with tracking and credential redirection.")

    # If no red flags detected, provide reassurance points
    if not reasons:
        reasons.append("URL exhibits clean lexical structure with standard domain and path parameters.")
        if features.get("has_https", 0) == 1:
            reasons.append("Secure HTTPS protocol is actively utilized.")
        reasons.append("No credential spoofing symbols (@) or raw IP addresses detected.")
        reasons.append("No suspicious phishing keywords detected in URL string.")

    return reasons
