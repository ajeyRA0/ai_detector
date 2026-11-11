"""
PhishGuard - Synthetic Sample Dataset Generator
Generates a representative demonstration dataset (sample_dataset.csv)
containing realistic legitimate (label=0) and phishing (label=1) URLs.
"""

import argparse
import os
import random
from typing import List, Tuple
import pandas as pd

# Fix random seed for reproducibility
random.seed(42)

LEGITIMATE_DOMAINS = [
    "google.com", "youtube.com", "github.com", "wikipedia.org", "amazon.com",
    "microsoft.com", "apple.com", "linkedin.com", "stackoverflow.com", "reddit.com",
    "medium.com", "nytimes.com", "bbc.co.uk", "cnn.com", "cloudflare.com",
    "mozilla.org", "python.org", "archive.org", "wordpress.org", "dropbox.com",
    "spotify.com", "salesforce.com", "quora.com", "coursera.org", "mit.edu",
    "stanford.edu", "harvard.edu", "nih.gov", "nasa.gov", "un.org"
]

LEGITIMATE_SUBDOMAINS = ["www", "blog", "docs", "support", "developer", "en", "status", "api", "news", "mail"]

LEGITIMATE_PATHS = [
    "",
    "/",
    "/index.html",
    "/about-us",
    "/contact",
    "/terms-of-service",
    "/privacy-policy",
    "/wiki/Machine_learning",
    "/wiki/Artificial_intelligence",
    "/questions/1289381/how-to-extract-features",
    "/questions/9837412/python-flask-routing",
    "/search?q=cybersecurity+best+practices",
    "/search?q=scikit-learn+random+forest",
    "/projects/open-source/repository",
    "/article/2026/04/technology-advancements",
    "/downloads/releases/version-3.2.0.tar.gz",
    "/watch?v=dQw4w9WgXcQ",
    "/categories/technology/cybersecurity",
    "/documentation/getting-started",
    "/posts/exploring-neural-architectures",
    "/support/accounts/answer/198273",
    "/user/profile/settings",
    "/jobs/search?location=remote&title=software-engineer",
    "/products/laptops/macbook-pro-16",
    "/pricing/business-plans?currency=USD",
    "/research/publications/2026/phishing-detection-analysis",
    "/help/kb/view-article?id=83921&category=networking"
]

PHISHING_BRANDS = [
    "paypal", "chase", "bankofamerica", "wellsfargo", "appleid", "microsoft-support",
    "netflix-billing", "amazon-security", "facebook-verify", "instagram-badge",
    "gmail-login", "coinbase-wallet", "binance-verify", "metamask-auth", "dhl-tracking"
]

PHISHING_TLDS = [
    ".xyz", ".top", ".cc", ".work", ".click", ".ru", ".cam", ".vip", ".pw", ".space", ".cfd", ".sbs"
]

PHISHING_LURES = [
    "login", "verify", "secure-update", "confirm-account", "wallet-recovery",
    "suspended-notice", "auth-portal", "credential-check", "billing-resolve",
    "unlock-device", "identity-verification", "signin-session", "webscr-login",
    "security-alert-center", "password-reset-confirm"
]


def generate_legitimate_url() -> str:
    """Generate a realistic legitimate URL."""
    scheme = "https://" if random.random() < 0.94 else "http://"
    domain = random.choice(LEGITIMATE_DOMAINS)
    
    # 25% chance of legitimate subdomain like docs.python.org or support.google.com
    if random.random() < 0.25:
        sub = random.choice(LEGITIMATE_SUBDOMAINS)
        domain = f"{sub}.{domain}"
        
    path = random.choice(LEGITIMATE_PATHS)
    
    # Optional benign query param
    if path and "?" not in path and random.random() < 0.15:
        page_num = random.randint(1, 20)
        path += f"?page={page_num}&sort=popular"
        
    return f"{scheme}{domain}{path}"


def generate_phishing_url() -> str:
    """Generate a realistic phishing URL exhibiting characteristic malicious markers."""
    technique = random.choice(["ip_address", "brand_spoof", "deep_subdomain", "at_trick", "long_token", "typosquatting"])
    scheme = "http://" if random.random() < 0.70 else "https://"

    if technique == "ip_address":
        ip = f"{random.randint(45, 215)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        port = f":{random.choice([8080, 8000, 8888, 3000])}" if random.random() < 0.25 else ""
        lure = random.choice(PHISHING_LURES)
        variant = random.choice(["simple", "html", "param", "bare"])
        if variant == "simple":
            return f"{scheme}{ip}{port}/{lure}"
        elif variant == "html":
            return f"{scheme}{ip}{port}/{lure}.html"
        elif variant == "bare":
            return f"{scheme}{ip}{port}/login"
        else:
            return f"{scheme}{ip}{port}/{lure}/index.php?client_id={random.randint(100000, 999999)}"

    elif technique == "at_trick":
        # @ symbol trick: browser directs to host AFTER the @ symbol
        spoofed = random.choice(LEGITIMATE_DOMAINS)
        evil_host = random.choice(PHISHING_BRANDS) + random.choice(PHISHING_TLDS)
        lure = random.choice(PHISHING_LURES)
        return f"{scheme}{spoofed}@{evil_host}/{lure}?session={random.randint(10000, 99999)}"

    elif technique == "deep_subdomain":
        # Multi-tiered deceptive subdomains
        brand = random.choice(PHISHING_BRANDS)
        lure = random.choice(PHISHING_LURES)
        evil_domain = f"server-{random.randint(10, 99)}{random.choice(PHISHING_TLDS)}"
        return f"{scheme}{lure}.secure.{brand}.account-notice.{evil_domain}/auth?id={random.randint(1000, 9999)}"

    elif technique == "typosquatting":
        # Hyphen-packed brand impersonation
        brand = random.choice(PHISHING_BRANDS)
        lure = random.choice(PHISHING_LURES)
        tld = random.choice(PHISHING_TLDS)
        host = f"{brand}-{lure}-{random.choice(['online', 'center', 'portal', 'alert'])}{tld}"
        return f"{scheme}{host}/verify?token={random.randint(10000000, 99999999)}&secure=true"

    elif technique == "long_token":
        # Extremely long obfuscated path with credential tracking parameters
        brand = random.choice(PHISHING_BRANDS)
        tld = random.choice(PHISHING_TLDS)
        token_a = "".join(random.choices("0123456789abcdef", k=32))
        token_b = "".join(random.choices("0123456789", k=16))
        return f"{scheme}{brand}-security{tld}/cgi-bin/webscr?cmd=_login_run&dispatch={token_a}&user_session={token_b}&verify_account=1"

    else: # brand_spoof
        brand = random.choice(PHISHING_BRANDS)
        lure = random.choice(PHISHING_LURES)
        tld = random.choice(PHISHING_TLDS)
        return f"{scheme}{brand}-security-update{tld}/{lure}.html"


def generate_dataset(num_samples: int = 1500) -> pd.DataFrame:
    """Create a balanced synthetic dataset of legitimate (0) and phishing (1) URLs."""
    half = num_samples // 2
    records: List[Tuple[str, int]] = []

    # Generate legitimate URLs
    for _ in range(half):
        records.append((generate_legitimate_url(), 0))

    # Generate phishing URLs
    for _ in range(num_samples - half):
        records.append((generate_phishing_url(), 1))

    # Shuffle dataset
    random.shuffle(records)

    df = pd.DataFrame(records, columns=["url", "label"])
    # Drop duplicates if any
    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)
    return df


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic sample dataset for PhishGuard demonstration.")
    parser.add_argument("--output", type=str, default="sample_dataset.csv", help="Output CSV path (default: sample_dataset.csv)")
    parser.add_argument("--count", type=int, default=1500, help="Number of samples to generate (default: 1500)")
    args = parser.parse_args()

    output_path = os.path.abspath(args.output)
    print(f"[*] Generating {args.count} synthetic URLs for demonstration...")
    df = generate_dataset(args.count)

    df.to_csv(output_path, index=False)
    print(f"[+] Dataset saved to: {output_path}")
    print(f"[+] Total samples: {len(df)}")
    print(f"[+] Distribution:\n{df['label'].value_counts().rename({0: 'Legitimate (0)', 1: 'Phishing (1)'})}")
    print("\n[NOTE] This synthetic dataset is designed for demo and viva defense.")
    print("For real-world evaluation, use build_real_dataset.py with PhishTank and Tranco datasets.")


if __name__ == "__main__":
    main()
