"""
PhishGuard - Real Dataset Builder
Combines real-world verified phishing URLs from PhishTank and verified legitimate
domains from the Tranco Top Sites ranking to produce a benchmark dataset.

Sources:
1. PhishTank CSV: Community-verified phishing database (https://phishtank.org/)
   Direct download: https://data.phishtank.com/data/online-valid.csv
2. Tranco List: Research-oriented top 1M ranking of benign web domains (https://tranco-list.eu/)
   Direct download: https://tranco-list.eu/top-1m.csv.zip
"""

import argparse
import io
import os
import sys
import zipfile
from typing import Optional
import pandas as pd
import requests


def load_phishtank_csv(file_or_url: str, limit: Optional[int] = None) -> pd.DataFrame:
    """Load and parse PhishTank CSV into a standardized DataFrame (url, label=1)."""
    print(f"[*] Reading PhishTank data from: {file_or_url}")
    if file_or_url.startswith("http://") or file_or_url.startswith("https://"):
        headers = {"User-Agent": "PhishGuard-Dataset-Builder/1.0"}
        response = requests.get(file_or_url, headers=headers, timeout=30)
        response.raise_for_status()
        df = pd.read_csv(io.StringIO(response.text))
    else:
        df = pd.read_csv(file_or_url)

    # PhishTank CSV typically contains a 'url' column
    url_col = None
    for candidate in ["url", "URL", "phish_detail_url"]:
        if candidate in df.columns:
            url_col = candidate
            break

    if not url_col:
        raise ValueError(f"Could not locate URL column in PhishTank CSV. Columns found: {list(df.columns)}")

    # Clean and filter
    urls = df[url_col].dropna().astype(str).str.strip()
    urls = urls[urls.str.len() > 8]
    if limit:
        urls = urls.head(limit)

    result_df = pd.DataFrame({"url": urls, "label": 1})
    print(f"[+] Loaded {len(result_df)} real phishing URLs from PhishTank.")
    return result_df


def load_tranco_csv(file_or_url: str, limit: Optional[int] = None) -> pd.DataFrame:
    """Load and parse Tranco top domains into benign URLs (url, label=0)."""
    print(f"[*] Reading Tranco data from: {file_or_url}")
    content_bytes: Optional[bytes] = None

    if file_or_url.startswith("http://") or file_or_url.startswith("https://"):
        headers = {"User-Agent": "PhishGuard-Dataset-Builder/1.0"}
        response = requests.get(file_or_url, headers=headers, timeout=45)
        response.raise_for_status()
        content_bytes = response.content
    else:
        with open(file_or_url, "rb") as f:
            content_bytes = f.read()

    # Handle zip archive if downloaded Tranco zip file
    if file_or_url.endswith(".zip") or (content_bytes and content_bytes[:2] == b"PK"):
        with zipfile.ZipFile(io.BytesIO(content_bytes)) as z:
            csv_name = z.namelist()[0]
            with z.open(csv_name) as zf:
                df = pd.read_csv(zf, header=None)
    else:
        df = pd.read_csv(io.BytesIO(content_bytes), header=None)

    # Tranco format is: [rank, domain] or just [domain]
    domain_col_idx = 1 if df.shape[1] > 1 else 0
    domains = df.iloc[:, domain_col_idx].dropna().astype(str).str.strip()

    if limit:
        domains = domains.head(limit)

    # Form standard URLs with https/http
    benign_urls = []
    for idx, domain in enumerate(domains):
        scheme = "https://" if idx % 10 != 0 else "http://"
        benign_urls.append(f"{scheme}{domain}")

    result_df = pd.DataFrame({"url": benign_urls, "label": 0})
    print(f"[+] Loaded {len(result_df)} benign URLs from Tranco.")
    return result_df


def build_real_dataset(phishtank_src: str, tranco_src: str, limit_per_class: int, output_path: str):
    """Combine PhishTank and Tranco into a balanced benchmark dataset."""
    phish_df = load_phishtank_csv(phishtank_src, limit=limit_per_class)
    legit_df = load_tranco_csv(tranco_src, limit=limit_per_class)

    # Balance classes
    min_count = min(len(phish_df), len(legit_df))
    phish_df = phish_df.sample(n=min_count, random_state=42)
    legit_df = legit_df.sample(n=min_count, random_state=42)

    combined = pd.concat([phish_df, legit_df], ignore_index=True)
    combined = combined.sample(frac=1.0, random_state=42).drop_duplicates(subset=["url"]).reset_index(drop=True)

    combined.to_csv(output_path, index=False)
    print(f"\n[+] Successfully created benchmark dataset: {output_path}")
    print(f"[+] Total samples: {len(combined)}")
    print(f"[+] Class distribution:\n{combined['label'].value_counts().rename({0: 'Legitimate (0)', 1: 'Phishing (1)'})}")


def main():
    parser = argparse.ArgumentParser(description="Build real phishing detection dataset from PhishTank and Tranco.")
    parser.add_argument("--phishtank", type=str, default=None, help="Path or URL to PhishTank online-valid.csv")
    parser.add_argument("--tranco", type=str, default=None, help="Path or URL to Tranco top-1m.csv (or .zip)")
    parser.add_argument("--limit", type=int, default=5000, help="Maximum samples per class (default: 5000)")
    parser.add_argument("--output", type=str, default="real_dataset.csv", help="Output path (default: real_dataset.csv)")
    parser.add_argument("--download", action="store_true", help="Download current files from official online URLs")
    args = parser.parse_args()

    phishtank_src = args.phishtank
    tranco_src = args.tranco

    if args.download:
        print("[*] Downloading latest live datasets...")
        phishtank_src = phishtank_src or "http://data.phishtank.com/data/online-valid.csv"
        tranco_src = tranco_src or "https://tranco-list.eu/top-1m.csv.zip"

    if not phishtank_src or not tranco_src:
        print("=" * 70)
        print("PhishGuard - Real Dataset Preparation Guide")
        print("=" * 70)
        print("To build a production-grade benchmark dataset, provide both files:")
        print("\n1. PhishTank CSV (Phishing URLs):")
        print("   Download: https://data.phishtank.com/data/online-valid.csv")
        print("   Save as: data/phishtank.csv")
        print("\n2. Tranco List (Benign Domains):")
        print("   Download: https://tranco-list.eu/top-1m.csv.zip")
        print("   Save as: data/tranco.csv")
        print("\n3. Run builder:")
        print("   python build_real_dataset.py --phishtank data/phishtank.csv --tranco data/tranco.csv --limit 5000")
        print("   OR run with --download to attempt direct download:")
        print("   python build_real_dataset.py --download --limit 2000")
        print("=" * 70)
        sys.exit(0)

    try:
        build_real_dataset(phishtank_src, tranco_src, args.limit, args.output)
    except Exception as e:
        print(f"[!] Error building dataset: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
