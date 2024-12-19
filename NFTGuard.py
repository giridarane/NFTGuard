#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
import re
import sys

def fetch_url(url):
    """Fetch the page source of a URL."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text, response.headers
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching URL: {e}")
        return None, None

def extract_metadata(html):
    """Extract metadata from the HTML source."""
    soup = BeautifulSoup(html, 'html.parser')
    metadata = {meta.get('name', '').lower(): meta.get('content', '') for meta in soup.find_all('meta')}
    return metadata

def find_sensitive_keywords(html):
    """Search for sensitive keywords in the page source, customized for NFT data."""
    nft_keywords = [
        'api_key', 'private_key', 'access_token', 'secret', 'password',
        'wallet_address', 'minted_at', 'transaction_hash', 'nft_id', 'smart_contract_address',
        'private_wallet', 'creator_wallet', 'nft_metadata', 'user_wallet', 'minting_fee', 'transaction_signature',
        'purchase_price', 'royalty', 'nft_creator', 'transaction_token', 'minting_date'
    ]
    
    found = {keyword: re.findall(rf'{keyword}[:=][\'"]?([\w-]+)', html, re.IGNORECASE) for keyword in nft_keywords}
    return {key: value for key, value in found.items() if value}

def find_open_redirects(html, base_url):
    """Identify potential open redirects."""
    soup = BeautifulSoup(html, 'html.parser')
    redirects = []
    for link in soup.find_all('a', href=True):
        if "http" in link['href'] and base_url not in link['href']:
            redirects.append(link['href'])
    return redirects

def analyze_javascript(html):
    """Analyze JavaScript for sensitive patterns."""
    scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
    api_calls = [script for script in scripts if "fetch" in script or "XMLHttpRequest" in script]
    return api_calls

def deep_scan_for_tokens(html):
    """Scan for exposed API keys, tokens, and secrets in the page source."""
    # Common patterns for API keys, tokens, and secrets
    token_patterns = [
        r'([A-Za-z0-9_-]{32,64})',  # Generic long API key or token (e.g., GitHub, Google API keys)
        r'(?<=access_token[:=]["\'])([A-Za-z0-9_-]{20,40})(?=["\'])',  # Access token
        r'(?<=api_key[:=]["\'])([A-Za-z0-9_-]{20,40})(?=["\'])',  # API Key
        r'(?<=secret_key[:=]["\'])([A-Za-z0-9_-]{20,40})(?=["\'])',  # Secret Key
        r'(?<=jwt[:=]["\'])([A-Za-z0-9_-]{100,200})(?=["\'])',  # JWT Tokens (JSON Web Tokens)
        r'(?<=x-api-key[:=]["\'])([A-Za-z0-9_-]{20,40})(?=["\'])',  # x-api-key
        r'(?<=private_key[:=]["\'])([A-Za-z0-9_-]{64})',  # Private Key (General for NFT wallets)
        r'(?<=wallet_address[:=]["\'])(0x[a-fA-F0-9]{40})',  # Ethereum-style wallet address
        r'(?<=smart_contract_address[:=]["\'])(0x[a-fA-F0-9]{40})',  # Smart contract address
        r'(?<=creator_wallet[:=]["\'])(0x[a-fA-F0-9]{40})',  # Creator Wallet Address
        r'(?<=transaction_hash[:=]["\'])(0x[a-fA-F0-9]{64})',  # Transaction Hash (Ethereum format)
        r'(?<=nft_id[:=]["\'])([A-Za-z0-9_-]+)',  # NFT ID
        r'(?<=nft_metadata[:=]["\'])([\w\-_]+)',  # Metadata related to NFTs
        r'(?<=user_wallet[:=]["\'])(0x[a-fA-F0-9]{40})',  # User Wallet Address
        r'(?<=purchase_price[:=]["\'])([\d\.]+)',  # Purchase price in NFT transactions
        r'(?<=minting_fee[:=]["\'])([\d\.]+)',  # Minting fee
        r'(?<=minting_date[:=]["\'])(\d{4}-\d{2}-\d{2})',  # Minting Date
        r'(?<=transaction_signature[:=]["\'])([A-Za-z0-9_-]+)',  # Transaction signature
        r'(?<=royalty[:=]["\'])([\d\.]+)',  # Royalty fee on NFT sales
        r'(?<=transaction_token[:=]["\'])([A-Za-z0-9_-]+)',  # Transaction Token ID
    ]
    
    tokens_found = {}
    
    for pattern in token_patterns:
        matches = re.findall(pattern, html)
        if matches:
            tokens_found[pattern] = matches
    
    return tokens_found

def selenium_fetch(url):
    """Use Selenium to fetch and interact with dynamically loaded content."""
    options = Options()
    options.add_argument('--headless')
    driver = webdriver.Firefox(options=options)
    try:
        driver.get(url)
        html = driver.page_source
        return html
    except Exception as e:
        print(f"[!] Selenium error: {e}")
        return None
    finally:
        driver.quit()

def main():
    if len(sys.argv) < 2:
        print("Usage: ./NFTGuard.py <URL> [--use-selenium]")
        sys.exit(1)

    url = sys.argv[1]
    use_selenium = '--use-selenium' in sys.argv

    print("\n[+] Starting NFTGuard OSINT Tool")
    print(f"[+] Target: {url}")

    if use_selenium:
        print("[*] Using Selenium for dynamic content...")
        html = selenium_fetch(url)
        headers = {}
    else:
        print("[*] Using Requests for static content...")
        html, headers = fetch_url(url)

    if not html:
        print("[!] Failed to retrieve content. Exiting.")
        sys.exit(1)

    # Metadata Extraction
    metadata = extract_metadata(html)
    print("\n[+] Extracted Metadata:")
    for name, content in metadata.items():
        print(f"    {name}: {content}")

    # Sensitive Keyword Finder (Customized for NFTs)
    sensitive_data = find_sensitive_keywords(html)
    print("\n[+] Found Sensitive Data:")
    if sensitive_data:
        for key, values in sensitive_data.items():
            print(f"    {key}: {', '.join(values)}")
    else:
        print("    No sensitive data found.")

    # Deep Token Scan
    print("\n[+] Scanning for Leaked Tokens and API Keys:")
    tokens = deep_scan_for_tokens(html)
    if tokens:
        for pattern, matches in tokens.items():
            print(f"    Found {len(matches)} potential token(s):")
            for match in matches:
                print(f"      - {match}")
    else:
        print("    No exposed tokens found.")

    # Open Redirects
    redirects = find_open_redirects(html, url)
    print("\n[+] Open Redirects:")
    if redirects:
        for redirect in redirects:
            print(f"    {redirect}")
    else:
        print("    No open redirects found.")

    # JavaScript Analysis
    js_apis = analyze_javascript(html)
    print("\n[+] JavaScript Analysis:")
    if js_apis:
        for api in js_apis:
            print(f"    {api[:100]}...")
    else:
        print("    No suspicious JavaScript patterns found.")

    # Headers Analysis
    if headers:
        print("\n[+] HTTP Headers:")
        for header, value in headers.items():
            print(f"    {header}: {value}")

if __name__ == "__main__":
    main()
