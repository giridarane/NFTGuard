# NFTGuard

NFTGuard is an open-source OSINT tool for analyzing NFT-related websites for sensitive information leaks, such as API keys, wallet addresses, private keys, and transaction metadata.

## Features

- Extract metadata and headers.
- Detect sensitive keywords related to NFTs.
- Scan for leaked API keys, tokens, and secrets.
- Identify potential open redirects.
- Analyze JavaScript for suspicious patterns.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/NFTGuard.git
   cd NFTGuard
   pip install -r requirements.txt
   ```
   Usage
      ```bash
    python NFTGuard.py <URL> [--use-selenium]
    ```
Example

python NFTGuard.py https://example-nft-site.com --use-selenium


