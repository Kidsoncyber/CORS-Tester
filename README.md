# CORS Misconfiguration Tester

A Python tool to test for CORS (Cross-Origin Resource Sharing) misconfigurations.

## Features

- Tests multiple CORS misconfiguration scenarios
- Supports pre-flight (OPTIONS) and actual request testing
- Custom origins and methods testing
- Credentials support check
- Multiple URL testing from file

## Installation

```bash
git clone https://github.com/kidsoncyber/security-tools.git
cd security-tools
pip install -r requirements.txt

## Usage

# Test single URL
python cors_tester.py -u https://api.example.com/data

# Test multiple URLs from file
python cors_tester.py -f urls.txt

# Test with custom origins
python cors_tester.py -u https://api.example.com -o "https://attacker.com" -o "null"

# Test with credentials check
python cors_tester.py -u https://api.example.com -c

# Disable SSL verification
python cors_tester.py -u https://api.example.com --insecure

# Add custom headers
python cors_tester.py -u https://api.example.com -H "Authorization: Bearer token123"

## Test Cases Detected

- Wildcard (*) Access-Control-Allow-Origin
- Reflected Origin in ACAO
- Partial Origin reflection in ACAO
- Access-Control-Allow-Credentials: true with reflected ACAO
- Missing pre-flight but CORS headers in GET requests
