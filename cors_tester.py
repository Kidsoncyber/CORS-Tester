#!/usr/bin/env python3
"""
CORS Misconfiguration Tester
Author: [Your Name]
"""

import requests
import argparse
from urllib.parse import urlparse

def print_banner():
    print("""
   _____ ____  _____ _____   _____           _     _____         _             
  / ____/ __ \|  __ \_   _| |  __ \         | |   |_   _|       | |            
 | |   | |  | | |__) || |   | |__) |__  _ __| |_    | | ___  ___| |_ ___  _ __ 
 | |   | |  | |  _  / | |   |  ___/ _ \| '__| __|   | |/ _ \/ __| __/ _ \| '__|
 | |___| |__| | | \ \_| |_  | |  | (_) | |  | |_   _| |  __/\__ \ || (_) | |   
  \_____\____/|_|  \_\_____| |_|   \___/|_|   \__| |_____\___||___/\__\___/|_|   
  
  A comprehensive CORS misconfiguration tester
  """)

def test_cors(url, headers=None, insecure=False, origins=None, methods=None, credentials=False):
    try:
        # Parse the URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Default test origins if not provided
        test_origins = origins or [
            "https://evil.com",
            "http://evil.com",
            "null",
            f"https://{domain}",
            f"http://{domain}",
            "https://subdomain.evil.com",
            "https://" + domain.replace(".", "-") + ".evil.com"
        ]
        
        # Default test methods if not provided
        test_methods = methods or ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
        
        # Prepare headers
        request_headers = headers.copy() if headers else {}
        
        # Test each origin
        for origin in test_origins:
            request_headers['Origin'] = origin
            
            # Test OPTIONS first (pre-flight)
            options_headers = {
                'Access-Control-Request-Method': 'GET',
                'Access-Control-Request-Headers': 'X-Requested-With'
            }
            options_headers.update(request_headers)
            
            verify = not insecure
            response = requests.options(
                url,
                headers=options_headers,
                verify=verify
            )
            
            # Check CORS headers in response
            cors_headers = {
                'ACAO': response.headers.get('Access-Control-Allow-Origin'),
                'ACAC': response.headers.get('Access-Control-Allow-Credentials'),
                'ACAM': response.headers.get('Access-Control-Allow-Methods'),
                'ACAH': response.headers.get('Access-Control-Allow-Headers')
            }
            
            # Now test with GET
            get_response = requests.get(
                url,
                headers=request_headers,
                verify=verify
            )
            
            # Analyze results
            vulnerabilities = analyze_cors_response(
                origin, 
                response, 
                get_response, 
                credentials
            )
            
            if vulnerabilities:
                print(f"\n[+] Potential CORS Misconfiguration for {url} with Origin: {origin}")
                for vuln in vulnerabilities:
                    print(f"    - {vuln}")
                print_headers(cors_headers)
            else:
                print(f"[-] No CORS issues detected for {url} with Origin: {origin}")
                
    except Exception as e:
        print(f"[!] Error testing {url}: {str(e)}")

def analyze_cors_response(origin, options_response, get_response, check_credentials):
    vulnerabilities = []
    
    # Check Access-Control-Allow-Origin
    acao = options_response.headers.get('Access-Control-Allow-Origin')
    if acao:
        if acao == '*':
            if check_credentials:
                acac = options_response.headers.get('Access-Control-Allow-Credentials')
                if acac and acac.lower() == 'true':
                    vulnerabilities.append("Wildcard (*) ACAO with ACAC true - dangerous!")
                else:
                    vulnerabilities.append("Wildcard (*) ACAO - potentially unsafe")
            else:
                vulnerabilities.append("Wildcard (*) ACAO - potentially unsafe")
        elif acao == origin:
            vulnerabilities.append("Reflects Origin exactly - potentially unsafe")
        elif origin in acao:
            vulnerabilities.append(f"Origin {origin} partially reflected in ACAO - potentially unsafe")
    
    # Check Access-Control-Allow-Credentials
    acac = options_response.headers.get('Access-Control-Allow-Credentials')
    if acac and acac.lower() == 'true':
        vulnerabilities.append("ACAC set to true - sensitive with reflected ACAO")
    
    # Check if headers are reflected in GET response but not in OPTIONS
    get_acao = get_response.headers.get('Access-Control-Allow-Origin')
    if get_acao and not acao:
        vulnerabilities.append("CORS headers in GET but not OPTIONS - potential cache poisoning")
    
    return vulnerabilities

def print_headers(headers):
    print("\n    CORS Headers Found:")
    for key, value in headers.items():
        if value:
            print(f"    {key}: {value}")

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="CORS Misconfiguration Tester")
    parser.add_argument("-u", "--url", help="Target URL (e.g., https://example.com)")
    parser.add_argument("-f", "--file", help="File containing list of URLs")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL verification")
    parser.add_argument("-H", "--header", action="append", help="Additional headers (e.g., -H 'Cookie: abc=123')")
    parser.add_argument("-o", "--origin", action="append", help="Custom origins to test")
    parser.add_argument("-m", "--method", action="append", help="Custom methods to test")
    parser.add_argument("-c", "--credentials", action="store_true", help="Check for credentials support")
    
    args = parser.parse_args()
    
    if not args.url and not args.file:
        parser.print_help()
        return
    
    # Process headers
    headers = {}
    if args.header:
        for header in args.header:
            key, value = header.split(":", 1)
            headers[key.strip()] = value.strip()
    
    # Test single URL
    if args.url:
        test_cors(
            args.url, 
            headers, 
            args.insecure, 
            args.origin, 
            args.method,
            args.credentials
        )
    
    # Test multiple URLs from file
    if args.file:
        with open(args.file) as f:
            urls = [line.strip() for line in f if line.strip()]
        
        for url in urls:
            test_cors(
                url, 
                headers, 
                args.insecure, 
                args.origin, 
                args.method,
                args.credentials
            )

if __name__ == "__main__":
    main()
