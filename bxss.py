#!/usr/bin/env python3
import os
import time
import sys
import argparse
import urllib3
from urllib.parse import urlsplit, parse_qs, urlencode, urlunsplit
from colorama import Fore, Style
import requests
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def print_bordered_line(url_index, total_urls, url):
    """Print the scanning URL with progress."""
    print(Fore.YELLOW + f"\n→ Scanning URL {url_index}/{total_urls}: {url}" + Fore.RESET)
    print("")

def generate_payload_urls(url, payload):
    """Generate URLs with injected payloads."""
    url_combinations = []
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    if not scheme:
        scheme = 'http'
    query_params = parse_qs(query_string, keep_blank_values=True)
    for key in query_params.keys():
        modified_params = query_params.copy()
        modified_params[key] = [payload]
        modified_query_string = urlencode(modified_params, doseq=True)
        modified_url = urlunsplit((scheme, netloc, path, modified_query_string, fragment))
        url_combinations.append(modified_url)
    return url_combinations

def check_vulnerability(url, payloads, threads, url_index, total_urls):
    """Check if a URL is vulnerable to XSS sequentially."""
    vulnerable_urls = []
    total_scanned = 0
    start_time = time.time()

    # Print the bordered scanning line
    print_bordered_line(url_index, total_urls, url)

    def scan_payload(payload, payload_index, total_payloads):
        nonlocal total_scanned
        # Print payload progress with colors
        print(
            Fore.GREEN + f"payload {payload_index}/{total_payloads} : " +
            Fore.YELLOW + payload + Fore.RESET
        )
        payload_urls = generate_payload_urls(url, payload)

        for payload_url in payload_urls:
            try:
                response = requests.get(payload_url, timeout=5, verify=False)
                total_scanned += 1
            except requests.RequestException:
                pass

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for i, payload in enumerate(payloads, start=1):
            executor.submit(scan_payload, payload, i, len(payloads))

            # Display progress bar
            elapsed_time = time.time() - start_time
            estimated_total_time = (elapsed_time / max(1, i)) * len(payloads)
            remaining_time = max(0, estimated_total_time - elapsed_time)
            print(Fore.YELLOW + f"urls: {url_index}/{total_urls}  payloads: {i}/{len(payloads)} "
                                  f"estimate time: {time.strftime('%H:%M:%S', time.gmtime(remaining_time))}",
                  end="\r", flush=True)

    print()  # Ensure the next output starts on a new line
    return vulnerable_urls, total_scanned

def load_payloads(payload_file):
    """Load payloads from a file."""
    try:
        with open(payload_file, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(Fore.RED + f"[!] Error loading payloads: {e}")
        sys.exit(1)

def save_results(vulnerable_urls, output_file):
    """Save vulnerable URLs to a file."""
    try:
        with open(output_file, "w") as file:
            for url in vulnerable_urls:
                file.write(url + "\n")
        print(Fore.GREEN + f"[\u2713] Results saved to: {output_file}")
    except Exception as e:
        print(Fore.RED + f"[!] Error saving results: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="XSS Scanner using requests library.")
    parser.add_argument("-f", "--file", help="Path to input file containing URLs.")
    parser.add_argument("-u", "--url", help="Scan a single URL.")
    parser.add_argument("-p", "--payloads", required=True, help="Path to payload file.")
    parser.add_argument("-o", "--output", help="Path to save vulnerable URLs.")
    parser.add_argument("-t", "--threads", type=int, default=4, choices=range(1, 11),
                        help="Number of threads to use (1-10). Default is 4.")
    args = parser.parse_args()

    # Validate input
    if not args.file and not args.url:
        print(Fore.RED + "[!] You must provide either a file of URLs (-f) or a single URL (-u).")
        sys.exit(1)
    if args.file and not os.path.isfile(args.file):
        print(Fore.RED + f"[!] Input file not found: {args.file}")
        sys.exit(1)

    # Load URLs
    if args.file:
        with open(args.file, "r") as file:
            urls = [line.strip() for line in file if line.strip()]
    else:
        urls = [args.url]

    # Load payloads
    payloads = load_payloads(args.payloads)

    # Scan URLs
    all_vulnerable_urls = []
    total_scanned = 0
    start_time = time.time()

    for url_index, url in enumerate(urls, start=1):
        vulnerable_urls, scanned = check_vulnerability(url, payloads, args.threads, url_index, len(urls))
        all_vulnerable_urls.extend(vulnerable_urls)
        total_scanned += scanned

    # Print summary
    print(Fore.YELLOW + "\n\u2192 Scan Complete.")
    print(Fore.GREEN + f"\u2022 Total Vulnerable URLs: {len(all_vulnerable_urls)}")
    print(Fore.GREEN + f"\u2022 Total Scanned URLs: {total_scanned}")
    print(Fore.GREEN + f"\u2022 Time Taken: {int(time.time() - start_time)} seconds")

    # Save results if output file is specified
    if args.output:
        save_results(all_vulnerable_urls, args.output)

if __name__ == "__main__":
    main()
