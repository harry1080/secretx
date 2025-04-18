#!/usr/bin/env python3

import requests
import re
import argparse
import random
import json
import sys
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Define colors for output
colors = ["red", "green", "yellow", "blue", "magenta", "cyan", "white"]

# Load patterns from JSON file
try:
    with open("patterns.json", "r") as f:
        patterns = json.load(f)
except FileNotFoundError:
    print("Error: patterns.json file not found.")
    sys.exit(1)
except json.JSONDecodeError as e:
    print(f"Error parsing patterns.json: {e}")
    sys.exit(1)

# Convert patterns to list of tuples
patterns = list(patterns.items())

already_found = set()

# Set up argument parser
ap = argparse.ArgumentParser(description='Secret Finder Tool')
ap.add_argument("--list", required=True, help="File containing list of URLs")
ap.add_argument("--threads", required=False, type=int, default=10, help="Number of threads (default: 10)")
ap.add_argument("--colorless", required=False, action='store_true', help="Disable colored output")
ap.add_argument("--output", required=False, help="Output file to write results")
args = ap.parse_args()

# Create thread pool
thread_pool = ThreadPoolExecutor(max_workers=args.threads)

def print_banner():
    banner = r"""
                                                     /$$             
                                                    | $$             
  /$$$$$$$  /$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$  /$$$$$$  /$$   /$$
 /$$_____/ /$$__  $$ /$$_____/ /$$__  $$ /$$__  $$|_  $$_/ |  $$ /$$/
|  $$$$$$ | $$$$$$$$| $$      | $$  \__/| $$$$$$$$  | $$    \  $$$$/ 
 \____  $$| $$_____/| $$      | $$      | $$_____/  | $$ /$$ >$$  $$ 
 /$$$$$$$/|  $$$$$$$|  $$$$$$$| $$      |  $$$$$$$  |  $$$$//$$/\  $$
|_______/  \_______/ \_______/|__/       \_______/   \___/ |__/  \__/ 

"""
    print(banner)

def mask_data(data, visible_chars=4):
    return '*' * (len(data) - visible_chars) + data[-visible_chars:]

def print_result(name, key, url):
    if key not in already_found:
        # Mask sensitive data if necessary
        masked_key = key
        if name in ["credit_card_number", "ssn", "bank_account_number"]:
            masked_key = mask_data(key)

        message = f"[+] Type: {name}, Data: {masked_key}, URL: {url}"
        if args.colorless:
            print(message)
        else:
            color = random.choice(colors)
            print(colored(message, color))

        # Write to output file if specified
        if args.output:
            with open(args.output, "a") as outfile:
                outfile.write(f"Type: {name}, Data: {masked_key}, URL: {url}\n")

        already_found.add(key)

def luhn_check(card_number):
    digits = [int(d) for d in card_number if d.isdigit()]
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 0:
            checksum += d
        else:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
    return checksum % 10 == 0

def extract_secrets(url):
    req_headers = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; SecretFinder/1.0; +https://github.com/xyele)"
        )
    }
    try:
        response = requests.get(
            url.strip(),
            verify=False,
            allow_redirects=True,
            headers=req_headers,
            timeout=10
        )

        if response.status_code in [200, 301, 302, 307, 308]:
            content = response.text
            for name, pattern in patterns:
                try:
                    regex_pattern = re.compile(pattern, re.MULTILINE)
                    matches = regex_pattern.findall(content)
                    for match in matches:
                        if isinstance(match, tuple):
                            key_value = match[0]
                        else:
                            key_value = match.strip()

                        # Check context around the match
                        start = max(0, content.find(key_value) - 10)
                        end = min(len(content), start + len(key_value) + 20)
                        context = content[start:end]

                        if any(char in context for char in [';', '{', '}', '=', '(', ')', '"', "'"]):
                            continue  # Skip minified code matches

                        # Validation logic
                        report = True
                        if name == "credit_card_number":
                            card_number = key_value.replace(' ', '').replace('-', '')
                            if not luhn_check(card_number):
                                report = False
                        elif name == "aws_secret_access_key":
                            if not key_value[0].isalpha():  # AWS keys start with a letter
                                report = False

                        if report:
                            print_result(name, key_value, url)
                except re.error as e:
                    print(f"Invalid regex pattern '{pattern}' for '{name}': {e}")
    except Exception as e:
        print(f"Error processing {url}: {e}")

def main():
    print_banner()
    try:
        with open(args.list, "r") as f:
            url_list = [line.strip() for line in f if line.strip()]
        if not url_list:
            print("No URLs found in the list.")
            sys.exit(1)

        futures = {thread_pool.submit(extract_secrets, url): url for url in url_list}

        for future in as_completed(futures):
            _ = future.result()  # We don't need the result here
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received. Shutting down...")
        thread_pool.shutdown(wait=False)
        sys.exit(0)
    except Exception as e:
        print(f"[!] An error occurred: {e}")
        sys.exit(1)
    finally:
        thread_pool.shutdown(wait=False)

if __name__ == "__main__":
    main()
