from argparse import ArgumentParser
import json
from tenacity import *
import asyncio
import aiohttp
import ipaddress
import logging
import os
import sys
import time


# Configure logging
logging.basicConfig(filename='ip_checker.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

API_TIMEOUT = 10  # seconds

def display_menu():
    print("\n--- IP Information Checker ---")
    print("1. Check IP using ipinfo.io")
    print("2. Check IP using ipapi.co")
    print("3. Check IP using ipstack.com")
    print("4. Check IP using AbuseIPDB")
    print("5. Check IP using VirusTotal")
    print("6. Export results to CSV")
    print("7. Exit")

def enforce_rate_limit():
    time.sleep(5)  # Add 5 seconds delay between requests

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
async def check_ip_ipinfo_async(ip):
    async with aiohttp.ClientSession() as session:
        async with session.get(f"https://ipinfo.io/{ip}/json", timeout=API_TIMEOUT) as response:
            if response.status == 200:
                data = await response.json()
                print("\n--- IP Information from ipinfo.io ---")
                print(json.dumps(data, indent=4))
                return data
            else:
                print(f"Error: {response.status}")

def check_ip_details(choice, ip):
    api_key_ipstack = os.getenv("IPSTACK_API_KEY")
    api_key_abuseipdb = os.getenv("ABUSEIPDB_API_KEY")
    api_key_virustotal = os.getenv("VIRUSTOTAL_API_KEY")

    menu_actions = {
        "1": lambda: asyncio.run(check_ip_ipinfo_async(ip)),
        "2": lambda: asyncio.run(check_ip_ipapi_async(ip)),
        "3": lambda: check_ip_ipstack(ip, api_key_ipstack),
        "4": lambda: check_ip_abuseipdb(ip, api_key_abuseipdb),
        "5": lambda: check_ip_virustotal(ip, api_key_virustotal),
        "6": lambda: export_to_csv(check_ip_ipinfo_async(ip), "results.csv"),
        "7": lambda: sys.exit()
    }

    action = menu_actions.get(choice)
    if action:
        action()
    else:
        print("Invalid option. Please choose again.")

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        print("Invalid IP address format or range. Please try again.")
        return False

def get_cli_arguments():
    parser = ArgumentParser(description="IP Information Checker")
    parser.add_argument("ip", help="IP address to check")
    return parser.parse_args()

def main():
    ip_arg = get_cli_arguments()
    ip_value = ip_arg.ip

    if not validate_ip(ip_value):
        return
    
    while True:
        display_menu()
        option = input("Select a tool (1-7): ")
        enforce_rate_limit()
        check_ip_details(option, ip_value)

if __name__ == "__main__":
    main()