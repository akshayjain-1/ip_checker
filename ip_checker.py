from argparse import ArgumentParser
import json
import requests
from tenacity import *
import asyncio
import aiohttp
import ipaddress
import logging
import os
import sys
import time


# Configure logging
logging.basicConfig(filename='ip_checker.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

API_TIMEOUT = 10  # seconds

def display_menu():
    print("\n--- IP Information Checker ---")
    print("1. Check IP using ipinfo.io")
    print("2. Check IP using ipapi.co")
    print("3. Check IP using AbuseIPDB")
    print("4. Check IP using VirusTotal")
    print("5. Exit")

def enforce_rate_limit():
    time.sleep(5)  # Add 5 seconds delay between requests

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
async def check_ip_ipinfo(ip):
    async with aiohttp.ClientSession() as session:
        async with session.get(f"https://ipinfo.io/{ip}/json", timeout=API_TIMEOUT) as response:
            if response.status == 200:
                data = await response.json()
                print("\n--- IP Information from ipinfo.io ---")
                print(json.dumps(data, indent=4))
                return data
            else:
                logging.error(f"Failed to retrieve IP information from ipinfo.io for IP {ip}. Status code: {response.status}")
                print(f"Error: {response.status}")

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
async def check_ip_ipapi(ip):
    async with aiohttp.ClientSession() as session:
        async with session.get(f"https://ipapi.co/{ip}/json", timeout=API_TIMEOUT) as response:
            if response.status == 200:
                data = await response.json()
                print("\n--- IP Information from ipapi.co ---")
                print(json.dumps(data, indent=4))
                return data
            else:
                logging.error(f"Failed to retrieve IP information from ipinfo.io for IP {ip}. Status code: {response.status}")
                print(f"Error: {response.status}")

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def check_ip_abuseipdb(ip, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {"ipAddress": ip, "maxAgeInDays": "90"}
    headers = {"Accept": "application/json", "Key": api_key}
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=API_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        print("\n--- IP Information from AbuseIPDB ---")
        print(json.dumps(data, indent=4))
        return data
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during API call to AbuseIPDB: {e}")
        print(f"Error retrieving data from AbuseIPDB: {e}")

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def check_ip_virustotal(ip, api_key):
    url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
    params = {'apikey': api_key, 'ip': ip}
    try:
        response = requests.get(url, params=params, timeout=API_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        print("\n--- IP Information from VirusTotal ---")
        print(json.dumps(data, indent=4))
        return data
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during API call to VirusTotal: {e}")
        print(f"Error retrieving data from VirusTotal: {e}")

def check_ip_details(choice, ip):
    api_key_abuseipdb = os.getenv("ABUSEIPDB_API_KEY")
    api_key_virustotal = os.getenv("VIRUSTOTAL_API_KEY")

    menu_actions = {
        "1": lambda: asyncio.run(check_ip_ipinfo(ip)),
        "2": lambda: asyncio.run(check_ip_ipapi(ip)),
        "3": lambda: check_ip_abuseipdb(ip, api_key_abuseipdb),
        "4": lambda: check_ip_virustotal(ip, api_key_virustotal),
        "5": lambda: sys.exit()
    }

    action = menu_actions.get(choice)
    if action:
        action()
    else:
        logging.error(f"Invalid option {choice} selected for IP {ip}")
        print("Invalid option. Please choose again.")

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        logging.error(f"Invalid IP address format or range: {ip}")
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
        option = input("Select a tool (1-5): ")
        enforce_rate_limit()
        check_ip_details(option, ip_value)

if __name__ == "__main__":
    main()