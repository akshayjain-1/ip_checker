# IP Information Checker

## Description

The IP Information Checker is a Python script designed to retrieve detailed information about IP addresses from various free and reputable sources. The tool supports multiple services including ipinfo.io, ipapi.co, AbuseIPDB, and VirusTotal. It features a menu-driven interface, supports asynchronous API calls.

## Features

- Validate IP address format
- Check IP information using multiple free APIs
- Asynchronous API requests for improved performance
- Logging of errors
- Retry mechanism for failed API calls
- Command-line argument support

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/ip_checker_project.git
   cd ip_checker_project

2. Install the required Python packages:
    ```bash
    pip install -r requirements.txt

3. Set up environment variables for API keys:
    ```bash
    export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
    export VIRUSTOTAL_API_KEY="your_virustotal_api_key"

## Usage

```python ip_checker.py <IP_ADDRESS>```


## Future Work

- Add support for more APIs
- Implement a caching mechanism to reduce API calls
- Ability to export results to CSV
- Ability to provide multiple IP address in a single command