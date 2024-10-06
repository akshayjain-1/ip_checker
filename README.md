# IP Information Checker

A command-line interface (CLI) tool to retrieve IP information from various APIs, including ipinfo.io, ipapi.co, AbuseIPDB, and VirusTotal.

## Table of Contents

* [Description](#description)
* [Features](#features)
* [Installation](#installation)
* [Usage](#usage)
* [Future Work](#future-work)

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

1. Install Poetry: 
    ```bash 
    pip install poetry
2. Clone the repository:
   ```bash
   git clone https://github.com/akshayjain-1/ip_checker.git

3. Navigate to the project directory:
    ```bash
    cd ip_checker

4. Install dependencies:
    ```bash
    poetry install

5. Set up environment variables for API keys:
    ```bash
    export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
    export VIRUSTOTAL_API_KEY="your_virustotal_api_key"

## Usage

```poetry run python ip_checker.py <IP_ADDRESS>```


## Future Work

- Add support for more APIs
- Implement a caching mechanism to reduce API calls
- Ability to export results to CSV
- Ability to provide multiple IP address in a single command