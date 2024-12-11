# Subdomain-Enumerator

## Overview

Subdomain Enumerator is a Python-based tool designed to streamline the process of enumerating subdomains and identifying live hosts. It integrates multiple tools for robust subdomain discovery and utilizes httpx for checking the reachability of the discovered subdomains.

Features

Enumerates subdomains using:

subfinder

assetfinder

amass

Removes duplicate results automatically.

Checks live hosts using httpx.

Saves results to separate files for subdomains and live hosts.

Provides clear and colored output for better readability.

## Requirements

The following tools must be installed on your system and accessible in the PATH:

subfinder

assetfinder

amass

httpx

Additionally, ensure Python 3 is installed on your system.

## Installation

### Clone this repository:

git clone https://github.com/your-username/subdomain-enumerator.git
cd subdomain-enumerator

Install the required Python dependencies (if any):

pip install -r requirements.txt

## Usage

Run the script with the following options:

python subdomain_enumerator.py -d <domain> [-o <output_file>]

## Arguments

-d or --domain (required): The target domain to enumerate subdomains.

-o or --output (optional): The file to save live hosts (default: results.txt).

## Example

python subdomain_enumerator.py -d example.com -o live_hosts.txt

## Output

subdomains.txt: Contains all unique subdomains discovered.

results.txt (or specified file): Contains the live hosts identified.


Happy hacking!
