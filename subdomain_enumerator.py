import os
import subprocess
import argparse
import re
from datetime import datetime

# Colors for output
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

# Function to run shell commands and capture output
def run_command(command):
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"{bcolors.FAIL}[ERROR]{bcolors.ENDC} Command failed: {e.cmd}\n{e.stderr}")
        return None

# Function to extract pure subdomains
def extract_subdomains(output):
    if not output:
        return []
    return list(set(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", output)))

# Main function
def main():
    parser = argparse.ArgumentParser(description="Advanced Subdomain Enumerator and Live Host Checker")
    parser.add_argument("-d", "--domain", required=True, help="Target domain to enumerate subdomains")
    parser.add_argument("-o", "--output", help="File to save the results", default="results.txt")
    args = parser.parse_args()

    domain = args.domain
    output_file = args.output

    print(f"{bcolors.OKBLUE}[*]{bcolors.ENDC} Starting subdomain enumeration for: {domain}\n")

    subdomains_list = []

    # Step 1: Subdomain enumeration with Subfinder
    print(f"{bcolors.OKCYAN}[1/5]{bcolors.ENDC} Running Subfinder...")
    subfinder_command = f"subfinder -d {domain} -silent"
    subfinder_output = run_command(subfinder_command)
    if subfinder_output:
        subdomains = extract_subdomains(subfinder_output)
        subdomains_list.extend(subdomains)
        print(f"{bcolors.OKGREEN}[+] Subfinder found {len(subdomains)} subdomains.{bcolors.ENDC}")
    else:
        print(f"{bcolors.WARNING}[!] Subfinder returned no results.{bcolors.ENDC}")

    # Step 2: Subdomain enumeration with Assetfinder
    print(f"{bcolors.OKCYAN}[2/5]{bcolors.ENDC} Running Assetfinder...")
    assetfinder_command = f"assetfinder --subs-only {domain}"
    assetfinder_output = run_command(assetfinder_command)
    if assetfinder_output:
        subdomains = extract_subdomains(assetfinder_output)
        subdomains_list.extend(subdomains)
        print(f"{bcolors.OKGREEN}[+] Assetfinder found {len(subdomains)} subdomains.{bcolors.ENDC}")
    else:
        print(f"{bcolors.WARNING}[!] Assetfinder returned no results.{bcolors.ENDC}")

    # Step 3: Subdomain enumeration with Findomain
    print(f"{bcolors.OKCYAN}[3/5]{bcolors.ENDC} Running Findomain...")
    findomain_command = f"findomain -t {domain} -q"
    findomain_output = run_command(findomain_command)
    if findomain_output:
        subdomains = extract_subdomains(findomain_output)
        subdomains_list.extend(subdomains)
        print(f"{bcolors.OKGREEN}[+] Findomain found {len(subdomains)} subdomains.{bcolors.ENDC}")
    else:
        print(f"{bcolors.WARNING}[!] Findomain returned no results.{bcolors.ENDC}")

    # Step 4: Subdomain enumeration with crt.sh (using curl)
    print(f"{bcolors.OKCYAN}[4/5]{bcolors.ENDC} Searching crt.sh...")
    crtsh_command = f"curl -s 'https://crt.sh/?q=%25.{domain}&output=json' | jq -r '.[].name_value' | sed 's/\\*\\.//g'"
    crtsh_output = run_command(crtsh_command)
    if crtsh_output:
        subdomains = extract_subdomains(crtsh_output)
        subdomains_list.extend(subdomains)
        print(f"{bcolors.OKGREEN}[+] crt.sh found {len(subdomains)} subdomains.{bcolors.ENDC}")
    else:
        print(f"{bcolors.WARNING}[!] crt.sh returned no results.{bcolors.ENDC}")

    # Step 5: Subdomain brute-forcing with dnsx
    print(f"{bcolors.OKCYAN}[5/5]{bcolors.ENDC} Running dnsx brute-forcing...")
    dnsx_command = f"dnsx -silent -d {domain} -w subdomains-top1million-20000.txt"
    dnsx_output = run_command(dnsx_command)
    if dnsx_output:
        subdomains = extract_subdomains(dnsx_output)
        subdomains_list.extend(subdomains)
        print(f"{bcolors.OKGREEN}[+] dnsx brute-forcing found {len(subdomains)} subdomains.{bcolors.ENDC}")
    else:
        print(f"{bcolors.WARNING}[!] dnsx returned no results.{bcolors.ENDC}")

    # Remove duplicates
    subdomains_list = list(set(subdomains_list))

    # Save subdomains to file
    print(f"{bcolors.OKCYAN}[6/6]{bcolors.ENDC} Saving unique subdomains to subdomains.txt...")
    with open("subdomains.txt", "w") as f:
        f.write("\n".join(subdomains_list))
    print(f"{bcolors.OKGREEN}[+] Total unique subdomains: {len(subdomains_list)}.{bcolors.ENDC}\n")

    # Step 6: Check live hosts with httpx
    print(f"{bcolors.OKCYAN}[7/7]{bcolors.ENDC} Checking for live hosts with httpx...")
    httpx_command = "httpx -l subdomains.txt -silent"
    live_hosts = run_command(httpx_command)

    if live_hosts:
        live_hosts_list = live_hosts.strip().split("\n")
        print(f"{bcolors.OKGREEN}[+] Found {len(live_hosts_list)} live hosts.{bcolors.ENDC}\n")

        # Save live hosts to the output file
        with open(output_file, "w") as f:
            f.write("\n".join(live_hosts_list))
        print(f"{bcolors.OKBLUE}[*]{bcolors.ENDC} Results saved to {output_file}")
    else:
        print(f"{bcolors.WARNING}[!] No live hosts found.{bcolors.ENDC}")

    print(f"{bcolors.OKGREEN}[DONE]{bcolors.ENDC} Enumeration completed successfully!\n")

if __name__ == "__main__":
    main()
