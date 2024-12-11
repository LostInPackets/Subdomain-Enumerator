import os
import subprocess
import argparse
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

# Main function
def main():
    parser = argparse.ArgumentParser(description="Enhanced Subdomain Enumerator and Live Host Checker")
    parser.add_argument("-d", "--domain", required=True, help="Target domain to enumerate subdomains")
    parser.add_argument("-o", "--output", help="File to save the results", default="results.txt")
    args = parser.parse_args()

    domain = args.domain
    output_file = args.output

    print(f"{bcolors.OKBLUE}[*]{bcolors.ENDC} Starting subdomain enumeration for: {domain}\n")

    subdomains_list = []

    # Step 1: Subdomain enumeration with subfinder
    print(f"{bcolors.OKCYAN}[1/4]{bcolors.ENDC} Running subfinder...")
    subfinder_command = f"subfinder -d {domain} -silent"
    subfinder_output = run_command(subfinder_command)
    if subfinder_output:
        subdomains_list.extend(subfinder_output.strip().split("\n"))
        print(f"{bcolors.OKGREEN}[+] Subfinder found {len(subfinder_output.strip().split('\n'))} subdomains.{bcolors.ENDC}")
    else:
        print(f"{bcolors.WARNING}[!] Subfinder returned no results.{bcolors.ENDC}")

    # Step 2: Subdomain enumeration with assetfinder
    print(f"{bcolors.OKCYAN}[2/4]{bcolors.ENDC} Running assetfinder...")
    assetfinder_command = f"assetfinder --subs-only {domain}"
    assetfinder_output = run_command(assetfinder_command)
    if assetfinder_output:
        subdomains_list.extend(assetfinder_output.strip().split("\n"))
        print(f"{bcolors.OKGREEN}[+] Assetfinder found {len(assetfinder_output.strip().split('\n'))} subdomains.{bcolors.ENDC}")
    else:
        print(f"{bcolors.WARNING}[!] Assetfinder returned no results.{bcolors.ENDC}")

    # Step 3: Subdomain enumeration with amass
    print(f"{bcolors.OKCYAN}[3/4]{bcolors.ENDC} Running amass...")
    amass_command = f"amass enum -d {domain} -silent"
    amass_output = run_command(amass_command)
    if amass_output:
        subdomains_list.extend(amass_output.strip().split("\n"))
        print(f"{bcolors.OKGREEN}[+] Amass found {len(amass_output.strip().split('\n'))} subdomains.{bcolors.ENDC}")
    else:
        print(f"{bcolors.WARNING}[!] Amass returned no results.{bcolors.ENDC}")

    # Remove duplicates
    subdomains_list = list(set(subdomains_list))

    # Save subdomains to file
    print(f"{bcolors.OKCYAN}[4/4]{bcolors.ENDC} Saving unique subdomains to subdomains.txt...")
    with open("subdomains.txt", "w") as f:
        f.write("\n".join(subdomains_list))
    print(f"{bcolors.OKGREEN}[+] Total unique subdomains: {len(subdomains_list)}.{bcolors.ENDC}\n")

    # Step 4: Check live hosts with httpx
    print(f"{bcolors.OKCYAN}[5/5]{bcolors.ENDC} Checking for live hosts with httpx...")
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
