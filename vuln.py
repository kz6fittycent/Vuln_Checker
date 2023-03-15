import apt
import requests
from termcolor import colored
import time

def get_installed_packages():
    cache = apt.Cache()
    cache.open()
    packages = {}
    for package in cache:
        if package.is_installed:
            packages[package.name] = package.versions[0].version
    return packages

def get_vulnerability_details(package_name, package_version):
    url = f"https://vuldb.com/?api"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "apiKey": "demo",
        "search": f"ubuntu {package_name} {package_version}"
    }
    while True:
        response = requests.post(url, headers=headers, data=data)
        if response.status_code == 200:
            json_data = response.json()
            if "result" in json_data:
                return json_data["result"]
            else:
                print(colored(f"No results found for {package_name} {package_version}", 'yellow'))
                return None
        elif response.status_code == 429:
            retry_after = int(response.headers["Retry-After"])
            print(f"Rate limit exceeded. Retrying in {retry_after} seconds.", end="", flush=True)
            for i in range(retry_after, 0, -1):
                print(f"\r{colored(f'Retrying in {i} seconds...', 'yellow')}", end="", flush=True)
                time.sleep(1)
            print("\rRetrying...", end="", flush=True)
        else:
            print(f"Failed to retrieve details for {package_name} {package_version}. Status code: {response.status_code}")
            return None

def main():
    packages = get_installed_packages()
    for package_name, package_version in packages.items():
        vulnerabilities = get_vulnerability_details(package_name, package_version)
        if vulnerabilities:
            print(colored(f"Vulnerabilities for {package_name} {package_version}:", 'red'))
            for vulnerability in vulnerabilities:
                print(vulnerability["title"])
            print("")
        else:
            print(colored(f"No vulnerabilities found for {package_name} {package_version}", 'green'))

if __name__ == "__main__":
    main()

# Final report
print("="*50)
print("Vulnerability Report")
print("="*50)

if len(vulnerable_hosts) == 0:
    print("No vulnerabilities found.")
else:
    print(f"{len(vulnerable_hosts)} hosts found with vulnerabilities:")
    for host, vulns in vulnerable_hosts.items():
        print(f"- Host {host} is vulnerable to the following exploits:")
        for vuln in vulns:
            print(f"\t- {vuln}")

print("="*50)
