import requests
import dns.resolver
import argparse
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor

# A dictionary mapping provider domains to error signatures that indicate an unclaimed service.
# These values were inspired by resources like https://github.com/EdOverflow/can-i-take-over-xyz
ERROR_SIGNATURES = {
    'elasticbeanstalk.com': 'NXDOMAIN',
    's3.amazonaws.com': 'The specified bucket does not exist',
    'agilecrm.com': 'Sorry, this page is no longer available.',
    'airee.ru': 'Ошибка 402. Сервис Айри.рф не оплачен',
    'animaapp.io': 'The page you were looking for does not exist.',
    'bitbucket.io': 'Repository not found',
    'trydiscourse.com': 'NXDOMAIN',
    'furyns.com': '404: This page could not be found.',
    'ghost.io': 'Site unavailable;Failed to resolve DNS path for this host',
    'hatenablog.com': '404 Blog is not found',
    'helpjuice.com': 'We could not find what youre looking for.',
    'helpscoutdocs.com': 'No settings were found for this company:',
    'helprace.com': 'HTTP_STATUS=301',
    'youtrack.cloud': 'is not a registered InCloud YouTrack',
    'launchrock.com': 'HTTP_STATUS=500',
    'cloudapp.net': 'NXDOMAIN',
    'cloudapp.azure.com': 'NXDOMAIN',
    'azurewebsites.net': 'NXDOMAIN',
    'blob.core.windows.net': 'NXDOMAIN',
    'azure-api.net': 'NXDOMAIN',
    'azurehdinsight.net': 'NXDOMAIN',
    'azureedge.net': 'NXDOMAIN',
    'azurecontainer.io': 'NXDOMAIN',
    'database.windows.net': 'NXDOMAIN',
    'azuredatalakestore.net': 'NXDOMAIN',
    'search.windows.net': 'NXDOMAIN',
    'azurecr.io': 'NXDOMAIN',
    'redis.cache.windows.net': 'NXDOMAIN',
    'servicebus.windows.net': 'NXDOMAIN',
    'visualstudio.com': 'NXDOMAIN',
    'ngrok.io': 'The creators of this project are still working on making everything perfect!',
    's.strikinglydns.com': 'PAGE NOT FOUND.',
    'na-west1.surge.sh': 'project not found',
    'surveysparrow.com': 'Account not found.',
    'read.uberflip.com': 'The URL youve accessed does not provide a hub.',
    'stats.uptimerobot.com': 'page not found',
    'wordpress.com': 'Do you want to register .*.wordpress.com?',
    'worksites.net': 'Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist.'
}

###############################################################################
# Synchronous DNS lookup function (using dnspython)
###############################################################################
def get_cname_record(subdomain):
    """
    Query the DNS for the CNAME record of a given subdomain.
    Returns the canonical name (if found) as a string (without the trailing dot)
    or None if no CNAME record is present or on error.
    """
    try:
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            return str(rdata.target).rstrip('.')
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return None

###############################################################################
# Asynchronous HTTP check using aiohttp
###############################################################################
async def async_check_service_status(subdomain, session):
    """
    Asynchronously sends an HTTP GET request to the subdomain and checks whether
    the response content contains any known error signatures indicating an unclaimed service.
    Returns False if a signature is found (i.e. likely vulnerable), otherwise True.
    """
    url = f'http://{subdomain}'
    try:
        async with session.get(url, timeout=5) as response:
            text = await response.text()
            for provider, signature in ERROR_SIGNATURES.items():
                if provider in subdomain and signature in text:
                    return False  # Service likely unclaimed
            return True  # Service appears active
    except asyncio.TimeoutError:
        return False
    except Exception:
        return False

###############################################################################
# Asynchronous scan function that combines DNS lookup and HTTP check
###############################################################################
async def async_scan_subdomain(subdomain, loop):
    """
    Asynchronously scans a subdomain for potential takeover vulnerability.
    - Uses run_in_executor to call the synchronous DNS lookup (get_cname_record).
    - Uses an aiohttp session to perform an asynchronous HTTP GET request.
    Returns a tuple (subdomain, cname) if a vulnerability is detected; otherwise, None.
    """
    # Run the DNS query in the default executor to avoid blocking the event loop.
    cname = await loop.run_in_executor(None, get_cname_record, subdomain)
    if cname:
        print(f"[INFO] {subdomain} has CNAME: {cname}")
        # Create an aiohttp session for the HTTP request.
        async with aiohttp.ClientSession() as session:
            active = await async_check_service_status(subdomain, session)
            if not active:
                print(f"[ALERT] Potential subdomain takeover vulnerability detected on {subdomain}!")
                return (subdomain, cname)
            else:
                print(f"[INFO] {subdomain} appears active.")
    else:
        print(f"[INFO] {subdomain} has no CNAME record (might be a bare A record).")
    return None

###############################################################################
# Multi-threaded subdomain enumeration using ThreadPoolExecutor
###############################################################################
def check_subdomain_existence(full_domain):
    """
    Synchronously checks if a subdomain exists by sending an HTTP HEAD request.
    Returns the full domain (without the scheme) if the request does not raise a ConnectionError;
    otherwise, returns None.
    """
    url = f"http://{full_domain}"
    try:
        # Using HEAD is faster since it only fetches headers.
        requests.head(url, timeout=5)
        return full_domain
    except requests.ConnectionError:
        return None

def subdomenum(domain, file_name):
    """
    Enumerates subdomains using a brute force wordlist provided in a text file.
    Uses multi-threading (ThreadPoolExecutor) to concurrently test subdomain existence.
    Returns a list of discovered subdomain strings (e.g. 'www.example.com').
    """
    discovered_subdomains = []

    # Read the list of subdomain prefixes from the text file.
    with open(file_name, 'r') as f:
        subdomain_prefixes = f.read().splitlines()

    # Create the list of full domain names (without the http:// prefix)
    full_domains = [f"{sub}.{domain}" for sub in subdomain_prefixes]

    # Use a ThreadPoolExecutor to concurrently check for existence of each subdomain.
    with ThreadPoolExecutor(max_workers=20) as executor:
        # Map the check_subdomain_existence function over the full_domains list.
        results = executor.map(check_subdomain_existence, full_domains)
    
    # Filter out None results and add to discovered_subdomains.
    for res in results:
        if res is not None:
            discovered_subdomains.append(res)
            print(f"[+] Discovered subdomain: {res}")

    return discovered_subdomains

###############################################################################
# Main execution and argument parsing
###############################################################################
def main():
    # Parse command line arguments for the domain and text file.
    parser = argparse.ArgumentParser(
        description="Subdomain Detection Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-d", "--domain", help="Domain name required", required=True)
    parser.add_argument("-t", "--textfile", help="Subdomain brute force text file", required=True)
    args = parser.parse_args()
    domain = args.domain
    textfile = args.textfile
    print(f"Domain: {domain}, Wordlist: {textfile}")

    # Enumerate subdomains using the provided wordlist (using multi-threading)
    discovered_subdomains = subdomenum(domain, textfile)

    # Asynchronously scan each discovered subdomain for takeover vulnerabilities.
    loop = asyncio.get_event_loop()
    # Prepare a list of async scanning tasks.
    tasks = [async_scan_subdomain(sub, loop) for sub in discovered_subdomains]
    # Gather results concurrently.
    vulnerable_results = loop.run_until_complete(asyncio.gather(*tasks))

    # Filter out None results from vulnerable_results.
    vulnerable = [result for result in vulnerable_results if result is not None]
    for sub, cname in vulnerable:
        print(f"[+] Discovered vulnerable subdomain: {sub} (CNAME: {cname})")

    # Write potentially vulnerable subdomains to a file.
    with open("vulnerable_subdomains.txt", "w") as f:
        for item in vulnerable:
            print(item, file=f)

if __name__ == "__main__":
    main()
