# Subdomain Takeover

## What Is Subdomain Takeover?

Subdomain takeover is a misconfiguration vulnerability that occurs when a subdomain’s DNS record points to an external service (such as a cloud provider or hosting platform) that has been decommissioned or is no longer under the organization’s control. In this scenario, an attacker can reclaim the unassigned service and “take over” the subdomain. Once taken over, the attacker might host malicious content, intercept traffic, or use the subdomain for phishing and other malicious activities. 

---

## Research Overview and My Approach

### Background

Many organizations accumulate subdomains under a primary domain, and over time some of these subdomains become unregistered or forgotten. Hackers can exploit this oversight by taking over these “dangling” subdomains to steal data or perform further malicious activities.

### Identification Process

There are two main approaches that I have identified so far:

- **Community-Based Approach:**  
  Websites and GitHub projects (e.g., [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)) list vulnerable services and subdomains along with discussions on exploitation techniques and timely reporting.

- **Hands-On Approach:**  
  You can manually check for vulnerable subdomains—using a registrar like Namecheap—to see if a particular subdomain is available for registration. If it is, that subdomain might be susceptible to takeover.

---

## Algorithm and Tool Overview

My tool automates the detection of subdomain takeover vulnerabilities using the following steps:

1. **Subdomain Enumeration:**  
   - Uses a brute-force wordlist (sourced from [dnscan](https://github.com/rbsec/dnscan/blob/master/subdomains-100.txt)) and external APIs to discover subdomains.  
   - Leverages multi-threading to efficiently test a large number of subdomains.

2. **DNS Record Querying:**  
   - Uses dnspython to retrieve the CNAME records for each subdomain.  
   - Identifies if a subdomain points to a third-party service.

3. **Service Validation:**  
   - Sends asynchronous HTTP requests (using aiohttp) to check if the service returns error messages (e.g., “The specified bucket does not exist” for AWS S3) that indicate the resource is unclaimed.  
   - Uses asynchronous concurrency to scan many subdomains quickly.

4. **Reporting:**  
   - Logs vulnerable subdomains and writes them to a file for further review and responsible disclosure.

---

## How to Use This Tool

### Prerequisites

- **Python 3** must be installed on your system.
- Install the required Python packages:

  ```bash
  pip install requests dnspython aiohttp
---

## Setup
- The word list `subdomain-100.txt` contains the list of subdomain used to brute force
- Clone this repository to your local machine and navigate to the project directory.

## Execution
Run the tool with the following command:
```bash 
python subdomain_scanner.py -d example.com -t subdomains.txt
```
- -d / --domain: The primary domain you wish to scan (e.g., example.com).
- -t / --textfile: The text file containing your subdomain prefixes.

---

## References:
1.	https://github.com/EdOverflow/can-i-take-over-xyz
2.	https://labs.detectify.com/writeups/hostile-subdomain-takeover-using-heroku-github-desk-more/
3.	https://0xpatrik.com/subdomain-takeover-ns/
4.	https://github.com/EdOverflow/can-i-take-over-xyz/issues/26
5.	https://thepythoncode.com/article/make-subdomain-scanner-python
6.  https://github.com/rbsec/dnscan/blob/master/subdomains-100.txt

