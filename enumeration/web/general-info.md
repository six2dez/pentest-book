# General Info

## Auth headers

```bash
# Basic Auth (B64)
Authorization: Basic AXVubzpwQDU1dzByYM==
# Bearer Token (JWT)
Authorization: Bearer <token>
# API Key
GET /endpoint?api_key=abcdefgh123456789
X-API-Key: abcdefgh123456789
# Digest Auth
Authorization: Digest username=”admin” Realm=”abcxyz” nonce=”474754847743646”, uri=”/uri” response=”7cffhfr54685gnnfgerg8”
# OAuth2.0
Authorization: Bearer hY_9.B5f-4.1BfE
# Hawk Authentication
Authorization: Hawk id="abcxyz123", ts="1592459563", nonce="gWqbkw", mac="vxBCccCutXGV30gwEDKu1NDXSeqwfq7Z0sg/HP1HjOU="
# AWS signature
Authorization: AWS4-HMAC-SHA256 Credential=abc/20200618/us-east-1/execute-api/aws4_
```

## Common checks

```bash
# robots.txt
curl http://example.com/robots.txt
# headers
wget --save-headers http://www.example.com/
    # Strict-Transport-Security (HSTS)
    # X-Frame-Options: SAMEORIGIN
    # X-XSS-Protection: 1; mode=block
    # X-Content-Type-Options: nosniff
# Cookies
    # Check Secure and HttpOnly flag in session cookie
    # If exists BIG-IP cookie, app behind a load balancer
# SSL Ciphers
nmap --script ssl-enum-ciphers -p 443 www.example.com
# HTTP Methods
nmap -p 443 --script http-methods www.example.com
# Cross Domain Policy
curl http://example.com/crossdomain.xml
    # allow-access-from domain="*"

# Cookies explained
https://cookiepedia.co.uk/
```

## Security headers explanation

![](<../../.gitbook/assets/image (11).png>)
