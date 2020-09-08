# SSL/TLS

## DROWN

```bash
# Check for "SSLv2 supported"
nmap –p- –sV –sC example.com
```

## TLS\_FALLBACK\_SCSV

```bash
# Check in the lower port
openssl s_client –tls1 -fallback_scsv -connect example.com:443
# - Response:
# tlsv1 alert inappropriate fallback:s3_pkt.c:1262:SSL alert number 86
```

## BEAST

```bash
# TLSv1.0 and CBC ciphers
openssl s_client -[sslv3/tls1] -cipher CBC_CIPHER -connect example.com:443
```

## LUCKY13

```bash
openssl s_client -cipher CBC_CIPHER -connect example.com:443
```

## Sweet32

```bash
openssl s_client -cipher 3DES -connect example.com:443
```

## Logjam

```bash
# Check the "Server Temp Key" response is bigger than 1024 (only in OpenSSL 1.0.2 or better)
openssl s_client -connect www.example.com:443 -cipher "EDH"
```

## SSLv2 Support

```bash
# If is supported this will return the server certificate information if not, error
openssl s_client –ssl2 -connect example.com:443
```

## SSLv3 Support

```bash
# If is supported this will return the server certificate information if not, error
openssl s_client -ssl3 -connect google.com:443
```

## Cipher suites

```bash
# Cipher Suites
nmap --script ssl-enum-ciphers -p 443 example.com

# - Anon cypher (fail)
openssl s_client -cipher aNULL -connect example.com:443

# - DES Cipher (fail)
openssl s_client -cipher DES -connect example.com:443

# - 3DES Cipher (fail)
openssl s_client -cipher 3DES -connect example.com:443

# - Export Cipher (fail)
openssl s_client -cipher EXPORT -connect example.com:443

# - Low Cipher (fail)
openssl s_client -cipher LOW -connect example.com:443

# - RC4 Cipher (fail)
openssl s_client -cipher RC4 -connect example.com:443

# - NULL Cipher (fail)
openssl s_client -cipher NULL -connect example.com:443

# - Perfect Forward Secrecy Cipher (This should NOT fail):
openssl s_client -cipher EECDH, EDH NULL -connect example.com:443
```

## Secure renegotiation

```bash
# Check secure renegotiation is not supported
# If not, send request in the renegotiation
# Once sent, if it's vulnerable it shouldn't return error
openssl s_client -connect example.com:443
HEAD / HTTP/1.0
R
# <Enter or Return key>
```

## CRIME

```bash
# Check for "Compression: NONE"
openssl s_client -connect example.com:443
```

## BREACH

```bash
# If the response contains encoded data, host is vulnerable
openssl s_client -connect example.com:443
GET / HTTP/1.1
Host: example.com
Accept-Encoding: compress, gzip
```

## Heartbleed

```bash
# Heartbleed
nmap -p 443 --script ssl-heartbleed --script-args vulns.showall example.com

# Heartbleed checker oneliner from sites list
cat list.txt | while read line ; do echo "QUIT" | openssl s_client -connect $line:443 2>&1 | grep 'server extension "heartbeat" (id=15)' || echo $line: safe; done
```

## Change cipher spec injection

```bash
nmap -p 443 --script ssl-ccs-injection example.com
```

## Cipher order enforcement

```bash
# Choose a protocol and 2 different ciphers, one stronger than other
# Make 2 request with different cipher order anc check in the response if the cipher is the first of the request in both cases
nmap -p 443 --script ssl-enum-ciphers example.com
openssl s_client –tls1_2 –cipher ‘AES128-GCM-SHA256:AES128-SHA’ –connect contextis.co.uk:443
openssl s_client –tls1_2 –cipher ‘AES128-SHA:AES128-GCM-SHA256’ –connect contextis.co.uk:443
```

