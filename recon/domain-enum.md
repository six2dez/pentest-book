# Root domains

### Basic

```bash
# https://github.com/OWASP/Amass 
amass intel -d domain.com -whois 

# Search on Google
https://google.com/search?q=united+airlines 

# Analyze owners on domainbigdata
https://iqwhois.com/
```

### Reverse whois

```
https://viewdns.info/reversewhois/?q=United+Airlines
https://tools.whoisxmlapi.com/reverse-whois-search
```

### ASN

```bash
https://bgp.he.net/search?search%5Bsearch%5D=united+airlines&commit=Search 
whois -h whois.radb.net -- '-i origin AS11535' | grep -Eo "([0-9.]+){4}/[0-9]+" | uniq 
whois -h whois.radb.net -- '-i origin AS20461' | grep -Eo "([0-9.]+){4}/[0-9]+" | uniq | mapcidr -silent | dnsx -ptr -resp-only -retry 3 -silent
```

### Favicon

```bash
# https://github.com/pielco11/fav-up
python3 favUp.py -ff ~/favicon.ico --shodan-cli 

# https://github.com/devanshbatham/FavFreak
cat urls.txt | python3 favfreak.py 

# https://faviconhasher.herokuapp.com/

# https://www.shodan.io/search?query=http.favicon.hash%3A-382492124

# https://github.com/edoardottt/favirecon
favirecon -u https://target.com/ -v
```

### Google Analytics ID

```bash
https://builtwith.com/relationships/united.com
https://builtwith.com/relationships/tag/UA-29214177
https://api.hackertarget.com/analyticslookup/?q=united.com
https://api.hackertarget.com/analyticslookup/?q=UA-16316580
```

### DNS manual recon

```bash
dnsrecon -d www.example.com -a 
dnsrecon -d www.example.com -t axfr
dnsrecon -d 
dnsrecon -d www.example.com -D  -t brt

dig www.example.com + short
dig www.example.com MX
dig www.example.com NS
dig www.example.com> SOA
dig www.example.com ANY +noall +answer
dig -x www.example.com
dig -4 www.example.com (For IPv4)
dig -6 www.example.com (For IPv6)
dig www.example.com mx +noall +answer example.com ns +noall +answer
dig -t AXFR www.example.com
dig axfr @10.11.1.111 example.box

dnsenum 10.11.1.111
```

### Reverse IP search

```bash
# Get domain from IP
# https://reverse-ip.whoisxmlapi.com/
# https://github.com/projectdiscovery/dnsx
cat ips.txt | dnsx -ptr -resp-only -silent -retry 3
```

### TLD bruteforcing

```
# TLD bruteforcing tool
https://github.com/Sybil-Scan/TLDbrute
```
