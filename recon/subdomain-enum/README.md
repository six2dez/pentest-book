# Subdomain Enum

## Best Tools

```bash
# https://github.com/OWASP/Amass
amass enum -passive -d example.com -o example.com.subs.txt
# Active needs DNS resolution - takes a long time
amass enum -active -brute -w /hpath/DNS/clean-jhaddix-dns.txt -d example.com -o example.com.subs.brute.txt
# Amass get company ASN and scan
amass intel -org EVILCORP -max-dns-queries 2500 | awk -F, '{print $1}' ORS=',' | sed 's/,$//' | xargs -P3 -I@ -d ',' amass intel -asn @ -max-dns-queries 2500''
# Bruteforce subdmain lists here
# https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS

# https://github.com/Screetsec/Sudomy
./sudomy -d example.com

# https://github.com/cihanmehmet/sub.sh
bash ./sub.sh -a example.com
```

## Subdomain enumeration tools

```bash
assetfinder example.com

subfinder -d example.com  -recursive -silent -t 200 -v -o  example.com.subs
subfinder -d target.com -silent | httpx -follow-redirects -status-code -vhost -threads 300 -silent | sort -u | grep “[200]” | cut -d [ -f1 > resolved.txt

knockpy domain.com

# https://github.com/nsonaniya2010/SubDomainizer
python3 SubDomainizer.py -u https://url.com

python3 domained.py -d example.com --quick

fierce -dns example.com

# Subdomains from Wayback Machine
gau -subs example.com | cut -d / -f 3 | sort -u

# AltDNS - Subdomains of subdomains XD
altdns -i subdomains.txt -o data_output -w words.txt -r -s results_output.txt

# Onliner to find (sub)domains related to a kword on pastebin through google
# https://github.com/gwen001/pentest-tools/blob/master/google-search.py
google-search.py -t "site:http://pastebin.com kword" -b -d -s 0 -e 5 | sed "s/\.com\//\.com\/raw\//" | xargs curl -s | egrep -ho "[a-zA-Z0-9_\.\-]+kword[a-zA-Z0-9_\.\-]+" | sort -fu

dnsrecon -d example.com -D subdomains-top1mil-5000.txt -t brt

# Aquatone - Validate subdomains (take screenshots and generate report)
cat hosts.txt | aquatone

# Wildcard subdomain
dig a *.domain.com = dig a asdasdasd132123123213.domain.com # this is a wildcard subdomain

# Subdomain enumeration from GitHub
# https://github.com/gwen001/github-search
python3 github-subdomains.py -t "GITHUB-TOKEN" -d example.com

# Subdomain bruteforce
dnsrecon -d target.com -D wordlist.txt -t brt

# Get url from JS files
# https://github.com/Threezh1/JSFinder
python JSFinder.py -u http://www.target.com

# Best subdomain bruteforce list 
https://gist.githubusercontent.com/jhaddix/f64c97d0863a78454e44c2f7119c2a6a/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt
```

## Subdomain discovery with Burp

Navigate throug target main website with Burp:

* Without passive scanner
* Set forms auto submit
* Scope in advanced, any protocol and one keyword \("tesla"\)
* Last step, select all sitemap, Engagement Tools -&gt; Analyze target

