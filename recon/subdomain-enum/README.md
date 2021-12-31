# Subdomain Enum

## Passive sources

```bash
# https://github.com/OWASP/Amass
# https://github.com/OWASP/Amass/blob/master/examples/config.ini
amass enum -passive -d domain.com

# https://github.com/projectdiscovery/subfinder
# https://github.com/projectdiscovery/subfinder#post-installation-instructions
subfinder -d domain.com -all -silent

# https://github.com/tomnomnom/assetfinder
assetfinder example.com

# https://github.com/tomnomnom/waybackurls
# https://github.com/tomnomnom/unfurl
echo domain.com | waybackurls | unfurl -u domains

# https://github.com/lc/gau
# https://github.com/tomnomnom/unfurl
gau -subs example.com | unfurl -u domains

## Cert Transparency
# https://certificate.transparency.dev/
# https://crt.sh/
# https://github.com/UnaPibaGeek/ctfr
python3 ctfr.py -d domain.com
```

## Active DNS resolution

```bash
# Generate custom resolvers list, always
# https://github.com/vortexau/dnsvalidator
dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 200

# https://github.com/d3mondev/puredns
puredns resolve subdomains.txt -r ~/Tools/resolvers.txt

## BF
# https://github.com/d3mondev/puredns
puredns bruteforce ~/Tools/subdomains.txt united.com -r ~/Tools/resolvers.txt
```

## Alterations and permutations

```bash
#https://github.com/Josue87/gotator
gotator -sub subdomains/subdomains.txt -perm permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md
```

## Crawling

```bash
# 1st resolve subdomains on valid websites
# https://github.com/projectdiscovery/httpx
cat subdomains.txt | httpx -follow-host-redirects -random-agent -status-code -silent -retries 2 -title -web-server -tech-detect -location -o webs_info.txt
# Clean output
cat webs_info.txt | cut -d ' ' -f1 | grep ".domain.com" | sort -u > websites.txt
# Crawl them
# https://github.com/jaeles-project/gospider
gospider -S websites.txt --js -t 20 -d 2 --sitemap --robots -w -r > urls.txt
# Clean output
# https://github.com/tomnomnom/unfurl
cat urls.txt | sed '/^.\{2048\}./d' | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | grep ".domain.com"
```

## DNS records

```bash
# https://github.com/projectdiscovery/dnsx
dnsx -retry 3 -a -aaaa -cname -ns -ptr -mx -soa -resp -silent -l subdomains.txt
```

## Other techniques

### Google Analytics ID

```bash
# https://github.com/Josue87/AnalyticsRelationships
cat subdomains.txt | analyticsrelationships
```

### Subdomain discovery with Burp

Navigate through target main website with Burp:

* Without passive scanner
* Set forms auto submit
* Scope in advanced, any protocol and one keyword ("tesla")
* Last step, select all sitemap, Engagement Tools -> Analyze target
