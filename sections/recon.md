---
description: Information gathering from passive and active methods
---

# Recon

* [Passive info gathering](recon.md#passive-public-info-gathering)
* [AIO](recon.md#aio-recon-tools)
* [Domain](recon.md#domain-enum)
* [Subdomain discovering](recon.md#subdomain-finder)
  * [Subdomain takeover](recon.md#subdomain-takeover)
* [Network scan](recon.md#network-scanning)
* [Nmap](recon.md#nmap-host-scanning)
* [Tcpdump](recon.md#tcpdump-packet-scan)
* [My metholodogy](recon.md#my-methodology)

## Passive/Public info gathering

```text
# Resource
https://osintframework.com/

# Websites
rapiddns.io
dnsdumpster.com
hunter.io
pentest-tools.com
viewdns.info

# spiderfoot
spiderfoot -s domain.com

#DMARC email spoofing
# https://github.com/BishopFox/spoofcheck
python2 spoofcheck.py domain.com

# theHarvester
theHarvester -d domain.com -b all

# recon-ng
recon-ng

# Check Wayback machine
# https://github.com/tomnomnom/waybackurls
go get github.com/tomnomnom/waybackurls

https://gist.githubusercontent.com/mhmdiaa/adf6bff70142e5091792841d4b372050/raw/56366e6f58f98a1788dfec31c68f77b04513519d/waybackurls.py
https://gist.githubusercontent.com/mhmdiaa/2742c5e147d49a804b408bfed3d32d07/raw/5dd007667a5b5400521761df931098220c387551/waybackrobots.py

# Google Dorks
site:target.com -www
site:target.com intitle:"test" -support
site:target.com ext:php | ext:html
site:subdomain.target.com
site:target.com inurl:auth
site:target.com inurl:dev

# Check in GitHub for SSH keys
https://shhgit.darkport.co.uk/
https://github.com/eth0izzle/shhgit
```

## AIO Recon tools

```text
# https://github.com/thewhiteh4t/FinalRecon
python3 finalrecon.py --full https://example.com

# https://github.com/evyatarmeged/Raccoon
raccoon domain.com

# https://github.com/s0md3v/Photon
sudo python3 photon.py -u domain.com -l 3 -t 10 -v --wayback --keys --dns

# https://github.com/j3ssie/Osmedeus
sudo python3 osmedeus.py -t example.com
```

## Domain enum

```text
# DNSRecon
dnsrecon -d www.example.com -a 
dnsrecon -d www.example.com -t axfr
dnsrecon -d 
dnsrecon -d www.example.com -D  -t brt

# Dig
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

# dnsenum
dnsenum 10.11.1.111
```

## Subdomain finder

```text
# Best tools overall
./sub.sh -a example.com
./chomp-scan.sh -u example.com

# Other common tools
assetfinder example.com
subfinder -d example.com
knockpy domain.com
amass enum -active -d example.com
python3 domained.py -d example.com --quick

# AltDNS - Subdomains of subdomains XD
altdns -i subdomains.txt -o data_output -w words.txt -r -s results_output.txt

# Onliner to find (sub)domains related to a kword on pastebin through google
# https://github.com/gwen001/pentest-tools/blob/master/google-search.py
google-search.py -t "site:http://pastebin.com kword" -b -d -s 0 -e 5 | sed "s/\.com\//\.com\/raw\//" | xargs curl -s | egrep -ho "[a-zA-Z0-9_\.\-]+kword[a-zA-Z0-9_\.\-]+" | sort -fu

# Aquatone - Validate subdomains (take screenshots and generate report)
cat hosts.txt | aquatone

# Subdomain bruteforcing
sudo python3 subbrute.py example.com > subbrute_results.txt && massdns -r /MASSDNSPATH/lists/resolvers.txt -t A subbrute_results.txt -o S -w massdns_output.txt
gobuster -m dns -u domain.com -t 100 -w /path/dictionary.txt

# Wildcard subdomain
dig a *.domain.com = dig a asdasdasd132123123213.domain.com -> this is a wildcard subdomain
```

### Subdomain takeover

```text
Explanation:
1. Domain name (sub.example.com) uses a CNAME record for another domain (sub.example.com CNAME anotherdomain.com).
2. At some point, anotherdomain.com expires and is available for anyone's registration.
3. Since the CNAME record is not removed from the DNS zone of example.com, anyone who records anotherdomain.com has full control over sub.example.com until the DNS record is present.

Best resources:
https://0xpatrik.com/takeover-proofs/
https://github.com/EdOverflow/can-i-take-over-xyz
https://blog.initd.sh/others-attacks/mis-configuration/subdomain-takeover-explained/

# Subzy
https://github.com/LukaSikic/subzy
subzy -targets list.txt
subzy -concurrency 100 -hide_fails -targets subs.txt

# SubOver
# https://github.com/Ice3man543/SubOver
SubOver -l /root/subdomains.txt -t 100 # Subdomains generated with subgen

# autoSubTakeover
https://github.com/JordyZomer/autoSubTakeover
pip install autosubtakeover
autosubtakeover --wordlist domains.txt

# subjack
https://github.com/haccer/subjack
subjack -w /root/subdomain.txt -a -v -t 100 -timeout 30 -o results.txt -ssl # Subdomains generated with subgen

# subdomain-takeover
# https://github.com/antichown/subdomain-takeover
python takeover.py -d domain.com -w /root/Repos/SecLists/Discovery/DNS/clean-jhaddix-dns.txt -t 100

# subgen (subdomain list generator)
# https://github.com/pry0cc/subgen
go get -u github.com/pry0cc/subgen
cat wordlist.txt | subgen -d "uber.com"
cat /home/user/Escritorio/tools/SecLists/Discovery/DNS/clean-jhaddix-dns.txt | subgen -d domain.com |  massdns -r /usr/share/wordlists/dns.txt -t A -o S -w results.txt
Check for results.txt
```

## Network scanning

```text
# Netdiscover
netdiscover -i eth0
netdiscover -r 10.11.1.1/24

# Nmap
nmap -sn 10.11.1.1/24
nmap -sn 10.11.1.1-253
nmap -sn 10.11.1.*

# NetBios
nbtscan -r 10.11.1.1/24

# Linux Ping Sweep (Bash)
for i in {1..254} ;do (ping -c 1 172.21.10.$i | grep "bytes from" &) ;done

# Windows Ping Sweep (Run on Windows System)
for /L %i in (1,1,255) do @ping -n 1 -w 200 172.21.10.%i > nul && echo 192.168.1.%i is up.
```

## nmap - host scanning

```text
# Fast simple scan
nmap 10.11.1.111

# Nmap ultra fast
nmap 10.11.1.111 --max-retries 1 --min-rate 1000

# Full complete slow scan with output
nmap -v -A -p- -Pn --script vuln -oA full 10.11.1.111

# Scan for UDP
nmap 10.11.1.111 -sU
unicornscan -mU -v -I 10.11.1.111

# Connect to udp if one is open
nc -u 10.11.1.111 48772

# Responder:
responder -I eth0 -A
```

## tcpdump - packet scan

```text
tcpdump -i eth0
tcpdump -c -i eth0
tcpdump -A -i eth0
tcpdump -w 0001.pcap -i eth0
tcpdump -r 0001.pcap
tcpdump -n -i eth0
tcpdump -i eth0 port 22
tcpdump -i eth0 -src 172.21.10.X
tcpdump -i eth0 -dst 172.21.10.X
```

## My methodology

```text
# Full subdomain enum
./sub.sh -a example.com
./chomp-scan.sh -u example.com

# Take snapshots of every subdomainy
cat subdomains.txt | aquatone -out ~/aquatone/whatever
eyewitness -file subs.txt --prepend-https

# Get unique IPs alive hosts and port scan
nmap -iL subs.txt -Pn -n -sn -oG - | awk '/Up$/{print $2}' > subs_ip_alive.txt
masscan -iL subs_alive.txt -p7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157 --max-rate 10000

# Check for every github repository
gitrob githubaccount

# Check for wayback urls and robots
waybackurls example.com
python3 waybackrobots.py
python3 waybackurls.py

# Check passwords leaks
python3 pwndb.py --target @example.com
python3 pwndb.py --target user@example.com
```

