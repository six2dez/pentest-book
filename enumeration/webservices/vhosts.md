# VHosts

## Tools

```text
# https://github.com/jobertabma/virtual-host-discovery
ruby scan.rb --ip=192.168.1.101 --host=domain.tld

# https://github.com/dariusztytko/vhosts-sieve
python3 vhosts-sieve.py -d domains.txt -o vhosts.txt

# Enum vhosts
fierce -dns example.com

# https://github.com/codingo/VHostScan
VHostScan -t example.com
```

## Techniques

```text
# ffuf
badresponse=$(curl -s -H "host: totallynotexistsforsure.bugcrowd.com" https://bugcrowd.com | wc -c)
ffuf -u https://TARGET.com -H "Host: FUZZ.TARGET.com" -w werdlists/dns-hostnames/nmap-vhosts-all.txt -fs $badresponse

# Manual with subdomains list
for sub in $(cat subdomains.txt); do
			echo "$sub $(dig +short a $sub | tail -n1)" | anew -q subdomains_ips.txt
done

```

