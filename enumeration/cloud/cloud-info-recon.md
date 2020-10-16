# Cloud Info Gathering



```text
# Azure IP Ranges
https://azurerange.azurewebsites.net/

# AWS IP Range
https://ip-ranges.amazonaws.com/ip-ranges.json
- Get creation date
jq .createDate < ip-ranges.json
- Get info for specific region
jq  '.prefixes[] | select(.region=="us-east-1")' < ip-ranges.json
- Get all IPs
jq -r '.prefixes | .[].ip_prefix' < ip-ranges.json

# Online services
https://viewdns.info/
https://securitytrails.com/
https://www.shodan.io/search?query=net%3A%2234.227.211.0%2F24%22
https://censys.io/ipv4?q=s3

# Google Dorks
site:*.amazonaws.com -www "compute"
site:*.amazonaws.com -www "compute" "ap-south-1"
site:pastebin.com "rds.amazonaws.com" "u " pass OR password
https://storage.googleapis.com/COMPANY

# Check certificate transparency logs
https://crt.sh
%.netfilx.com

# Find Cloud Services
python3 cloud_enum.py -k keywork
python3 CloudScraper.py -u https://example.com

# AWS Buckets
# Dork
site:*.s3.amazonaws.com ext:xls | ext:xlsx | ext:csv password|passwd|pass user|username|uid|email

# AWS discovering, stealing keys and endpoints
# Nimbostratus - check against acutal profile
https://github.com/andresriancho/nimbostratus
python nimbostratus dump-credentials

# ScoutSuite - audit AWS, GCP and Azure clouds
scout --provider aws --profile stolen

# Prowler - AWS security assessment, auditing and hardening
https://github.com/toniblyx/prowler
```

