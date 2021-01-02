# Subdomain Takeover

## Explanation

1. Domain name \(sub.example.com\) uses a CNAME record for another domain \(sub.example.com CNAME anotherdomain.com\). 
2. At some point, anotherdomain.com expires and is available for anyone's registration. 
3. Since the CNAME record is not removed from the DNS zone of example.com, anyone who records anotherdomain.com has full control over sub.example.com until the DNS record is present.

## Resources

{% embed url="https://0xpatrik.com/takeover-proofs/" %}

{% embed url="https://github.com/EdOverflow/can-i-take-over-xyz" %}

{% embed url="https://blog.initd.sh/others-attacks/mis-configuration/subdomain-takeover-explained/" %}

## Tools

```bash
# https://github.com/LukaSikic/subzy
subzy -targets list.txt
subzy -concurrency 100 -hide_fails -targets subs.txt

# https://github.com/haccer/subjack
subjack -w /root/subdomain.txt -a -v -t 100 -timeout 30 -o results.txt -ssl # Subdomains generated with subgen

# https://github.com/guptabless/unclaim-s3-finder
bucket-takeover.py -u https://qweqwe.asasdasdad.com

# https://github.com/In3tinct/Taken

```

