# Subdomain Takeover

## Explanation

1. Domain name (sub.example.com) uses a CNAME record for another domain (sub.example.com CNAME anotherdomain.com).&#x20;
2. At some point, anotherdomain.com expires and is available for anyone's registration.&#x20;
3. Since the CNAME record is not removed from the DNS zone of example.com, anyone who records anotherdomain.com has full control over sub.example.com until the DNS record is present.

## Resources

{% embed url="https://0xpatrik.com/takeover-proofs/" %}

{% embed url="https://github.com/EdOverflow/can-i-take-over-xyz" %}
