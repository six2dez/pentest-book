# Domain Enum

## DNSRecon

```bash
dnsrecon -d www.example.com -a 
dnsrecon -d www.example.com -t axfr
dnsrecon -d 
dnsrecon -d www.example.com -D  -t brt
```

## DIG

```bash
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
```

## DNSEnum

```bash
# dnsenum
dnsenum 10.11.1.111
```

