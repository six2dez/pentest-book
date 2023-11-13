# Host Scanning

## nmap

```bash
# Fast simple scan
nmap 10.11.1.111

# Nmap ultra fast
nmap 10.11.1.111 --max-retries 1 --min-rate 1000

# Get open ports
nmap -p - -Pn -n 10.10.10.10

# Comprehensive fast and accurate
nmap --top-ports 200 -sV -n --max-retries 2 -Pn --open -iL ips.txt -oA portscan_active

# Get sV from ports
nmap -pXX,XX,XX,XX,XX -Pn -sV -n 10.10.10.10

# Full complete slow scan with output
nmap -v -A -p- -Pn --script vuln -oA full 10.11.1.111

# Network filtering evasion
nmap --source-port 53 -p 5555 10.11.1.111
    # If work, set IPTABLES to bind this port
    iptables -t nat -A POSTROUTING -d 10.11.1.111 -p tcp -j SNAT --to :53

# Scan for UDP
nmap 10.11.1.111 -sU
nmap -sU -F -Pn -v -d -sC -sV --open --reason -T5 10.11.1.111

# FW evasion
nmap -f <IP>
nmap --mtu 24 <IP>
nmap --data-length 30 <IP>
nmap --source-port 53 <IP>

# Nmap better speed flags
--max-rtt-timeout: Time response per probe
--script-timeout: Time response per script
--host-timeout: Time response for host
--open: Avoid detection if filtered or closed
--min-rate
```

## shodan

```bash
# https://cli.shodan.io/
shodan host 151.101.1.68
```

![](<../.gitbook/assets/image (2).png>)

![](<../.gitbook/assets/image (45).png>)
