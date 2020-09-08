# Network Scanning

## Netdiscover

```bash
netdiscover -i eth0
netdiscover -r 10.11.1.1/24
```

## Nmap

```bash
nmap -sn 10.11.1.1/24
nmap -sn 10.11.1.1-253
nmap -sn 10.11.1.*
```

## NetBios

```bash
nbtscan -r 10.11.1.1/24
```

## Ping Sweep - Bash

```bash
for i in {1..254} ;do (ping -c 1 172.21.10.$i | grep "bytes from" &) ;done
```

## Ping Sweep - Windows

```bash
for /L %i in (1,1,255) do @ping -n 1 -w 200 172.21.10.%i > nul && echo 192.168.1.%i is up.
```

