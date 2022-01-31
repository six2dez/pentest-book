# Public info gathering

## OSINT resources

```bash
https://osintframework.com/
https://i-intelligence.eu/uploads/public-documents/OSINT_Handbook_2020.pdf
https://start.me/p/DPYPMz/the-ultimate-osint-collection
https://docs.google.com/spreadsheets/d/18rtqh8EG2q1xBo2cLNyhIDuK9jrPGwYr9DI2UncoqJQ
```

## OSINT websites

```bash
# Multipurpose
https://shodan.io/
https://app.netlas.io/
https://fofa.so/
https://fullhunt.io/
https://www.zoomeye.org/
https://leakix.net/
https://www.yougetsignal.com/
https://intelx.io/
https://pentest-tools.com/
https://gofindwhois.com/
https://gofindwho.com/

# Domain Recon
https://domainbigdata.com/
https://suip.biz/
https://viewdns.info/
http://bgp.he.net/
https://dnsdumpster.com/
https://www.whoxy.com/
http://ipv4info.com/
https://rapiddns.io/

# Analytics
https://publicwww.com/
https://intelx.io/tools?tab=analytics
https://dnslytics.com/reverse-analytics
https://builtwith.com/

# Mailserver blacklists
http://multirbl.valli.org/

# Dark web exposure
https://immuniweb.com/radar/

# New acquisitions
https://crunchbase.com/

# Public APIs
https://www.postman.com/explore/
```

## General / AIO

```bash
# https://github.com/OWASP/Amass
# Get ASN
amass intel -org "whatever"
# Reverse whois
amass intel -active -asn NUMBER -whois -d domain.com
# SSL Cert Grabbing
amass enum -active -d example.com -cidr IF.YOU.GOT.THIS/24 -asn NUMBER

# https://github.com/smicallef/spiderfoot
spiderfoot -s domain.com

# https://github.com/j3ssie/Osmedeus
python3 osmedeus.py -t example.com

# https://github.com/thewhiteh4t/FinalRecon
python3 finalrecon.py --full https://example.com

# https://github.com/laramies/theHarvester
theHarvester -d domain.com -b all

# https://github.com/lanmaster53/recon-ng
recon-ng
```

## Whois/Registrant Tools

```bash
# https://github.com/jpf/domain-profiler
./profile target.com

# Standard whois tool
whois

# Whoxy api
# https://www.whoxy.com/
# Whoxy clients
# https://github.com/MilindPurswani/whoxyrm
# https://github.com/vysecurity/DomLink
```

## Dorks

### Google

#### Tools

```bash
# Google Dorks Cli
# https://github.com/six2dez/degoogle_hunter
degoogle_hunter.sh company.com

# uDork
# https://github.com/m3n0sd0n4ld/uDork
./uDork.sh united.com -u all
./uDork.sh united.com -e all
```

#### Dorks

```bash
# Google dorks helper
https://dorks.faisalahmed.me/

# Code share sites
site:http://ideone.com | site:http://codebeautify.org | site:http://codeshare.io | site:http://codepen.io | site:http://repl.it | site:http://jsfiddle.net "company"
# GitLab/GitHub/Bitbucket
site:github.com | site:gitlab.com | site:bitbucket.org "company"
# Stackoverflow
site:stackoverflow.com "target.com"
# Project management sites
site:http://trello.com | site:*.atlassian.net "company"
# Pastebin-like sites
site:http://justpaste.it | site:http://pastebin.com "company"
# Config files
site:target.com ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:env | ext:ini
# Database files
site:target.com ext:sql | ext:dbf | ext:mdb
# Backup files
site:target.com ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup
# .git folder
inurl:"/.git" target.com -github
# Exposed documents
site:target.com ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv
# Other files
site:target.com intitle:index.of | ext:log | ext:php intitle:phpinfo "published by the PHP Group" | inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd | shadow | passwd | boot.ini | inurl:backdoor | inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config | inurl:"/phpinfo.php" | inurl:".htaccess" | ext:swf
# SQL errors
site:target.com intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"
# PHP errors
site:target.com "PHP Parse error" | "PHP Warning" | "PHP Error"
# Login pages
site:target.com inurl:signup | inurl:register | intitle:Signup
# Open redirects
site:target.com inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:src=http | inurl:r=http
# Apache Struts RCE
site:target.com ext:action | ext:struts | ext:do
# Search in pastebin
site:pastebin.com target.com
# Linkedin employees
site:linkedin.com employees target.com
# Wordpress files
site:target.com inurl:wp-content | inurl:wp-includes
# Subdomains
site:*.target.com
# Sub-subdomains
site:*.*.target.com
#Find S3 Buckets
site:.s3.amazonaws.com | site:http://storage.googleapis.com | site:http://amazonaws.com "target"
# Traefik
intitle:traefik inurl:8080/dashboard "target"
# Jenkins
intitle:"Dashboard [Jenkins]"

# Other 3rd parties sites
https://www.google.com/search?q=site%3Agitter.im%20%7C%20site%3Apapaly.com%20%7C%20site%3Aproductforums.google.com%20%7C%20site%3Acoggle.it%20%7C%20site%3Areplt.it%20%7C%20site%3Aycombinator.com%20%7C%20site%3Alibraries.io%20%7C%20site%3Anpm.runkit.com%20%7C%20site%3Anpmjs.com%20%7C%20site%3Ascribd.com%20%22united%22
# Backup files
https://www.google.com/search?q=site%3Aunited.com%20ext%3Abkf%20%7C%20ext%3Abkp%20%7C%20ext%3Abak%20%7C%20ext%3Aold%20%7C%20ext%3Abackup
# Login pages
https://www.google.com/search?q=site%3Aunited.com%20inurl%3Asignup%20%7C%20inurl%3Aregister%20%7C%20intitle%3ASignup
# Config files
https://www.google.com/search?q=site%3Aunited.com%20ext%3Axml%20%7C%20ext%3Aconf%20%7C%20ext%3Acnf%20%7C%20ext%3Areg%20%7C%20ext%3Ainf%20%7C%20ext%3Ardp%20%7C%20ext%3Acfg%20%7C%20ext%3Atxt%20%7C%20ext%3Aora%20%7C%20ext%3Aenv%20%7C%20ext%3Aini
# .git folder
https://www.google.com/search?q=inurl%3A%5C%22%2F.git%5C%22%20united.com%20-github
# Database files
https://www.google.com/search?q=site%3Aunited.com%20ext%3Asql%20%7C%20ext%3Adbf%20%7C%20ext%3Amdb
# Open redirects
https://www.google.com/search?q=site%3Aunited.com%20inurl%3Aredir%20%7C%20inurl%3Aurl%20%7C%20inurl%3Aredirect%20%7C%20inurl%3Areturn%20%7C%20inurl%3Asrc%3Dhttp%20%7C%20inurl%3Ar%3Dhttp
# Code share sites
https://www.google.com/search?q=site%3Asharecode.io%20%7C%20site%3Acontrolc.com%20%7C%20site%3Acodepad.co%20%7Csite%3Aideone.com%20%7C%20site%3Acodebeautify.org%20%7C%20site%3Ajsdelivr.com%20%7C%20site%3Acodeshare.io%20%7C%20site%3Acodepen.io%20%7C%20site%3Arepl.it%20%7C%20site%3Ajsfiddle.net%20%22united%22
# Pastebin-like sites
https://www.google.com/search?q=site%3Ajustpaste.it%20%7C%20site%3Aheypasteit.com%20%7C%20site%3Apastebin.com%20%22united%22
# Linkedin employees
https://www.google.com/search?q=site%3Alinkedin.com%20employees%20united.com
# Project management sites
https://www.google.com/search?q=site%3Atrello.com%20%7C%20site%3A*.atlassian.net%20%22united%22
# Other files
https://www.google.com/search?q=site%3Aunited.com%20intitle%3Aindex.of%20%7C%20ext%3Alog%20%7C%20ext%3Aphp%20intitle%3Aphpinfo%20%5C%22published%20by%20the%20PHP%20Group%5C%22%20%7C%20inurl%3Ashell%20%7C%20inurl%3Abackdoor%20%7C%20inurl%3Awso%20%7C%20inurl%3Acmd%20%7C%20shadow%20%7C%20passwd%20%7C%20boot.ini%20%7C%20inurl%3Abackdoor%20%7C%20inurl%3Areadme%20%7C%20inurl%3Alicense%20%7C%20inurl%3Ainstall%20%7C%20inurl%3Asetup%20%7C%20inurl%3Aconfig%20%7C%20inurl%3A%5C%22%2Fphpinfo.php%5C%22%20%7C%20inurl%3A%5C%22.htaccess%5C%22%20%7C%20ext%3Aswf
# Sub-subdomains
https://www.google.com/search?q=site%3A*.*.united.com
# Jenkins
https://www.google.com/search?q=intitle%3A%5C%22Dashboard%20%5BJenkins%5D%5C%22%20%22united%22
# Traefik
https://www.google.com/search?q=intitle%3Atraefik%20inurl%3A8080%2Fdashboard%20%22united%22
# Cloud buckets S3/GCP
https://www.google.com/search?q=site%3A.s3.amazonaws.com%20%7C%20site%3Astorage.googleapis.com%20%7C%20site%3Aamazonaws.com%20%22united%22
# SQL errors
https://www.google.com/search?q=site%3Aunited.com%20intext%3A%5C%22sql%20syntax%20near%5C%22%20%7C%20intext%3A%5C%22syntax%20error%20has%20occurred%5C%22%20%7C%20intext%3A%5C%22incorrect%20syntax%20near%5C%22%20%7C%20intext%3A%5C%22unexpected%20end%20of%20SQL%20command%5C%22%20%7C%20intext%3A%5C%22Warning%3A%20mysql_connect()%5C%22%20%7C%20intext%3A%5C%22Warning%3A%20mysql_query()%5C%22%20%7C%20intext%3A%5C%22Warning%3A%20pg_connect()%5C%22
# Exposed documents
https://www.google.com/search?q=site%3Aunited.com%20ext%3Adoc%20%7C%20ext%3Adocx%20%7C%20ext%3Aodt%20%7C%20ext%3Apdf%20%7C%20ext%3Artf%20%7C%20ext%3Asxw%20%7C%20ext%3Apsw%20%7C%20ext%3Appt%20%7C%20ext%3Apptx%20%7C%20ext%3Apps%20%7C%20ext%3Acsv
# Wordpress files
https://www.google.com/search?q=site%3Aunited.com%20inurl%3Awp-content%20%7C%20inurl%3Awp-includes
# Apache Struts RCE
https://www.google.com/search?q=site%3Aunited.com%20ext%3Aaction%20%7C%20ext%3Astruts%20%7C%20ext%3Ado
# GitLab/GitHub/Bitbucket
https://www.google.com/search?q=site%3Agithub.com%20%7C%20site%3Agitlab.com%20%7C%20site%3Abitbucket.org%20%22united%22
# Subdomains
https://www.google.com/search?q=site%3A*.united.com
# Stackoverflow
https://www.google.com/search?q=site%3Astackoverflow.com%20%22united.com%22
# PHP errors
https://www.google.com/search?q=site%3Aunited.com%20%5C%22PHP%20Parse%20error%5C%22%20%7C%20%5C%22PHP%20Warning%5C%22%20%7C%20%5C%22PHP%20Error%5C%22
```

### GitHub

#### Tools

```
#https://github.com/obheda12/GitDorker
python3 GitDorker.py -tf ~/Tools/.github_tokens -q united.com -p -ri -d Dorks/medium_dorks.txt
```

#### Dorks

```bash
".mlab.com password"
"access_key"
"access_token"
"amazonaws"
"api.googlemaps AIza"
"api_key"
"api_secret"
"apidocs"
"apikey"
"apiSecret"
"app_key"
"app_secret"
"appkey"
"appkeysecret"
"application_key"
"appsecret"
"appspot"
"auth"
"auth_token"
"authorizationToken"
"aws_access"
"aws_access_key_id"
"aws_key"
"aws_secret"
"aws_token"
"AWSSecretKey"
"bashrc password"
"bucket_password"
"client_secret"
"cloudfront"
"codecov_token"
"config"
"conn.login"
"connectionstring"
"consumer_key"
"credentials"
"database_password"
"db_password"
"db_username"
"dbpasswd"
"dbpassword"
"dbuser"
"dot-files"
"dotfiles"
"encryption_key"
"fabricApiSecret"
"fb_secret"
"firebase"
"ftp"
"gh_token"
"github_key"
"github_token"
"gitlab"
"gmail_password"
"gmail_username"
"herokuapp"
"internal"
"irc_pass"
"JEKYLL_GITHUB_TOKEN"
"key"
"keyPassword"
"ldap_password"
"ldap_username"
"login"
"mailchimp"
"mailgun"
"master_key"
"mydotfiles"
"mysql"
"node_env"
"npmrc _auth"
"oauth_token"
"pass"
"passwd"
"password"
"passwords"
"pem private"
"preprod"
"private_key"
"prod"
"pwd"
"pwds"
"rds.amazonaws.com password"
"redis_password"
"root_password"
"secret"
"secret.password"
"secret_access_key"
"secret_key"
"secret_token"
"secrets"
"secure"
"security_credentials"
"send.keys"
"send_keys"
"sendkeys"
"SF_USERNAME salesforce"
"sf_username"
"site.com" FIREBASE_API_JSON=
"site.com" vim_settings.xml
"slack_api"
"slack_token"
"sql_password"
"ssh"
"ssh2_auth_password"
"sshpass"
"staging"
"stg"
"storePassword"
"stripe"
"swagger"
"testuser"
"token"
"x-api-key"
"xoxb "
"xoxp"
[WFClient] Password= extension:ica
access_key
bucket_password
dbpassword
dbuser
extension:avastlic "support.avast.com"
extension:bat
extension:cfg
extension:env
extension:exs
extension:ini
extension:json api.forecast.io
extension:json googleusercontent client_secret
extension:json mongolab.com
extension:pem
extension:pem private
extension:ppk
extension:ppk private
extension:properties
extension:sh
extension:sls
extension:sql
extension:sql mysql dump
extension:sql mysql dump password
extension:yaml mongolab.com
extension:zsh
filename:.bash_history
filename:.bash_history DOMAIN-NAME
filename:.bash_profile aws
filename:.bashrc mailchimp
filename:.bashrc password
filename:.cshrc
filename:.dockercfg auth
filename:.env DB_USERNAME NOT homestead
filename:.env MAIL_HOST=smtp.gmail.com
filename:.esmtprc password
filename:.ftpconfig
filename:.git-credentials
filename:.history
filename:.htpasswd
filename:.netrc password
filename:.npmrc _auth
filename:.pgpass
filename:.remote-sync.json
filename:.s3cfg
filename:.sh_history
filename:.tugboat NOT _tugboat
filename:_netrc password
filename:apikey
filename:bash
filename:bash_history
filename:bash_profile
filename:bashrc
filename:beanstalkd.yml
filename:CCCam.cfg
filename:composer.json
filename:config
filename:config irc_pass
filename:config.json auths
filename:config.php dbpasswd
filename:configuration.php JConfig password
filename:connections
filename:connections.xml
filename:constants
filename:credentials
filename:credentials aws_access_key_id
filename:cshrc
filename:database
filename:dbeaver-data-sources.xml
filename:deployment-config.json
filename:dhcpd.conf
filename:dockercfg
filename:environment
filename:express.conf
filename:express.conf path:.openshift
filename:filezilla.xml
filename:filezilla.xml Pass
filename:git-credentials
filename:gitconfig
filename:global
filename:history
filename:htpasswd
filename:hub oauth_token
filename:id_dsa
filename:id_rsa
filename:id_rsa or filename:id_dsa
filename:idea14.key
filename:known_hosts
filename:logins.json
filename:makefile
filename:master.key path:config
filename:netrc
filename:npmrc
filename:pass
filename:passwd path:etc
filename:pgpass
filename:prod.exs
filename:prod.exs NOT prod.secret.exs
filename:prod.secret.exs
filename:proftpdpasswd
filename:recentservers.xml
filename:recentservers.xml Pass
filename:robomongo.json
filename:s3cfg
filename:secrets.yml password
filename:server.cfg
filename:server.cfg rcon password
filename:settings
filename:settings.py SECRET_KEY
filename:sftp-config.json
filename:sftp-config.json password
filename:sftp.json path:.vscode
filename:shadow
filename:shadow path:etc
filename:spec
filename:sshd_config
filename:token
filename:tugboat
filename:ventrilo_srv.ini
filename:WebServers.xml
filename:wp-config
filename:wp-config.php
filename:zhrc
HEROKU_API_KEY language:json
HEROKU_API_KEY language:shell
HOMEBREW_GITHUB_API_TOKEN language:shell
jsforce extension:js conn.login
language:yaml -filename:travis
msg nickserv identify filename:config
org:Target "AWS_ACCESS_KEY_ID"
org:Target "list_aws_accounts"
org:Target "aws_access_key"
org:Target "aws_secret_key"
org:Target "bucket_name"
org:Target "S3_ACCESS_KEY_ID"
org:Target "S3_BUCKET"
org:Target "S3_ENDPOINT"
org:Target "S3_SECRET_ACCESS_KEY"
password
path:sites databases password
private -language:java
PT_TOKEN language:bash
redis_password
root_password
secret_access_key
SECRET_KEY_BASE=
shodan_api_key language:python
WORDPRESS_DB_PASSWORD=
xoxp OR xoxb OR xoxa
s3.yml
.exs
beanstalkd.yml
deploy.rake
.sls
```

### Shodan

#### Dorks

```bash
port:"9200" elastic
product:"docker"
product:"kubernetes"
hostname:"target.com"
host:"10.10.10.10"
# Spring boot servers, look for /env or /heapdump
org:YOUR_TAGET http.favicon.hash:116323821 
```

## ASN/CIDR Tools

```bash
# https://github.com/nitefood/asn
asn -n 8.8.8.8

# https://github.com/j3ssie/metabigor
echo "company" | metabigor net --org
echo "ASN1111" | metabigor net --asn

# https://github.com/yassineaboukir/Asnlookup
python asnlookup.py -m -o <Organization>

# https://github.com/harleo/asnip
asnip -t domain.com -p

# https://github.com/projectdiscovery/mapcidr
echo 10.10.10.0/24 | mapcidr

# https://github.com/eslam3kl/3klector
python 3klector.py -t company

# https://github.com/SpiderLabs/HostHunter
python3 hosthunter.py targets.txt
```

## Credentials leaks&#x20;

```bash
# pwndb
# https://github.com/davidtavarez/pwndb
python3 pwndb.py --target asd@asd.com

# Websites
https://hunter.io/
https://link-base.org/index.php
http://xjypo5vzgmo7jca6b322dnqbsdnp3amd24ybx26x5nxbusccjkm4pwid.onion/
http://pwndb2am4tzkvold.onion
https://weleakinfo.to/
https://www.dehashed.com/search?query=
https://haveibeenpwned.com
https://breachchecker.com
https://vigilante.pw/
https://leak.sx/
https://intelx.io
https://breachdirectory.org/
```

## Email tools

```bash
# https://github.com/SimplySecurity/SimplyEmail
./SimplyEmail.py

pip3 install mailspoof
sudo mailspoof -d domain.com

# Test email spoof
https://emkei.cz/

# https://github.com/sham00n/buster
buster -e target@example.com

# https://github.com/m4ll0k/Infoga
python infoga.py

# https://github.com/martinvigo/email2phonenumber
python email2phonenumber.py scrape -e target@email.com

# https://github.com/jkakavas/creepy/

# https://github.com/Josue87/EmailFinder
emailfinder -d domain.com

# https://github.com/laramies/theHarvester
python3 theHarvester.py -d domain.com -b "linkedin"
```

## GIT tools

```bash
# https://github.com/obheda12/GitDorker
python3 GitDorker.py -tf TOKENSFILE -q tesla.com -d dorks/DORKFILE -o target

# https://github.com/dxa4481/truffleHog
trufflehog https://github.com/Plazmaz/leaky-repo
trufflehog --regex --entropy=False https://github.com/Plazmaz/leaky-repo

# https://github.com/eth0izzle/shhgit
shhgit --search-query AWS_ACCESS_KEY_ID=AKIA

# https://github.com/d1vious/git-wild-hunt
python git-wild-hunt.py -s "extension:json filename:creds language:JSON"

# https://shhgit.darkport.co.uk/

# GitLab (API token required)
# https://github.com/codeEmitter/token-hunter
./token-hunter.py -g 123456
```

## Metadata

```bash
# https://github.com/Josue87/MetaFinder
metafinder -d "domain.com" -l 10 -go -bi -ba -o united
```

## Social Media

```bash
# Twitter
# https://github.com/twintproject/twint
twint -u username

# Google account
# https://github.com/mxrch/ghunt
python hunt.py myemail@gmail.com

# Instagram
# https://github.com/th3unkn0n/osi.ig
python3 main.py -u username

# Public GDrive docs
https://www.dedigger.com/#gsc.tab=0

# Websites
emailrep.io # Accounts registered by email
tinfoleak.com # Twitter
mostwantedhf.info # Skype
searchmy.bio # Instagram
search.carrot2.org # Results grouped by topic
boardreader.com # forums
searchcode.com # search by code in repositories
swisscows.com # semantic search engine
publicwww.com # search by source page code
psbdmp.ws # search in pastebin
kribrum.io # social-media search engine
whatsmyname.app
```
