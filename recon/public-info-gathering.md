# Public info gathering

## Web resources

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
https://www.zoomeye.org/
https://leakix.net/
https://www.yougetsignal.com/
https://intelx.io/
https://pentest-tools.com/

# Analytics
https://publicwww.com/
https://intelx.io/tools?tab=analytics
https://dnslytics.com/reverse-analytics
https://builtwith.com/


# DNS Recon
https://domainbigdata.com/
https://viewdns.info/
http://bgp.he.net/
https://rapiddns.io/
https://dnsdumpster.com/
https://www.whoxy.com/
http://ipv4info.com/

# Mailserver blacklists
http://multirbl.valli.org/

# Dark web exposure
https://immuniweb.com/radar/

# New acquisitions
https://crunchbase.com/

# Email
https://hunter.io/
```

## Whois/Registrant Tools

```bash
# https://github.com/jpf/domain-profiler
./profile target.com

whois

# Whoxy api
#https://github.com/MilindPurswani/whoxyrm
#https://github.com/vysecurity/DomLink
```

## Dorks

### Google

```bash
# Google Dorks Cli
# https://github.com/six2dez/degoogle_hunter
degoogle_hunter.sh company.com

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
```

### GitHub

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

## General / AIO

### Amass

```bash
# Get ASN and do amass intel
# Get ASN
amass intel -org "whatever"
# Reverse whois
amass intel -active -asn NUMBER -whois -d domain.com
# SSL Cert Grabbing
amass enum -active -d example.com -cidr IF.YOU.GOT.THIS/24 -asn NUMBER
```

### Spiderfoot

```bash
spiderfoot -s domain.com
```

### theHarvester

```bash
# theHarvester
theHarvester -d domain.com -b all
```

### recon-ng

```bash
recon-ng
```

## URLs & IPs

### waybackurls / gau / shorteners

```bash
# https://github.com/lc/gau
gau example.com

# https://github.com/utkusen/urlhunter
urlhunter -keywords keywords.txt -date latest

# https://github.com/tomnomnom/waybackurls
go get github.com/tomnomnom/waybackurls

# Wayback machine dorks
https://web.archive.org/web/*/website.com/*

https://gist.githubusercontent.com/mhmdiaa/adf6bff70142e5091792841d4b372050/raw/56366e6f58f98a1788dfec31c68f77b04513519d/waybackurls.py
https://gist.githubusercontent.com/mhmdiaa/2742c5e147d49a804b408bfed3d32d07/raw/5dd007667a5b5400521761df931098220c387551/waybackrobots.py
```

### favicon tools

```bash
# https://github.com/devanshbatham/FavFreak
cat urls.txt | python3 favfreak.py
# https://github.com/pielco11/fav-up
favUp.py -k SHODANKEY -w website.com
```

### Rapid 7 Sonar DNS database

```bash
# https://opendata.rapid7.com/sonar.fdns_v2/
# https://github.com/cgboal/sonarsearch

go get -u github.com/cgboal/sonarsearch/crobat
crobat -s site.com
```

## Creds leaks 

### pymeta - metadata analyzer

```bash
# https://github.com/m8r0wn/pymeta
pymeta -d example.com
```

### pwndb - leaked creds \(tor enabled\)

```bash
# https://github.com/davidtavarez/pwndb
python3 pwndb.py --target asd@asd.com
```

### Websites

```bash
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

