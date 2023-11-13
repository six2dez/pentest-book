# General

## Tools

```bash
# Non provider specific and general purpose
# https://github.com/nccgroup/ScoutSuite
# https://github.com/SygniaLabs/security-cloud-scout
# https://github.com/initstring/cloud_enum
python3 cloud_enum.py -k companynameorkeyword
# https://github.com/cyberark/SkyArk
# https://github.com/SecurityFTW/cs-suite
    cd /tmp
    mkdir .aws
    cat > .aws/config <<EOF
        [default]
        output = json
        region = us-east-1
    EOF
    cat > .aws/credentials <<EOF
        [default]
        aws_access_key_id = XXXXXXXXXXXXXXX
        aws_secret_access_key = XXXXXXXXXXXXXXXXXXXXXXXXX
    EOF
    docker run -v `pwd`/.aws:/root/.aws -v `pwd`/reports:/app/reports securityftw/cs-suite -env aws

# Dictionary
https://gist.github.com/BuffaloWill/fa96693af67e3a3dd3fb

Searching for bad configurations

No auditable items:
• DoS testing
• Intense fuzzing
• Phishing the cloud provider’s employees
• Testing other company’s assets
• Etc.
```

## Audit policies

{% embed url="https://www.microsoft.com/en-us/msrc/pentest-rules-of-engagement" %}

{% embed url="https://aws.amazon.com/security/penetration-testing" %}

{% embed url="https://support.google.com/cloud/answer/6262505?hl=en" %}

## Comparison table

![](<../../.gitbook/assets/image (30).png>)

## Recon

```bash
# PoC from Forward DNS dataset
# This data is created by extracting domain names from a number of sources and then sending DNS queries for each domain.
# https://opendata.rapid7.com/sonar.fdns_v2/
cat CNAME-DATASET-NAME | pigz -dc | grep -E "\.azurewebsites\.com"
cat CNAME-DATASET-NAME | pigz -dc | grep -E "\.s3\.amazonaws\.com"

# https://github.com/99designs/clouddetect
clouddetect -ip=151.101.1.68

• First step should be to determine what services are in use
• More and more orgs are moving assets to the cloud one at a time
• Many have limited deployment to cloud providers, but some have fully embraced the cloud and are using it for AD, production assets, security products, and more
• Determine things like AD connectivity, mail gateways, web apps, file storage, etc.
• Traditional host discovery still applies
• After host discovery resolve all names, then perform whois
lookups to determine where they are hosted
• Microsoft, Amazon, Google IP space usually indicates cloud service usage
   ◇ More later on getting netblock information for each cloud service
• MX records can show cloud-hosted mail providers
• Certificate Transparency (crt.sh)
• Monitors and logs digital certs
• Creates a public, searchable log
• Can help discover additional subdomains
• More importantly… you can potentially find more Top Level Domains (TLD’s)!
• Single cert can be scoped for multiple domains
• Search (Google, Bing, Baidu, DuckDuckGo): site:targetdomain.com -site:www.targetdomain.com
• Shodan.io and Censys.io zoomeye.org
• Internet-wide portscans
• Certificate searches
• Shodan query examples:
   ◇ org:”Target Name”
   ◇ net:”CIDR Range”
   ◇ port:”443”
• DNS Brute Forcing
• Performs lookups on a list of potential subdomains
• Make sure to use quality lists
• SecLists: https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS
• MX Records can help us identify cloud services in use
   ◇ O365 = target-domain.mail.protection.outlook.com
   ◇ G-Suite = google.com | googlemail.com
   ◇ Proofpoint = pphosted.com
• If you find commonalities between subdomains try iterating names
•  Other Services
   ◇ HackerTarget https://hackertarget.com/
   ◇ ThreatCrowd  https://www.threatcrowd.org/
   ◇ DNSDumpster  https://dnsdumpster.com/
   ◇ ARIN Searches  https://whois.arin.net/ui/
      ▪ Search bar accepts wild cards “*”
      ▪ Great for finding other netblocks owned by the same organization
• Azure Netblocks
      ▪ Public: https://www.microsoft.com/en-us/download/details.aspx?id=56519
      ▪ US Gov: http://www.microsoft.com/en-us/download/details.aspx?id=57063
      ▪ Germany: http://www.microsoft.com/en-us/download/details.aspx?id=57064
      ▪ China: http://www.microsoft.com/en-us/download/details.aspx?id=57062
• AWS Netblocks
   ◇ https://ip-ranges.amazonaws.com/ip-ranges.json
• GCP Netblocks
   ◇ Google made it complicated so there’s a script on the next page to get the current IP netblocks.
• Box.com Usage
   ◇ Look for any login portals
      ▪ https://companyname.account.box.com
   ◇ Can find cached Box account data too 
• Employees
   ◇ LinkedIn
   ◇ PowerMeta https://github.com/dafthack/PowerMeta
   ◇ FOCA https://github.com/ElevenPaths/FOCA
   ◇ hunter.io

 Tools:
    • Recon-NG https://github.com/lanmaster53/recon-ng
    • OWASP Amass https://github.com/OWASP/Amass
    • Spiderfoot https://www.spiderfoot.net/
    • Gobuster https://github.com/OJ/gobuster
    • Sublist3r https://github.com/aboul3la/Sublist3r

Foothold:
• Find ssh keys in shhgit.darkport.co.uk https://github.com/eth0izzle/shhgit
• GitLeaks https://github.com/zricethezav/gitleaks
• Gitrob https://github.com/michenriksen/gitrob
• Truffle Hog https://github.com/dxa4481/truffleHog

Password attacks:
• Password Spraying
   ◇ Trying one password for every user at an org to avoid account lockouts (Spring2020)
• Most systems have some sort of lockout policy
   ◇ Example: 5 attempts in 30 mins = lockout
• If we attempt to auth as each individual username one time every 30 mins we lockout nobody
• Credential Stuffing
   ◇ Using previously breached credentials to attempt to exploit password reuse on corporate accounts
• People tend to reuse passwords for multiple sites including corporate accounts
• Various breaches end up publicly posted
• Search these and try out creds
• Try iterating creds

Web server explotation
• Out-of-date web technologies with known vulns
• SQL or command injection vulns
• Server-Side Request Forgery (SSRF)
• Good place to start post-shell:
• Creds in the Metadata Service
• Certificates
• Environment variables
• Storage accounts
• Reused access certs as private keys on web servers
   ◇ Compromise web server
   ◇ Extract certificate with Mimikatz
   ◇ Use it to authenticate to Azure
• Mimikatz can export “non-exportable” certificates:
    mimikatz# crypto::capi
    mimikatz# privilege::debug
    mimikatz# crypto::cng
    mimikatz# crypto::certificates /systemstore:local_machine /store:my /export

Phising
• Phishing is still the #1 method of compromise
• Target Cloud engineers, Developers, DevOps, etc.
• Two primary phishing techniques:
   ◇ Cred harvesting / session hijacking
   ◇ Remote workstation compromise w/ C2
• Attack designed to steal creds and/or session cookies
• Can be useful when security protections prevent getting shells
• Email a link to a target employee pointing to cloned auth portal
   ◇ Examples: Microsoft Online (O365, Azure, etc.), G-Suite, AWS Console
• They auth and get real session cookies… we get them too.

Phishing: Remote Access
• Phish to compromise a user’s workstation
• Enables many other options for gaining access to cloud resources
• Steal access tokens from disk
• Session hijack
• Keylog
• Web Config and App Config files
   ◇ Commonly found on pentests to include cleartext creds
   ◇ WebApps often need read/write access to cloud storage or DBs
   ◇ Web.config and app.config files might contain creds or access tokens
   ◇ Look for management cert and extract to pfx like publishsettings files
   ◇ Often found in root folder of webapp
• Internal Code Repositories
   ◇ Gold mine for keys
   ◇ Find internal repos:
      ▪ A. Portscan internal web services (80, 443, etc.) then use EyeWitness to screenshot each service to quickly analyze
      ▪ B. Query AD for all hostnames, look for subdomains git, code, repo, bitbucket, gitlab, etc..
   ◇ Can use automated tools (gitleaks, trufflehog, gitrob) or use built-in search features
      ▪ Search for AccessKey, AKIA, id_rsa, credentials, secret, password, and token
• Command history
• The commands ran previously may indicate where to look
• Sometimes creds get passed to the command line
• Linux hosts command history is here:
   ◇ ~/.bash_history
• PowerShell command history is here:
   ◇ %USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

Post-Compromise Recon
• Who do we have access as?
• What roles do we have?
• Is MFA enabled?
• What can we access (webapps, storage, etc.?)
• Who are the admins?
• How are we going to escalate to admin?
• Any security protections in place (ATP, GuardDuty, etc.)?

Service metadata summary
AWS
http://169.254.169.254/metadata/v1/*
Google Cloud
http://metadata.google.internal/computeMetadata/v1/*
DigitalOcean 
http://169.254.169.254/metadata/v1/*
Docker 
http://127.0.0.1:2375/v1.24/containers/json
Kubernetes ETCD 
http://127.0.0.1:2379/v2/keys/?recursive=true
Alibaba Cloud
http://100.100.100.200/latest/meta-data/*
Microsoft Azure
http://169.254.169.254/metadata/v1/*

```

![](<../../.gitbook/assets/image (39).png>)

## Cloud Labs

* AWS Labs&#x20;
  * flaws.cloud&#x20;
  * flaws2.cloud&#x20;
  * https://github.com/OWASP/Serverless-Goat&#x20;
  * https://n0j.github.io/2017/10/02/aws-s3-ctf.html
  * https://github.com/RhinoSecurityLabs/cloudgoat&#x20;
  * https://github.com/appsecco/attacking-cloudgoat2&#x20;
  * https://github.com/m6a-UdS/dvca&#x20;
  * https://github.com/OWASP/DVSA&#x20;
  * https://github.com/nccgroup/sadcloud&#x20;
  * https://github.com/torque59/AWS-Vulnerable-Lambda
  * https://github.com/wickett/lambhack&#x20;
  * https://github.com/BishopFox/iam-vulnerable&#x20;
* GCP Labs&#x20;
  * http://thunder-ctf.cloud/ https://gcpgoat.joshuajebaraj.com/
* Azure Labs&#x20;
  * https://github.com/azurecitadel/azure-security-lab
