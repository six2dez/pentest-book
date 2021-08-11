# iOS

```bash
# All about Jailbreak & iOS versions
https://www.theiphonewiki.com/wiki/Jailbreak

# Checklist
https://mobexler.com/checklist.htm#ios

# Jailbreak for iPhone 5s though iPhone X, iOS 12.3 and up
# https://checkra.in/
checkra1n 

# 3UTools
http://www.3u.com/

# Cydia
# Liberty Bypass Antiroot

# To check:
# https://github.com/Soulghost/iblessing

# Check Info Stored:
3U TOOLS - SSH Tunnel

# Analyzing binary:
# Get .ipa
# unzip example.ipa
# Locate binary file (named as the app usually)

# Check encryption
otool –l BINARY | grep –A 4 LC_ENCRYPTION_INFO
# If returned "cryptid 1" ipa is encrypted, good for them

# Check dynamic dependencies
otool –L BINARY

# SSL Bypass
# https://github.com/evilpenguin/SSLBypass

find /data/app -type f -exec grep --color -Hsiran "FINDTHIS" {} \;
find /data/app -type f -exec grep --color -Hsiran "\"value\":\"" {} \;

.pslist= "value":"base64"}

find APPPATH -iname "*localstorage-wal" -> Check manually

# Extract IPA from installed app
ls -lahR /var/containers/Bundle/Application/ | grep -B 2 -i 'appname' # To find app ID
scp -r root@127.0.0.1:/var/containers/Bundle/Application/{ID} LOCAL_PATH
mkdir Payload
cp -r appname.app/ Payload/
zip -r app.ipa Payload/

# Interesting locations
/private/var/mobile/Containers/Data/Application/{HASH}/{BundleID-3uTools-getBundelID}
/private/var/containers/Bundle/Application/{HASH}/{Nombre que hay dentro del IPA/Payloads}
/var/containers/Bundle/Application/{HASH}
/var/mobile/Containers/Data/Application/{HASH}
/var/mobile/Containers/Shared/AppGroup/{HASH}
```

![](../.gitbook/assets/image%20%2821%29.png)

