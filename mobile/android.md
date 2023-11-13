# Android

## Tools

### Extract

```
# Jadx - decompiler gui
jadx-gui
# Jadx - decomp cli (with deobf)
jadx -d path/to/extract/ --deobf app_name.apk

# Apkx decompiler
apkx example.apk 

# Apktool
apktool d app_name.apk
```

### Get sensitive info

```
# Urls and secrets
# https://github.com/dwisiswant0/apkleaks
python apkleaks.py -f ~/path/to/file.apk

# Analyze URLs in apk:
# https://github.com/shivsahni/APKEnum
python APKEnum.py -p ~/Downloads/app-debug.apk

# Quick wins tool (go branch)
# https://github.com/mzfr/slicer
slicer -d path/to/extact/apk

# Unpack apk and find interesting strings
apktool d app_name.apk
cd apk_folder
grep -EHirn "accesskey|admin|aes|api_key|apikey|checkClientTrusted|crypt|http:|https:|password|pinning|secret|SHA256|SharedPreferences|superuser|token|X509TrustManager|insert into"
grep -Phro "(https?://)[\w\.-/]+[\"'\`]" | sed 's#"##g' | anew | grep -v "w3\|android\|github\|http://schemas.android\|google\|http://goo.gl"

# Apk analyzer
# https://github.com/Cyber-Buddy/APKHunt

# Regex FCM Server Keys for push notification services control
AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}
AIza[0-9A-Za-z_-]{35}

# FCM Google Server Keys Validation
# https://github.com/adarshshetty18/fcm_server_key
python3 fcmserverkey.py file.apk

# Facebook Static Analysis Tool
https://github.com/facebook/mariana-trench/

# Manifest.xml findings:
android:allowBackup = TRUE
android:debuggable = TRUE
andorid:exported= TRUE or not set (within <provider>-Tag) --> allows external app to access data
android.permission.WRITE_EXTERNAL_STORAGE / READ_EXTERNAL_STORAGE (ONLY IF sensitive data was stored/read externally)
Use of permissions
            e.g. the app opens website in external browser (not inApp), however requires "android.permission.INTERNET" --> false usage of permissions. (over-privileged)
            "android:protectionLevel" was not set properly (<permission android:name="my_custom_permission_name" android:protectionLevel="signature"/>)
            missing android:permission (permission tags limit exposure to other apps)
```

### Static analyzers

```
# Android Malware Analyzer
# https://github.com/quark-engine/quark-engine
pipenv shell
quark -a test.apk -r rules/ --detail

# Androtickler
https://github.com/ernw/AndroTickler
java -jar AndroTickler.jar

# androbugs.py
python androbugs.py -f /root/android.apk

# MobSF
# https://github.com/MobSF/Mobile-Security-Framework-MobSF

- Findings:
Cleartext credentials (includes base64 encoded or weak encrypted ones)
Credentials cracked (brute-force, guessing, decrypted with stored cryptographic-key, ...)
File permission MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE (other apps/users are able to read/write)
If http is in use (no SSL)
Anything that shouldn't be there (debug info, comments wiht info disclosure, ...)
```

## Manual analysis (adb, frida, objection, etc...)

```
# Good Checklist
https://mobexler.com/checklist.htm#android

# Adb
# https://developer.android.com/studio/command-line/adb?hl=es-419
adb connect IP:PORT/ID
adb devices
adb shell
adb push
adb install
adb shell pm list packages # List all installed packages
adb shell pm path xx.package.name


# DeviceId
adb shell
settings get secure android_id
adb shell sqlite3 /data/data/com.android.providers.settings/databases/settings.db "select value from secure where name = 'android_id'"

# Frida (rooted device method)
# https://github.com/frida/frida/releases
adb root
adb push /root/Downloads/frida-server-12.7.24-android-arm /data/local/tmp/. # Linux
adb push C:\Users\username\Downloads\frida-server-12.8.11-android-arm /data/local/tmp/. # Windows
adb root
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"
frida-ps -U # Check frida running correctly
# Run Frida script
frida -U -f com.vendor.app.version -l PATH\fridaScript.js --no-pause

# Easy way to load Frida Server in Rooted Device
https://github.com/dineshshetty/FridaLoader

# Frida (NON rooted device) a.k.a. patch the apk
# a) Lief injector method
# https://gitlab.com/jlajara/frida-gadget-lief-injector
# b) Objection and dalvik bytecode method
https://github.com/sensepost/objection/wiki/Patching-Android-Applications#patching---patching-an-apk

# Frida resources
https://codeshare.frida.re/
https://github.com/dweinstein/awesome-frida
https://rehex.ninja/posts/frida-cheatsheet/
https://github.com/androidmalware/android_frida_scripts

# Objection
# https://github.com/sensepost/objection
objection --gadget com.vendor.app.xx explore
android sslpinning disable

# Android Backup files (*.ab files)
( printf "\x1f\x8b\x08\x00\x00\x00\x00\x00" ; tail -c +25 backup.ab ) |  tar xfvz -

# Useful apps:
# Xposed Framework
# RootCloak
# SSLUnpinning

# Check Info Stored
find /data/app -type f -exec grep --color -Hsiran "FINDTHIS" {} \;
find /storage/sdcard0/Android/ -maxdepth 7 -exec ls -dl \{\} \;

/data/data/com.app/database/keyvalue.db
/data/data/com.app/database/sqlite
/data/app/
/data/user/0/
/storage/emulated/0/Android/data/
/storage/emulated/0/Android/obb/
/assets
/res/raw
/target/global/Constants.java

# Check logs during app usage
https://github.com/JakeWharton/pidcat

# Download apks
https://apkpure.com
https://apps.evozi.com/apk-downloader/
https://apkcombo.com/
```

### Burp Cert Installation > Android  7.0

```bash
#!/bin/bash
# Export only certificate in burp as DER format
openssl x509 -inform DER -in cacert.der -out cacert.pem
export CERT_HASH=$(openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1)
adb root && adb remount
adb push cacert.pem "/sdcard/${CERT_HASH}.0"
adb shell su -c "mv /sdcard/${CERT_HASH}.0 /system/etc/security/cacerts"
adb shell su -c "chmod 644 /system/etc/security/cacerts/${CERT_HASH}.0"
rm -rf cacert.*
# Reboot device
```

## Tips

```
Recon:
- AndroidManifest.xml (basically a blueprint for the application)
Find exported components, api keys, custom deep link schemas, schema endpoints etc.
- resources.arsc/strings.xml
Developers are encouraged to store strings in this file instead of hard coding in application.
- res/xml/file_paths.xml
Shows file save paths.
- Search source code recursively
Especially BuildConfig files.
- Look for firebase DB:
Decompiled apk: Resources/resources.arsc/res/values/strings.xml, search for "firebsae.io" and try to access:
https://*.firebase.io/.json

API Keys:
- String references in Android Classes
getString(R.string.cmVzb3VyY2VzX3lv)
cmVzb3VyY2VzX3lv is the string resource label.
- Find these string references in strings.xml
apikeyhere
- Piece together the domains and required params in source code

Exported components:
- Activities - Entry points for application interactions of components specified in AndroidManifest.xml.
    Has several states managed by callbacks such as onCreate().
   →  Access to protected intents via exported Activities
    One exported activity that accepts a user provided intent can expose protected intents.
   → Access to sensitive data via exported Activity
    Often combined with deep links to steal data via unvalidated parameters. Write session tokens to an
    external file.
   → Access to sensitive files, stealing files, replacing imported files via exported Activities
    external-files-path, external-path
    Public app directories
   → Look for "content://" in source code
- Service - Supplies additional functionality in the background.
   → Custom file upload service example that is vulnerable because android:exported="true". When exported by third party
  applications can send data to the service or steal sensitive data from applications depending on the services   function. Check if params and intent data can be set with proof of concept application.
- Broadcast receivers - Receives broadcasts from events of interest. Usually specified broadcasted intents in the broadcast receiver activity.
   → Vulnerable when receiver is exported and accepts user provided broadcasts.
   → Any application, including malicious ones, can send an intent to this broadcast receiver causing it to be triggered without any restrictions.
- Content providers - Helps applications manage access to stored data and ways to share data with other Android applications
   → Content providers that connect to sqlite can be exploited via SQL injection by third party apps.

Deep links
- In Android, a deep link is a link that takes you directly to a specific destination within an app.
- Think of deep links as Android urls to specific parts of the application.
- Usually mirrors web application except with a different schema that navigate directory to specific Android activities.
- Verified deep links can only use http and https schemas. Sometimes developers keep custom schemas for testing new
features.
- Type of vulnerabilities are based on how the scheme://, host://, and parameters are validated
   → CSRF - Test when autoVerify=”true” is not present in AndroidManifest.xml It’s easier.
   → Open redirect - Test when custom schemes do not verify endpoint parameters or hosts
   → XSS - Test when endpoint parameters or host not validated, addJavaScriptInterface and
   → setJavascriptEnabled(true); is used.
   → LFI - Test when deep link parameters aren’t validated. appschema://app/goto?file=
   
Database encryption
- Check database is encrypted under /data/data/<package_name>/
- Check in source code for database credentials

Allowed backup
- Lead to sensitive information disclosure
- adb backup com.vendor.app

Logging Enabled
- Check logcat when login and any action performed

Storing Sensitive Data in External Storage
- Check data stored after usage /sdcard/android/data/com.vendor.app/

Weak Hashing Algorithms 
- MD5 is a weak algorythm and have collisions

Predictable Random Number Generator (PRNG)
- The java.util.Random function is predictable

Hard-coded Data
- Hard-coded user authentication information (credentials, PINs, etc.)
- Hard-coded cryptographic keys.
- Hard-coded keys used for encrypted databases.
- Hard-coded API keys/private
- Hard-coded keys that have been encoded or encrypted (e.g. base64 encoded, XOR encrypted, etc.).
- Hard-coded server IP addresses.

Debug Mode enabled
- Start a shell on Android and gain an interactive shell with run-as command
- run-as com.vendor.app
- adb exec-out run-as com.vendor.app cat databases/appName > appNameDB-copy

If you get built-in WebView and try to access:
appscheme://webview?url=https://google.com
appscheme://webview?url=javascript:document.write(document.domain)

If install apk in Genymotion fails with "INSTALL_FAILED_NO_MATCHING_ABIS":
- Apk is compiled only for ARM
- Download zip for your Android version here https://github.com/m9rco/Genymotion_ARM_Translation
- Move zip to VM and flash
https://pentester.land/tips-n-tricks/2018/10/19/installing-arm-android-apps-on-genymotion-devices.html
```

## Mindmaps

![](<../.gitbook/assets/image (47).png>)

![](<../.gitbook/assets/image (38).png>)
