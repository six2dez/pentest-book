# IIS



```text
# Reminder:
Case insensitive
IIS Shortname
VIEWSTATE deserialization RCE gadget
Web.config upload tricks
Debug mode w/ detailed stack traces and full path
Debugging scripts often deployed (ELMAH, Trace)
Telerik RCE

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
# https://github.com/liquidsec/pyOracle2

# Look for web.config or web.xml
https://x.x.x.x/.//WEB-INF/web.xml

# ASP - force error paths
/con/
/aux/
con.aspx
aux.aspx

# HTTPAPI 2.0 404 Error
Change Host header to correct subdomain
Add to /etc/hosts
Scan again including IIS Shortnames

# IIS 7
IIS Short Name scanner
HTTP.sys DOS RCE

# ViewState
# https://github.com/0xacb/viewgen
```

