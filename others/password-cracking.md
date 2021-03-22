# Password cracking

## Identify hash

```bash
hash-identifier
hashid
nth
gth
```

## jtr

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
john --rules --wordlist=/usr/share/wordlists/rockyou.txt hash
```

## Hashcat

### Wiki

{% embed url="https://hashcat.net/wiki/doku.php?id=hashcat" %}

### Hashes

{% embed url="https://openwall.info/wiki/john/sample-hashes" %}

{% embed url="https://hashcat.net/wiki/doku.php?id=example\_hashes" %}

### Examples

```bash
# Dictionary
hashcat -m 0 -a 0 hashfile dictionary.txt -O --user -o result.txt

# Dictionary + rules
hashcat -m 0 -w 3 -a 0 hashfile dictionary.txt -O -r haku34K.rule --user -o result.txt

# Mask bruteforce (length 1-8 A-Z a-z 0-9)
hashcat -m 0 -w 3 -a 3 hashfile ?1?1?1?1?1?1?1?1 --increment -1 --user ?l?d?u
hashcat -m 0 -w 3 -a 3 hashfile suffix?1?1?1 -i -1 --user ?l?d

# Modes
-a 0 = Dictionary (also with rules)
-a 3 = Bruteforce with mask 

# Max performance options
--force -O -w 3 --opencl-device-types 1,2

# Output results
-o result.txt

# Ignore usernames in hashfile
--user/--username

# Masks
?l = abcdefghijklmnopqrstuvwxyz
?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
?d = 0123456789
?s = «space»!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
?a = ?l?u?d?s
?b = 0x00 - 0xff
```

### Useful hashes

#### Linux Hashes - /etc/shadow

| ID | Description |
| :--- | :--- |
| 500 | md5crypt $1$, MD5\(Unix\) |
| 200 | bcrypt $2\*$, Blowfish\(Unix\) |
| 400 | sha256crypt $5$, SHA256\(Unix\) |
| 1800 | sha512crypt $6$, SHA512\(Unix\) |

#### Windows Hashes

| ID | Description |
| :--- | :--- |
| 3000 | LM |
| 1000 | NTLM |

#### Common Hashes

| ID | Description | Type |
| :--- | :--- | :--- |
| 900 | MD4 | Raw Hash |
| 0 | MD5 | Raw Hash |
| 5100 | Half MD5 | Raw Hash |
| 100 | SHA1 | Raw Hash |
| 10800 | SHA-384 | Raw Hash |
| 1400 | SHA-256 | Raw Hash |
| 1700 | SHA-512 | Raw Hash |

#### Common Files with password

| ID | Description |
| :--- | :--- |
| 11600 | 7-Zip |
| 12500 | RAR3-hp |
| 13000 | RAR5 |
| 13200 | AxCrypt |
| 13300 | AxCrypt in-memory SHA1 |
| 13600 | WinZip |
| 9700 | MS Office &lt;= 2003 $0/$1, MD5 + RC4 |
| 9710 | MS Office &lt;= 2003 $0/$1, MD5 + RC4, collider \#1 |
| 9720 | MS Office &lt;= 2003 $0/$1, MD5 + RC4, collider \#2 |
| 9800 | MS Office &lt;= 2003 $3/$4, SHA1 + RC4 |
| 9810 | MS Office &lt;= 2003 $3, SHA1 + RC4, collider \#1 |
| 9820 | MS Office &lt;= 2003 $3, SHA1 + RC4, collider \#2 |
| 9400 | MS Office 2007 |
| 9500 | MS Office 2010 |
| 9600 | MS Office 2013 |
| 10400 | PDF 1.1 - 1.3 \(Acrobat 2 - 4\) |
| 10410 | PDF 1.1 - 1.3 \(Acrobat 2 - 4\), collider \#1 |
| 10420 | PDF 1.1 - 1.3 \(Acrobat 2 - 4\), collider \#2 |
| 10500 | PDF 1.4 - 1.6 \(Acrobat 5 - 8\) |
| 10600 | PDF 1.7 Level 3 \(Acrobat 9\) |
| 10700 | PDF 1.7 Level 8 \(Acrobat 10 - 11\) |
| 16200 | Apple Secure Notes |

#### Database Hashes

| ID | Description | Type | Example Hash |
| :--- | :--- | :--- | :--- |
| 12 | PostgreSQL | Database Server | a6343a68d964ca596d9752250d54bb8a:postgres |
| 131 | MSSQL \(2000\) | Database Server | 0x01002702560500000000000000000000000000000000000000008db43dd9b1972a636ad0c7d4b8c515cb8ce46578 |
| 132 | MSSQL \(2005\) | Database Server | 0x010018102152f8f28c8499d8ef263c53f8be369d799f931b2fbe |
| 1731 | MSSQL \(2012, 2014\) | Database Server | 0x02000102030434ea1b17802fd95ea6316bd61d2c94622ca3812793e8fb1672487b5c904a45a31b2ab4a78890d563d2fcf5663e46fe797d71550494be50cf4915d3f4d55ec375 |
| 200 | MySQL323 | Database Server | 7196759210defdc0 |
| 300 | MySQL4.1/MySQL5 | Database Server | fcf7c1b8749cf99d88e5f34271d636178fb5d130 |
| 3100 | Oracle H: Type \(Oracle 7+\) | Database Server | 7A963A529D2E3229:3682427524 |
| 112 | Oracle S: Type \(Oracle 11+\) | Database Server | ac5f1e62d21fd0529428b84d42e8955b04966703:38445748184477378130 |
| 12300 | Oracle T: Type \(Oracle 12+\) | Database Server | 78281A9C0CF626BD05EFC4F41B515B61D6C4D95A250CD4A605CA0EF97168D670EBCB5673B6F5A2FB9CC4E0C0101E659C0C4E3B9B3BEDA846CD15508E88685A2334141655046766111066420254008225 |
| 8000 | Sybase ASE | Database Server | 0xc00778168388631428230545ed2c976790af96768afa0806fe6c0da3b28f3e132137eac56f9bad027ea2 |

#### Kerberos Hashes

| ID | Type | Example |
| :--- | :--- | :--- |
| 13100 | Type 23 | $krb5tgs$23$ |
| 19600 | Type 17 | $krb5tgs$17$ |
| 19700 | Type 18 | $krb5tgs$18$ |
| 18200 | ASREP Type 23 | $krb5asrep$23$ |

## Files

```bash
https://github.com/kaonashi-passwords/Kaonashi
https://github.com/NotSoSecure/password_cracking_rules
https://crackstation.net/files/crackstation-human-only.txt.gz
https://crackstation.net/files/crackstation.txt.gz
```

