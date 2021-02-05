# Deserialization

{% hint style="info" %}
Insecure deserialization is when user-controllable data is deserialized by a website. This potentially enables an attacker to manipulate serialized objects in order to pass harmful data into the application code.

Objects of any class that is available to the website will be deserialized and instantiated, regardless of which class was expected. An object of an unexpected class might cause an exception. By this time, however, the damage may already be done. Many deserialization-based attacks are completed before deserialization is finished. This means that the deserialization process itself can initiate an attack, even if the website's own functionality does not directly interact with the malicious object.
{% endhint %}

## Vulnerable functions

```text
# PHP
unserialize()

# Python
pickle/c_pickle/_pickle with load/loads
PyYAML with load
jsonpickle with encode or store methods>/tmp/f

# Java
# Whitebox
XMLdecoder with external user defined parameters
XStream with fromXML method (xstream version <= v1.46 is vulnerable to the serialization issue)
ObjectInputStream with readObject
Uses of readObject, readObjectNodData, readResolve or readExternal
ObjectInputStream.readUnshared
Serializable
# Blackbox
AC ED 00 05 in Hex
rO0 in Base64
Content-type: application/x-java-serialized-object
# ysoserial
java -jar ysoserial.jar CommonsCollections4 'command'

# .Net
# Whithebox
TypeNameHandling
JavaScriptTypeResolver
# Blackbox
AAEAAAD/////
TypeObject
$type
```

## Tools

```text
# Java
# Ysoserial: https://github.com/frohoff/ysoserial
java -jar ysoserial.jar CommonsCollections4 'command'
# Java Deserialization Scanner: https://github.com/federicodotta/Java-Deserialization-Scanner
# SerialKiller: https://github.com/ikkisoft/SerialKiller
# Serianalyzer: https://github.com/mbechler/serianalyzer
# Java Unmarshaller Security: https://github.com/mbechler/marshalsec
# Java Serial Killer: https://github.com/NetSPI/JavaSerialKiller
# Android Java Deserialization Vulnerability Tester: https://github.com/modzero/modjoda

# .NET
# Ysoserial.net: https://github.com/pwntester/ysoserial.net
ysoserial.exe -g ObjectDataProvider -f Json.Net -c “command-here” -o base64

# Burp-Plugins
# Java: https://github.com/DirectDefense/SuperSerial
# Java: https://github.com/DirectDefense/SuperSerial-Active
# Burp-ysoserial: https://github.com/summitt/burp-ysoserial
```



