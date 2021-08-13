# Code review

## General

```bash
# Guidelines
https://rules.sonarsource.com/

https://www.sonarqube.org/downloads/
https://deepsource.io/signup/
https://github.com/pyupio/safety
https://github.com/returntocorp/semgrep
https://github.com/WhaleShark-Team/cobra
https://github.com/mhaskar/Bughound

# Find interesting strings
https://github.com/s0md3v/hardcodes
https://github.com/micha3lb3n/SourceWolf
https://libraries.io/pypi/detect-secrets

# Tips
1.Important functions first
2.Follow user input
3.Hardcoded secrets and credentials
4.Use of dangerous functions and outdated dependencies
5.Developer comments, hidden debug functionalities, configuration files, and the .git directory
6.Hidden paths, deprecated endpoints, and endpoints in development
7.Weak cryptography or hashing algorithms
8.Missing security checks on user input and regex strength
9.Missing cookie flags
10.Unexpected behavior, conditionals, unnecessarily complex and verbose functions
```

## JavaScript

```text
https://jshint.com/
https://github.com/jshint/jshint/
```

## NodeJS

```text
https://github.com/ajinabraham/nodejsscan
```

## Electron

```text
https://github.com/doyensec/electronegativity
https://github.com/doyensec/awesome-electronjs-hacking
```

## Python

```text
# bandit
https://github.com/PyCQA/bandit
# pyt
https://github.com/python-security/pyt
# atheris
https://github.com/google/atheris
# aura
https://github.com/SourceCode-AI/aura
```

## .NET

```text
# dnSpy
https://github.com/0xd4d/dnSpy

# .NET compilation
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe test.cs

# Cheatsheet
https://www.c-sharpcorner.com/UploadFile/ajyadav123/net-penetration-testing-cheat-sheet/
```

## PHP

```text
# phpvuln
https://github.com/ecriminal/phpvuln
```

## C/C++

```text
# flawfinder
https://github.com/david-a-wheeler/flawfinder
```

## Java

```text
# JD-Gui
https://github.com/java-decompiler/jd-gui

# Java compilation step-by-step
javac -source 1.8 -target 1.8 test.java
mkdir META-INF
echo "Main-Class: test" > META-INF/MANIFEST.MF
jar cmvf META-INF/MANIFEST.MF test.jar test.class
```

| Task | Command |
| :--- | :--- |
| Execute Jar | java -jar \[jar\] |
| Unzip Jar | unzip -d \[output directory\] \[jar\] |
| Create Jar | jar -cmf META-INF/MANIFEST.MF \[output jar\] \* |
| Base64 SHA256 | sha256sum \[file\] \| cut -d' ' -f1 \| xxd -r -p \| base64 |
| Remove Signing | rm META-INF/_.SF META-INF/_.RSA META-INF/\*.DSA |
| Delete from Jar | zip -d \[jar\] \[file to remove\] |
| Decompile class | procyon -o . \[path to class\] |
| Decompile Jar | procyon -jar \[jar\] -o \[output directory\] |
| Compile class | javac \[path to .java file\] |

