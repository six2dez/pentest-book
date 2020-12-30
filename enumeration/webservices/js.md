# JS

```text
# JSScanner
# https://github.com/dark-warlord14/JSScanner
# https://securityjunky.com/scanning-js-files-for-endpoint-and-secrets/
bash install.sh
# Configure domain in alive.txt
bash script.sh
cat js/*
cd db && grep -oriahE "https?://[^\"\\'> ]+"

# https://github.com/KathanP19/JSFScan.sh
bash JSFScan.sh -l targets.txt -e -s -m -o 

# https://github.com/bp0lr/linkz

# FindSecrets in JS files
https://github.com/m4ll0k/SecretFinder
python3 SecretFinder.py -i https://example.com/1.js -o results.html

# Js vuln scanner, like retire.js with crawling
https://github.com/callforpapers-source/jshole

# get Shell from xss
https://github.com/shelld3v/JSshell

# Find JS sourcemap
1) Find JavaScript files
2) ffuf -w js_files.txt -u FUZZ -mr "sourceMappingURL"
3) Download sourcemap
4) https://github.com/chbrown/unmap
5) Browse configs or just grep for API keys/Creds
```

