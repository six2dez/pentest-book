# Firebase

## Tools

```text
# https://github.com/Turr0n/firebase
python3 firebase.py -p 4 --dnsdumpster -l file

# https://github.com/MuhammadKhizerJaved/Insecure-Firebase-Exploit
Firebase_Exploit.py

# https://github.com/viperbluff/Firebase-Extractor
firebase.py xyz.firebaseio.com
```

```python
# Python conector
# https://github.com/thisbejim/Pyrebase

import pyrebase

config = {
  "apiKey": "FIREBASE_API_KEY",
  "authDomain": "FIREBASE_AUTH_DOMAIN_ID.firebaseapp.com",
  "databaseURL": "https://FIREBASE_AUTH_DOMAIN_ID.firebaseio.com",
  "storageBucket": "FIREBASE_AUTH_DOMAIN_ID.appspot.com",
}

firebase = pyrebase.initialize_app(config)

db = firebase.database()

print(db.get())
```

