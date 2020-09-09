# Web Cache Deception

{% hint style="info" %}
These preconditions can be exploited for the Web Cache Deception attack in the following manner:

* Step 1: An attacker entices the victim to open a maliciously crafted link:

  `https://www.example.com/my_profile/test.jpg`

  The application ignores the 'test.jpg' part of the URL, the victim profile page is loaded. The caching mechanism identifies the resource as an image, caching it.

* Step 2: The attacker sends a GET request for the cached page:

  `https://www.example.com/my_profile/test.jpg`

  The cached resource, which is in fact the victim profile page is returned to the attacker \(and to anyone else requesting it\).
{% endhint %}

