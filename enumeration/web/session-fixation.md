# Session fixation

{% hint style="info" %}
**Steps to reproduce**

1. Open example.com/login.
2. Open browser devtools.
3. Get value for `SESSION` cookie.
4. Open example.com/login in the incognito tab.
5. In the incognito tab, change cookie value to the one, obtained in step 3.
6. In the normal tab \(the one from steps 1-3\) log in as any user.
7. Refresh page in the incognito tab.

**Result**

You are now logged in the incognito tab as user from step 6 as well.
{% endhint %}

