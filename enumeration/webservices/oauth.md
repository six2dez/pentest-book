# OAuth

## Explanation

```
# OAuth 2.0
https://oauth.net/2/
https://oauth.net/2/grant-types/authorization-code/

Flow:

1. MyWeb tried integrate with Twitter.
2. MyWeb request to Twitter if you authorize.
3. Prompt with a consent.
4. Once accepted Twitter send request redirect_uri with code and state.
5. MyWeb take code and it's own client_id and client_secret and ask server for access_token.
6. MyWeb call Twitter API with access_token.

Definitions:

- resource owner: The resource owner is the user/entity granting access to their protected resource, such as their Twitter account Tweets
- resource server: The resource server is the server handling authenticated requests after the application has obtained an access token on behalf of the resource owner . In the above example, this would be https://twitter.com
- client application: The client application is the application requesting authorization from the resource owner. In this example, this would be https://yourtweetreader.com.
- authorization server: The authorization server is the server issuing access tokens to the client application after successfully authenticating the resource owner and obtaining authorization. In the above example, this would be https://twitter.com
- client_id: The client_id is the identifier for the application. This is a public, non-secret unique identifier.
- client_secret: The client_secret is a secret known only to the application and the authorization server. This is used to generate access_tokens
- response_type: The response_type is a value to detail which type of token is being requested, such as code
- scope: The scope is the requested level of access the client application is requesting from the resource owner
- redirect_uri: The redirect_uri  is the URL the user is redirected to after the authorization is  complete. This usually must match the redirect URL that you have  previously registered with the service
- state: The state  parameter can persist data between the user being directed to the  authorization server and back again. It’s important that this is a  unique value as it serves as a CSRF protection mechanism if it contains a  unique or random value per request
- grant_type: The grant_type parameter explains what the grant type is, and which token is going to be returned
- code: This code is the authorization code received from the authorization server which will be in the query string parameter “code” in this request. This code is used in conjunction with the client_id and client_secret by the client application to fetch an access_token
- access_token: The access_token is the token that the client application uses to make API requests on behalf of a resource owner
- refresh_token: The refresh_token allows an application to obtain a new access_token without prompting the user
```

## Bugs

```
# Weak redirect_uri
1. Alter the redirect_uri URL with TLD aws.console.amazon.com/myservice -> aws.console.amazon.com
2. Finish OAuth flow and check if you're redirected to the TLD, then is vulnerable
3. Check your redirect is not to Referer header or other param

https://yourtweetreader.com/callback?redirectUrl=https://evil.com
https://www.target01.com/api/OAUTH/?next=https://www.target01.com//evil.com/
https://www.target01.com/api/OAUTH?next=https://www.target01.com%09.evil.com
https://www.target01.com/api/OAUTH/?next=https://www.target01.com%252e.evil.com
https://www.target01.com/api/OAUTH/?next=https://www.target01.com/project/team
http://target02.com/oauth?redirect_uri=https://evil.com[.target02.com/
https://www.target01.com/api/OAUTH/?next=https://yourtweetreader.com.evil.com
https://www.target.com/endpoint?u=https://EVILtwitter.com/

ffuf -w words.txt -u https://www.target.com/endpoint?u=https://www.FUZZ.com/ 

# Path traversal: https://yourtweetreader.com/callback/../redirect?url=https://evil.com

# HTML Injection and stealing tokens via referer header
Check referer header in the requests for sensitive info
   
# Access Token Stored in Browser History
Check browser history for sensitive info

# Improper handling of state parameter
Check lack of state parameter and is in url params and is passed to all the flow
Verifying State entropy
Check state is not reused
Remove state and URI and check request is invalid

# Access Token Stored in JavaScript

# Lack of verification
If not email verification is needed in account creation, register before the victim.
If not email verification in Oauth signing, register other app before the victim.

# Access token passed in request body
If the access token is passed in the request body at the time of allocating the access token to the web application there arises an attack scenario. 
An attacker can create a web application and register for an Oauth framework with a provider such as twitter or facebook. The attacker uses it as a malicious app for gaining access tokens. 
For example, a Hacker can build his own facebook app and get victim’s facebook access token and use that access token to login into victim account.

# Reusability of an Oauth access token
Replace the new Oauth access token with the old one and continue to the application. This should not be the case and is considered as a very bad practice.
```

## OAuth resources

```
https://owasp.org/www-pdf-archive/20151215-Top_X_OAuth_2_Hacks-asanso.pdf
https://medium.com/@lokeshdlk77/stealing-facebook-mailchimp-application-oauth-2-0-access-token-3af51f89f5b0
https://medium.com/a-bugz-life/the-wondeful-world-of-oauth-bug-bounty-edition-af3073b354c1
https://gauravnarwani.com/misconfigured-oauth-to-account-takeover/
https://medium.com/@Jacksonkv22/oauth-misconfiguration-lead-to-complete-account-takeover-c8e4e89a96a
https://medium.com/@logicbomb_1/bugbounty-user-account-takeover-i-just-need-your-email-id-to-login-into-your-shopping-portal-7fd4fdd6dd56
https://medium.com/@protector47/full-account-takeover-via-referrer-header-oauth-token-steal-open-redirect-vulnerability-chaining-324a14a1567
https://hackerone.com/reports/49759
https://hackerone.com/reports/131202
https://hackerone.com/reports/6017
https://hackerone.com/reports/7900
https://hackerone.com/reports/244958
https://hackerone.com/reports/405100
https://ysamm.com/?p=379
https://www.amolbaikar.com/facebook-oauth-framework-vulnerability/
https://medium.com/@godofdarkness.msf/mail-ru-ext-b-scope-account-takeover-1500-abdb1560e5f9
https://medium.com/@tristanfarkas/finding-a-security-bug-in-discord-and-what-it-taught-me-516cda561295
https://medium.com/@0xgaurang/case-study-oauth-misconfiguration-leads-to-account-takeover-d3621fe8308b
https://medium.com/@rootxharsh_90844/abusing-feature-to-steal-your-tokens-f15f78cebf74
http://blog.intothesymmetry.com/2014/02/oauth-2-attacks-and-bug-bounties.html
http://blog.intothesymmetry.com/2015/04/open-redirect-in-rfc6749-aka-oauth-20.html
https://www.veracode.com/blog/research/spring-social-core-vulnerability-disclosure
https://medium.com/@apkash8/oauth-and-security-7fddce2e1dc5
https://xploitprotocol.medium.com/exploiting-oauth-2-0-authorization-code-grants-379798888893
```

## OAuth scheme

![](<../../.gitbook/assets/imagen (5).png>)

## Code grant flow

![](<../../.gitbook/assets/imagen (4).png>)

## OAuth Attack mindmap

![](../../.gitbook/assets/photo\_2020-06-08\_07-24-17.jpg)

