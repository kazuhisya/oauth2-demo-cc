# OAuth2 demo server

for Client Credentials Grant

```
$ curl "http://localhost:9096/token?grant_type=client_credentials&client_id=000000&client_secret=123456&scope=tmp" | jq
{
  "access_token": "2F4759L4MYUGAZERVF7H9Q",
  "expires_in": 120,
  "scope": "tmp",
  "token_type": "Bearer"
}
```

```
$ curl "http://localhost:9096/test?access_token=2F4759L4MYUGAZERVF7H9Q" | jq
{
  "client_id": "000000",
  "expires_in": 102,
  "scope": "tmp"
}
```
