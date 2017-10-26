# Authentication

## Retrieve access token

Issues access and refresh tokens of account. For **OAuth2 Client Credentials Grant** authentication flow client's credentials are used to identify the subject of authentication. If an account hasn't exit yet it will be created.

*NOTE: the operation isn't allowed for disabled accounts*

**URI**

```
POST /auth/${AUTH_KEY}/token
```

**URI parameters**

Name      | Type   | Default    | Description
--------- | ------ | ---------- | ------------------
AUTH\_KEY | string | _required_ | Authentication key (follows `${PROTOCOL}.${PROVIDER}` convention)

**Payload**

Name          | Type   | Default    | Description
------------- | ------ | ---------- | ------------------
grant\_type   | string | _required_ | Always `client_credentials`
client\_token | string | _required_ | Client credentials

**Response**

Name           | Type   | Default    | Description
-------------- | ------ | ---------- | ------------------
access\_token  | string | _required_ | Used for account identification
refresh\_token | string | _required_ | Used to refresh the access token, never expires
expires\_in    | string | _required_ | Expiration time of access token
token\_type    | string | _required_ | Always `Bearer`

**Example**

```bash
## www-form payload
curl -fsSL \
    -XPOST ${ENDPOINT}/auth/oauth2.example/token \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d "grant_type=client_credentials&client_token=${CLIENT_TOKEN}" \
    | jq '.'
 
## JSON payload
curl -fsSL \
    -XPOST ${ENDPOINT}/auth/oauth2.example/token \
    -H 'Content-Type: application/json' \
    -d "{\"grant_type\":\"client_credentials\",\"client_token\":\"${CLIENT_TOKEN}\"}" \
    | jq '.'
 
{
  "access_token": "eyJhbGci...",
  "refresh_token": "eyJhbGci...",
  "expires_in": 86400,
  "token_type": "Bearer"
}
```



## Refresh access token

Issues a new access token of account. A previously issued refresh token is used to identify the subject of authentication.

*NOTE: the operation isn't allowed for disabled accounts*

**URI**

```
POST /accounts/${KEY}/refresh
```

**URI parameters**

Name      | Type   | Default    | Description
--------- | ------ | ---------- | ------------------
KEY       | string | _required_ | Account identifier or `me`

**Response**

Name           | Type   | Default    | Description
-------------- | ------ | ---------- | ------------------
access\_token  | string | _required_ | Used for account identification.
expires\_in    | string | _required_ | Expiration time of access token
token\_type    | string | _required_ | Always `Bearer`

**Example**

```bash
curl -fsSL \
    -XPOST ${ENDPOINT}/accounts/me/refresh \
    -H"Authorization: Bearer ${REFRESH_TOKEN}" \
    | jq '.'
 
{
  "access_token": "eyJhbGci...",
  "expires_in": 86400,
  "token_type": "Bearer"
}
```



## Revoke refresh token

Revokes the old refresh token and issues a new one.

*NOTE: the operation isn't allowed for disabled accounts*

**URI**

```
POST /accounts/${KEY}/revoke
```

**URI parameters**

Name      | Type   | Default    | Description
--------- | ------ | ---------- | ------------------
KEY       | string | _required_ | Account identifier or `me`

**Response**

Name           | Type   | Default    | Description
-------------- | ------ | ---------- | ------------------
refresh\_token | string | _required_ | Used to refresh the access token, never expires

**Example**

```bash
curl -fsSL \
    -XPOST ${ENDPOINT}/accounts/me/revoke \
    -H"Authorization: Bearer ${REFRESH_TOKEN}" \
    | jq '.'
 
{
  "refresh_token": "eyJhbGci..."
}
```



## Add client's identity

Add another client's identity to the account.

*NOTE: the operation isn't allowed for disabled accounts*

**URI**

```
POST /auth/${KEY}/link
```

**URI parameters**

Name      | Type   | Default    | Description
--------- | ------ | ---------- | ------------------
KEY       | string | _required_ | Account identifier or `me`

**Payload**

Name          | Type   | Default    | Description
------------- | ------ | ---------- | ------------------
grant\_type   | string | _required_ | Always `client_credentials`
client\_token | string | _required_ | Client credentials

**Response**

Name           | Type   | Default    | Description
-------------- | ------ | ---------- | ------------------
id             | string | _required_ | Client's identity identifier

**Example**

```bash
## www-form payload
curl -fsSL \
    -XPOST ${ENDPOINT}/auth/oauth2.example/link \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d "grant_type=client_credentials&client_token=${CLIENT_TOKEN}" \
    | jq '.'
 
## JSON payload
curl -fsSL \
    -XPOST ${ENDPOINT}/auth/oauth2.example/link \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    -H 'Content-Type: application/json' \
    -d '{"grant_type":"client_credentials","client_token":"${CLIENT_TOKEN}"}' \
    | jq '.'
 
{
  "id": "oauth2.example.123"
}
```



## List client's identities

Returns list of client's identities previously added to the account.

**URI**

```
GET /accounts/${KEY}/auth
```

**URI parameters**

Name      | Type   | Default    | Description
--------- | ------ | ---------- | ------------------
KEY       | string | _required_ | Account identifier or `me`

**Response**

List of client's identities.

**Example**

```bash
curl -fsSL \
    -XGET ${ENDPOINT}/accounts/me/auth \
    -H"Authorization: Bearer ${ACCESS_TOKEN}" \
    | jq '.'

[
  {
    "id": "oauth2.example.123"
  }
]
```



## Delete client's identity

Removes the client's identity.

*NOTE: the operation isn't allowed for disabled accounts*

**URI**

```
DELETE /accounts/${KEY}/auth/${IDENTITY}
```

**URI parameters**

Name      | Type   | Default    | Description
--------- | ------ | ---------- | ------------------
KEY       | string | _required_ | Account identifier or `me`
IDENTITY  | string | _required_ | Client's identity identifier

**Response**

Removed client's identity.

**Example**

```bash
curl -fsSL \
    -XDELETE ${ENDPOINT}/accounts/me/auth/oauth2.example.123 \
    -H"Authorization: Bearer ${ACCESS_TOKEN}" \
    | jq '.'

{
  "id": "oauth2.example.123"
}
```