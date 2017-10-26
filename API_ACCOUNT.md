# Account

## Read

Returns the account.

**URI**

```
GET /accounts/${KEY}
```

**URI parameters**

Name      | Type   | Default    | Description
--------- | ------ | ---------- | ------------------
KEY       | string | _required_ | Account identifier or `me`

**Response**

Account

**Example**

```bash
curl -fsSL \
    -XPOST ${ENDPOINT}/accounts/me \
    -H"Authorization: Bearer ${ACCESS_TOKEN}" \
    | jq '.'
 
{
  "id": "9074b6aa-a980-44e9-8973-29501900aa79"
}
```



## Delete

Removes the account.

*NOTE: the operation is only allowed for admins (members of 'admin' predefined group)*

**URI**

```
DELETE /accounts/${KEY}
```

**URI parameters**

Name      | Type   | Default    | Description
--------- | ------ | ---------- | ------------------
KEY       | string | _required_ | Account identifier or `me`

**Response**

Removed account

**Example**

```bash
curl -fsSL \
    -XDELETE ${ENDPOINT}/accounts/me \
    -H"Authorization: Bearer ${ACCESS_TOKEN}" \
    | jq '.'
 
{
  "id": "9074b6aa-a980-44e9-8973-29501900aa79"
}
```



## Check if enabled

Returns **204 Success** status code if account is enabled, otherwise - **404 Not Found**.

*NOTE: the operation is only allowed for admins (members of 'admin' predefined group)*

**URI**

```
GET /accounts/${KEY}/enabled
```

**URI parameters**

Name      | Type   | Default    | Description
--------- | ------ | ---------- | ------------------
KEY       | string | _required_ | Account identifier or `me`

**Example**

```bash
curl -fsSL \
    -XGET ${ENDPOINT}/accounts/9074b6aa-a980-44e9-8973-29501900aa79/disabled \
    -H"Authorization: Bearer ${ACCESS_TOKEN}" \
    | jq '.'
```



## Enable

Enables account.

*NOTE: the operation is only allowed for admins (members of 'admin' predefined group)*

**URI**

```
PUT /accounts/${KEY}/enabled
```

**URI parameters**

Name      | Type   | Default    | Description
--------- | ------ | ---------- | ------------------
KEY       | string | _required_ | Account identifier or `me`

**Example**

```bash
curl -fsSL \
    -XPUT ${ENDPOINT}/accounts/9074b6aa-a980-44e9-8973-29501900aa79/disabled \
    -H"Authorization: Bearer ${ACCESS_TOKEN}" \
    | jq '.'
```



## Dissable

Disables account.

*NOTE: the operation is only allowed for admins (members of 'admin' predefined group)*

**URI**

```
DELETE /accounts/${KEY}/enabled
```

**URI parameters**

Name      | Type   | Default    | Description
--------- | ------ | ---------- | ------------------
KEY       | string | _required_ | Account identifier or `me`

**Example**

```bash
curl -fsSL \
    -XDELETE ${ENDPOINT}/accounts/9074b6aa-a980-44e9-8973-29501900aa79/disabled \
    -H"Authorization: Bearer ${ACCESS_TOKEN}" \
    | jq '.'
```