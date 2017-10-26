# Identity Provider

[![Build Status][travis-img]][travis]

Highly available, scalable and extendible Identity Provider.
It utilises [OAuth2 Authorization Framework][rfc6749] to retrieve and associate
one or many authentication identities (globally unique identifiers)
with the unified account.

At this point, only [OAuth2 Client Credentials Grant][rfc6749-client-credentials] flow is supported.



### How To Use

To build and start playing with the application,
execute following shell commands within different terminal tabs:

```bash
## Building the development image and running the container with Riak KV within it..
$ ./run-docker.sh
## Building the application and executing an erlang shell.
$ make app shell
```



### API

IdP could be operated through its REST APIs:

- [Authentication][api-authentication]
- [Account][api-account]

To make examples in the API reference work, we need to create an account with admin permissions (account that is a member of predefined `admin` ACL group).

```erlang
%% We specify an account identifier explicitly just for simplicity reasons
Tokens =
  idp_cli_account:create(
    #{acl => [{<<"admin">>, riakacl_group:new_dt()}]},
    #{aud => <<"example.org">>, expires_in => infinity}),
io:format(
  "ID='~s'~nACCESS_TOKEN='~s'~nREFRESH_TOKEN='~s'~n",
  [ maps:get(id, Tokens),
    maps:get(access_token, Tokens),
    maps:get(refresh_token, Tokens)]).
```

For authorization examples to work, we also need client's token. Here is how it can be created.

```erlang
Claims =
  #{aud => <<"idp.example.org">>,
    iss => <<"example.org">>,
    exp => 32503680000,
    sub => <<"John">>},
{ok, Pem} = file:read_file(idp:conf_path(<<"keys/example.priv.pem">>)),
{Alg, Priv} = jose_pem:parse_key(Pem),
ClientToken = jose_jws_compact:encode(Claims, Alg, Priv),
io:format("CLIENT_TOKEN='~s'~n", [ClientToken]).
```

Finally, we could use the following endpoint URI and tokens issued bellow.

```bash
ENDPOINT='https://localhost:8443/api/v1'
```



### License

The source code is provided under the terms of [the MIT license][license].

[api-account]:https://github.com/foxford/idp/blob/master/API_ACCOUNT.md
[api-authentication]:https://github.com/foxford/idp/blob/master/API_AUTHENTICATION.md
[license]:http://www.opensource.org/licenses/MIT
[rfc6749]:https://tools.ietf.org/html/rfc6749
[rfc6749-client-credentials]:https://tools.ietf.org/html/rfc6749#section-4.4
[travis]:https://travis-ci.org/foxford/idp?branch=master
[travis-img]:https://secure.travis-ci.org/foxford/idp.png?branch=master
