# Identity Provider

Highly available, scalable and extendible Identity Provider.
It utilises [OAuth2 Authorization Framework][rfc6749] to retrieve and map
one or many authentication identities (globally unique identifiers)
with account.

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



### License

The source code is provided under the terms of [the MIT license][license].

[license]:http://www.opensource.org/licenses/MIT
[rfc6749]:https://tools.ietf.org/html/rfc6749
[rfc6749-client-credentials]:https://tools.ietf.org/html/rfc6749#section-4.4
