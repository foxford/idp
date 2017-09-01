%% ----------------------------------------------------------------------------
%% The MIT License
%%
%% Copyright (c) 2016-2017 Andrei Nesterov <ae.nesterov@gmail.com>
%%
%% Permission is hereby granted, free of charge, to any person obtaining a copy
%% of this software and associated documentation files (the "Software"), to
%% deal in the Software without restriction, including without limitation the
%% rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
%% sell copies of the Software, and to permit persons to whom the Software is
%% furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
%% IN THE SOFTWARE.
%% ----------------------------------------------------------------------------

-module(auth_SUITE).
-include_lib("common_test/include/ct.hrl").

-compile(export_all).

%% =============================================================================
%% Common Test callbacks
%% =============================================================================

all() ->
	application:ensure_all_started(idp),
	application:ensure_all_started(gun),
	[{group, auth}].

groups() ->
	[{auth, [parallel], ct_helper:all(?MODULE)}].

init_per_suite(Config) ->
	idp_cth:init_config() ++ Config.

end_per_suite(Config) ->
	Config.

%% =============================================================================
%% Tests
%% =============================================================================

%% We must not issue any tokens for disabled accounts.
auth_disabled_account(Config) ->
	{ok, Pem} = file:read_file(idp:conf_path(<<"keys/example.priv.pem">>)),
	{Alg, Priv} = jose_pem:parse_key(Pem),
	ClientUid = idp_cth:make_uid(),
	I = [<<"oauth2">>, <<"example">>, ClientUid],
	Ib = <<"oauth2.example.", ClientUid/binary>>,
	ClientToken = do_create_client_token(ClientUid, Alg, Priv),
	ContentTypeH = {<<"content-type">>, <<"application/json">>},
	Payload = jsx:encode(#{grant_type => <<"client_credentials">>, client_token => ClientToken}),
	AuthorizationH = fun(Token) -> {<<"authorization">>, [<<"Bearer ">>, Token]} end,

	#{access_token := AccessToken,
		refresh_token := RefreshToken} = idp_cli_account:create(#{enable => false, identities => [I]}, #{}),
	do_wait(),

	Pid = idp_cth:gun_open(Config),
	%% Retrieving an access token is forbidden
	Ref0 = gun:request(Pid, <<"POST">>, <<"/api/v1/auth/oauth2.example/token">>, [ContentTypeH], Payload),
	{400, _Hs0, _Body0} = idp_cth:gun_await(Pid, Ref0),
	%% Linking another account is forbidden
	Ref1 = gun:request(Pid, <<"POST">>, <<"/api/v1/auth/oauth2.example/link">>, [AuthorizationH(AccessToken), ContentTypeH], Payload),
	{400, _Hs1, _Body1} = idp_cth:gun_await(Pid, Ref1),
	%% Refreshing an access token is forbidden
	Ref2 = gun:request(Pid, <<"POST">>, <<"/api/v1/accounts/me/refresh">>, [AuthorizationH(RefreshToken)]),
	{422, _Hs2, _Body2} = idp_cth:gun_await(Pid, Ref2),
	%% Revoking an refresh token is forbidden
	Ref3 = gun:request(Pid, <<"POST">>, <<"/api/v1/accounts/me/revoke">>, [AuthorizationH(RefreshToken)]),
	{422, _Hs3, _Body3} = idp_cth:gun_await(Pid, Ref3),
	%% Deleting an account is forbidden
	Ref4 = gun:request(Pid, <<"DELETE">>, <<"/api/v1/accounts/me">>, [AuthorizationH(AccessToken)]),
	{422, _Hs4, _Body4} = idp_cth:gun_await(Pid, Ref4),
	%% Deleting an identity of account is forbidden
	Ref5 = gun:request(Pid, <<"DELETE">>, [<<"/api/v1/accounts/me/auth/">>, Ib], [AuthorizationH(AccessToken)]),
	{422, _Hs5, _Body5} = idp_cth:gun_await(Pid, Ref5).

%% Access and refresh tokens can be retrieved by using credentials of an external service (client)
%% in a form of Json Web Token issued and signed by the client.
auth_oauth2_client_credentials(Config) ->
	{ok, Pem} = file:read_file(idp:conf_path(<<"keys/example.priv.pem">>)),
	{Alg, Priv} = jose_pem:parse_key(Pem),
	ClientToken = do_create_client_token(idp_cth:make_uid(), Alg, Priv),
	ContentTypeJsonH = {<<"content-type">>, <<"application/json">>},
	ContentTypeFormH = {<<"content-type">>, <<"application/x-www-form-urlencoded">>},
	PayloadJson = jsx:encode(#{grant_type => <<"client_credentials">>, client_token => ClientToken}),
	PayloadForm = <<"grant_type=client_credentials&client_token=", ClientToken/binary>>,
	Test =
		[	{ContentTypeJsonH, PayloadJson},
			{ContentTypeFormH, PayloadForm} ],

	Pid = idp_cth:gun_open(Config),
	[begin
		Ref = gun:request(Pid, <<"POST">>, <<"/api/v1/auth/oauth2.example/token">>, [ContentTypeH], Payload),
		{200, _Hs, #{<<"access_token">> := _, <<"refresh_token">> := _, <<"expires_in">> := _, <<"token_type">> := <<"Bearer">>}} = idp_cth:gun_await_json(Pid, Ref)
	end || {ContentTypeH, Payload} <- Test].

%% Access token can be refreshed by using previously issued refresh token.
auth_access_token_refresh(Config) ->
	{ok, Pem} = file:read_file(idp:conf_path(<<"keys/example.priv.pem">>)),
	{Alg, Priv} = jose_pem:parse_key(Pem),
	ClientToken = do_create_client_token(idp_cth:make_uid(), Alg, Priv),
	ContentTypeH = {<<"content-type">>, <<"application/json">>},
	Payload = jsx:encode(#{grant_type => <<"client_credentials">>, client_token => ClientToken}),
	AuthorizationH = fun(Token) -> {<<"authorization">>, [<<"Bearer ">>, Token]} end,

	Pid = idp_cth:gun_open(Config),
	%% Getting a refresh token
	Ref0 = gun:request(Pid, <<"POST">>, <<"/api/v1/auth/oauth2.example/token">>, [ContentTypeH], Payload),
	{200, _Hs0, #{<<"refresh_token">> := RefreshToken}} = idp_cth:gun_await_json(Pid, Ref0),
	%% Refreshing access token using a refresh token
	Ref1 = gun:request(Pid, <<"POST">>, <<"/api/v1/accounts/me/refresh">>, [AuthorizationH(RefreshToken)]),
	{200, _Hs1, #{<<"access_token">> := _, <<"expires_in">> := _, <<"token_type">> := _}} = idp_cth:gun_await_json(Pid, Ref1),
	%% Multiple refreshing access token using same refresh token
	Ref2 = gun:request(Pid, <<"POST">>, <<"/api/v1/accounts/me/refresh">>, [AuthorizationH(RefreshToken)]),
	{200, _Hs2, #{<<"access_token">> := _, <<"expires_in">> := _, <<"token_type">> := _}} = idp_cth:gun_await_json(Pid, Ref2).

%% Refresh token can be revoked by using previously issued refresh token.
auth_refresh_token_revoke(Config) ->
	{ok, Pem} = file:read_file(idp:conf_path(<<"keys/example.priv.pem">>)),
	{Alg, Priv} = jose_pem:parse_key(Pem),
	ClientToken = do_create_client_token(idp_cth:make_uid(), Alg, Priv),
	ContentTypeH = {<<"content-type">>, <<"application/json">>},
	Payload = jsx:encode(#{grant_type => <<"client_credentials">>, client_token => ClientToken}),
	AuthorizationH = fun(Token) -> {<<"authorization">>, <<"Bearer ", Token/binary>>} end,

	Pid = idp_cth:gun_open(Config),
	%% Getting a refresh token
	Ref0 = gun:request(Pid, <<"POST">>, <<"/api/v1/auth/oauth2.example/token">>, [ContentTypeH], Payload),
	{200, _Hs0, #{<<"refresh_token">> := RefreshToken}} = idp_cth:gun_await_json(Pid, Ref0),
	%% Revoking the refresh token
	Ref1 = gun:request(Pid, <<"POST">>, <<"/api/v1/accounts/me/revoke">>, [AuthorizationH(RefreshToken)]),
	{200, _Hs1, #{<<"refresh_token">> := _}} = idp_cth:gun_await_json(Pid, Ref1),
	%% Confirming that refresh token is revoked
	Ref2 = gun:request(Pid, <<"POST">>, <<"/api/v1/accounts/me/revoke">>, [AuthorizationH(RefreshToken)]),
	{401, _Hs2, _Body2} = idp_cth:gun_await(Pid, Ref2).

%% Accounts can have more than one identity linked to it.
auth_link(Config) ->
	{ok, Pem} = file:read_file(idp:conf_path(<<"keys/example.priv.pem">>)),
	{Alg, Priv} = jose_pem:parse_key(Pem),
	ClientAkey = <<"oauth2.example">>,
	ClientBkey = <<"oauth2.example-restricted">>,
	ClientAuid = idp_cth:make_uid(),
	ClientBuid = idp_cth:make_uid(),
	ClientAtoken = do_create_client_token(ClientAuid, Alg, Priv),
	ClientBtoken = do_create_client_token(ClientBuid, Alg, Priv),
	ContentTypeH = {<<"content-type">>, <<"application/json">>},
	ClientApayload = jsx:encode(#{grant_type => <<"client_credentials">>, client_token => ClientAtoken}),
	ClientBpayload = jsx:encode(#{grant_type => <<"client_credentials">>, client_token => ClientBtoken}),
	IdentityA = <<"oauth2.example.", ClientAuid/binary>>,
	Keys = [[<<"oauth2">>, <<"example">>], [<<"oauth2">>, <<"example-restricted">>]],

	Pid = idp_cth:gun_open(Config),
	Aref = gun:request(Pid, <<"POST">>, [<<"/api/v1/auth/">>, ClientAkey, <<"/token">>], [ContentTypeH], ClientApayload),
	{200, _Ahs, #{<<"access_token">> := Token}} = idp_cth:gun_await_json(Pid, Aref),
	[_, #{<<"sub">> := Akey} | _] = jose_jws_compact:parse(Token, #{parse_payload => map}),

	do_wait(),
	do_has_account(Akey),
	AuthorizationH = {<<"authorization">>, [<<"Bearer ">>, Token]},
	Bref = gun:request(Pid, <<"POST">>, [<<"/api/v1/auth/">>, ClientBkey, <<"/link">>], [AuthorizationH, ContentTypeH], ClientBpayload),
	{200, _Bhs, #{<<"id">> := IdentityB}} = idp_cth:gun_await_json(Pid, Bref),

	do_wait(),
	do_has_identities(Akey, Keys, [IdentityA, IdentityB]).

%% =============================================================================
%% Internal functions
%% =============================================================================

-spec do_create_client_token(binary(), binary(), binary()) -> binary().
do_create_client_token(Uid, Alg, Priv) ->
	jose_jws_compact:encode(
		#{aud => <<"app.example.org">>,
			iss => <<"example.org">>,
			exp => 32503680000,
			sub => Uid},
		Alg,
		Priv).

-spec do_create_client_token(binary(), binary(), binary(), binary()) -> binary().
do_create_client_token(Uid, Alg, Priv, Role) ->
	jose_jws_compact:encode(
		#{aud => <<"app.example.org">>,
			iss => <<"example.org">>,
			exp => 32503680000,
			sub => Uid,
			role => Role},
		Alg,
		Priv).

-spec do_create_client_token(binary(), binary(), binary(), binary(), map()) -> binary().
do_create_client_token(Uid, Alg, Priv, Role, Resource) ->
	jose_jws_compact:encode(
		#{aud => <<"app.example.org">>,
			iss => <<"example.org">>,
			exp => 32503680000,
			sub => Uid,
			role => Role,
			resource => Resource},
		Alg,
		Priv).

-spec do_has_account(binary()) -> ok.
do_has_account(Key) ->
	#{account := #{bucket := Bucket, pool := KVpool}} = idp:resources(),
	KVpid = riakc_pool:lock(KVpool),
	_ = riakauth_account:get(KVpid, Bucket, Key),
	riakc_pool:unlock(KVpool, KVpid),
	ok.

-spec do_has_identities(binary(), [[binary()]], [binary()]) -> ok.
do_has_identities(Key, Keys, ExpectedIdentities) ->
	#{account := #{bucket := Bucket, pool := KVpool}} = idp:resources(),
	IdentityToBinary =
		fun
			([Segment]) -> Segment;
			([H|T])     -> lists:foldl(fun(Segment, Acc) -> <<Acc/binary, $., Segment/binary>> end, H, T);
			([])        -> <<>>
		end,
	Handle = fun(Identity, _Raw, Acc) -> [IdentityToBinary(Identity)|Acc] end,
	KVpid = riakc_pool:lock(KVpool),
	A = riakauth_account:get(KVpid, Bucket, Key),
	riakc_pool:unlock(KVpool, KVpid),
	Identities = riakauth_account:fold_identities_dt(Handle, Keys, [], A),
	[true = lists:member(ExpectedIdentity, Identities) || ExpectedIdentity <- ExpectedIdentities],
	ok.

-spec do_wait() -> ok.
do_wait() ->
	timer:sleep(3000).
