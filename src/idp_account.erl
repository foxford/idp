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

-module(idp_account).

%% CRUD API
-export([
	refresh_access_token/3,
	revoke_refresh_token/3,
	create/4,
	link/5,
	read/2,
	read/3,
	delete/3,
	enable/3,
	disable/3
]).

%% API
-export([
	is_enabled/1,
	to_map/2
]).

%% DataType API
-export([
	update_enabled_dt/2,
	refresh_token_dt/1,
	update_refresh_token_dt/4,
	fold_refresh_token_dt/3,
	generate_refresh_token_key/1
]).

%% =============================================================================
%% CRUD API
%% =============================================================================

-spec refresh_access_token(binary(), map(), map()) -> map().
refresh_access_token(Akey, Tokens, Rdesc) ->
	#{account :=
			#{pool := Pool,
				bucket := Ab}} = Rdesc,
	#{type := Type,
		expires_in := ExpiresIn,
		iss := Iss,
		aud := Aud,
		access_token :=
			#{alg := Alg,
				key := Key}} = Tokens,

	KVpid = riakc_pool:lock(Pool),
	A = riakauth_account:get(KVpid, Ab, Akey),
	riakc_pool:unlock(Pool, KVpid),

	%% We must not issue any tokens for disabled accounts.
	true = is_enabled(A),

	Now = idp:unix_time(),
	Exp = Now +ExpiresIn,

	AccessToken =
		jose_jws_compact:encode(
			#{iss => Iss,
				aud => Aud,
				sub => Akey,
				exp => Exp},
			Alg,
			Key),

	%% According to RFC 6749 - The OAuth 2.0 Authorization Framework
	%% 5.1. Issuing an Access Token. Successful Response
	%% https://tools.ietf.org/html/rfc6749#section-5.1
	#{access_token => AccessToken,
		token_type => Type,
		expires_in => ExpiresIn}.

-spec revoke_refresh_token(binary(), map(), map()) -> map().
revoke_refresh_token(Akey, Tokens, Rdesc) ->
	#{account :=
			#{pool := Pool,
				bucket := Ab}} = Rdesc,
	#{iss := Iss,
		aud := Aud,
		refresh_token :=
			#{alg := RefreshAlg}} = Tokens,

	KVpid0 = riakc_pool:lock(Pool),
	A = riakauth_account:get(KVpid0, Ab, Akey, [{pr, quorum}]),
	riakc_pool:unlock(Pool, KVpid0),

	%% We must not issue any tokens for disabled accounts.
	true = is_enabled(A),

	NowUs = idp:unix_time_us(),
	RefreshKey = generate_refresh_token_key(RefreshAlg),

	KVpid1 = riakc_pool:lock(Pool),
	_ =
		riakauth_account:put(
			KVpid1, Ab, Akey,
			riakauth_account:update_data_dt(
				fun(Data) ->
					update_refresh_token_dt(RefreshAlg, RefreshKey, NowUs, Data)
				end, A)),
	riakc_pool:unlock(Pool, KVpid1),

	RefreshToken =
		jose_jws_compact:encode(
			#{iss => Iss,
				aud => Aud,
				sub => Akey},
			RefreshAlg,
			RefreshKey),
	
	#{refresh_token => RefreshToken}.

-spec create(map(), map(), map(), map()) -> map().
create(ClientTokenPayload, Rdesc, Tokens, IdpsConf) ->
	#{key := [Prot, Prov]} = IdpsConf,
	#{account :=
			#{pool := Pool,
				bucket := Ab,
				index := Index,
				handler := Hmod}} = Rdesc,
	#{type := Type,
		expires_in := ExpiresIn,
		iss := Iss,
		aud := Aud,
		access_token :=
			#{alg := Alg,
				key := Key},
		refresh_token :=
			#{alg := RefreshAlg}} = Tokens,
	#{<<"sub">> := Uid} = ClientTokenPayload,
	Now = idp:unix_time(),
	NowUs = to_us(Now),
	Exp = Now +ExpiresIn,
	ExpUs = to_us(Exp),

	NewRefreshKey = generate_refresh_token_key(RefreshAlg),
	Identity = [Prot, Prov, Uid],
	HandleKey = fun idp:make_uuid/0,
	HandleData =
		fun(Data0) ->
			Data1 = update_refresh_token_dt(RefreshAlg, NewRefreshKey, NowUs, Data0),
			Data2 = update_enabled_dt(enable, Data1),
			Data2
		end,

	KVpid = riakc_pool:lock(Pool),
	{Akey, A} = riakauth:authenticate(KVpid, Ab, Index, Identity, HandleKey, HandleData),
	riakc_pool:unlock(Pool, KVpid),

	_ =
		case riakauth_account:find_data_rawdt(A) of
			{ok, Data} ->
				%% Already existed account.
				%% We must not issue any tokens or create ACL for disabled accounts.
				true = is_enabled_rawdt(Data);
			_ ->
				%% Newly created account.
				ignore
		end,

	Hmod:create_acl(ClientTokenPayload, Akey, NowUs, ExpUs, Rdesc, IdpsConf),

	AccessToken =
		jose_jws_compact:encode(
			#{iss => Iss,
				aud => Aud,
				sub => Akey,
				exp => Exp},
			Alg,
			Key),

	RefreshKey = case refresh_token_dt(A) of #{key := Val} -> Val; _ -> NewRefreshKey end,
	RefreshToken =
		jose_jws_compact:encode(
			#{iss => Iss,
				aud => Aud,
				sub => Akey},
			RefreshAlg,
			RefreshKey),

	%% According to RFC 6749 - The OAuth 2.0 Authorization Framework
	%% 5.1. Issuing an Access Token. Successful Response
	%% https://tools.ietf.org/html/rfc6749#section-5.1
	#{access_token => AccessToken,
		refresh_token => RefreshToken,
		token_type => Type,
		expires_in => ExpiresIn}.

-spec link(map(), map(), map(), map(), map()) -> map().
link(ClientTokenPayload, AuthM, Rdesc, Tokens, IdpsConf) ->
	#{account :=
			#{pool := Pool,
				bucket := Ab,
				handler := Hmod}} = Rdesc,
	#{key := [Prot, Prov]} = IdpsConf,
	#{expires_in := ExpiresIn} = Tokens,
	#{<<"sub">> := Uid} = ClientTokenPayload,
	#{<<"sub">> := Akey} = AuthM,

	Identity = [Prot, Prov, Uid],
	KVpid0 = riakc_pool:lock(Pool),
	A = riakauth_account:get(KVpid0, Ab, Akey),
	riakc_pool:unlock(Pool, KVpid0),

	%% We must not link new identities to disabled accounts.
	true = is_enabled(A),

	KVpid1 = riakc_pool:lock(Pool),
	_ = riakauth_account:put(
			KVpid1, Ab, Akey,
			riakauth_account:update_identity_dt(Identity, A)),
	riakc_pool:unlock(Pool, KVpid1),

	NowUs = idp:unix_time_us(),
	ExpUs = NowUs +to_us(ExpiresIn),
	Hmod:create_acl(ClientTokenPayload, Akey, NowUs, ExpUs, Rdesc, IdpsConf),

	#{id => <<Prot/binary, $., Prov/binary, $., Uid/binary>>}.

-spec read(binary(), map()) -> {ok, riakauth_account:account()} | error.
read(Akey, Rdesc) ->
	read(Akey, Rdesc, []).

-spec read(binary(), map(), [proplists:property()]) -> {ok, riakauth_account:account()} | error.
read(Akey, Rdesc, Opts) ->
	#{account := #{pool := KVpool, bucket := Ab}} = Rdesc,
	KVpid = riakc_pool:lock(KVpool),
	MaybeA = riakauth_account:find(KVpid, Ab, Akey, Opts),
	riakc_pool:unlock(KVpool, KVpid),
	MaybeA.

-spec delete(binary(), riakauth_account:account(), map()) -> map().
delete(Akey, A, Rdesc) ->
	#{account := #{pool := KVpool, bucket := Ab},
		account_aclsubject := #{pool := KVpool, bucket := AclSb}} = Rdesc,

	%% We do not allow deleting disabled accounts.
	true = is_enabled(A),

	KVpid = riakc_pool:lock(KVpool),
	riakacl_entry:remove(KVpid, AclSb, Akey),
	riakauth_account:remove(KVpid, Ab, Akey),
	riakc_pool:unlock(KVpool, KVpid),
	to_map(Akey, A).

-spec enable(binary(), riakauth_account:account(), map()) -> ok.
enable(Akey, A, Rdesc) ->
	enable_(enable, Akey, A, Rdesc).

-spec disable(binary(), riakauth_account:account(), map()) -> ok.
disable(Akey, A, Rdesc) ->
	enable_(disable, Akey, A, Rdesc).

%% =============================================================================
%% API
%% =============================================================================

-spec to_map(binary(), riakauth_account:account()) -> map().
to_map(Akey, A) ->
	format_resource(Akey, A).

-spec is_enabled(riakauth_account:account()) -> boolean().
is_enabled(A) ->
	case riakauth_account:find_data_rawdt(A) of
		{ok, Data} -> is_enabled_rawdt(Data);
		_          -> false
	end.

%% =============================================================================
%% DataType API
%% =============================================================================

-spec is_enabled_rawdt([riakauth_account:rawdt()]) -> boolean().
is_enabled_rawdt(Data) ->
	case lists:keyfind({<<"enabled">>, flag}, 1, Data) of
		{_, Val} -> Val;
		_        -> false
	end.

-spec update_enabled_dt(enable | disable, riakauth_account:data()) -> riakauth_account:account().
update_enabled_dt(Val, Data) ->
	riakc_map:update({<<"enabled">>, flag}, fun(Obj) -> riakc_flag:Val(Obj) end, Data).

-spec generate_refresh_token_key(binary()) -> binary().
generate_refresh_token_key(Alg) ->
	jose_jwa:generate_key(Alg).

-spec refresh_token_dt(riakauth:account()) -> map().
refresh_token_dt(A) ->
	fold_refresh_token_dt(
		fun
			({{<<"alg">>, register}, Val}, Acc) -> Acc#{alg => Val};
			({{<<"key">>, register}, Val}, Acc) -> Acc#{key => cow_base64url:decode(Val)};
			({{<<"iat">>, register}, Val}, Acc) -> Acc#{iat => Val};
			(_, Acc)                            -> Acc
		end, #{}, A).

-spec update_refresh_token_dt(binary(), binary(), non_neg_integer(), riakauth_account:data()) -> riakauth_account:data().
update_refresh_token_dt(Alg, Key, IssuedAt, Data) ->
	riakc_map:update(
		{<<"refresh_token">>, map},
			fun(T0) ->
				T1 = riakc_map:update({<<"alg">>, register}, fun(Obj) -> riakc_register:set(Alg, Obj) end, T0),
				T2 = riakc_map:update({<<"key">>, register}, fun(Obj) -> riakc_register:set(cow_base64url:encode(Key), Obj) end, T1),
				T3 = riakc_map:update({<<"iat">>, register}, fun(Obj) -> riakc_register:set(integer_to_binary(IssuedAt), Obj) end, T2),
				T3
			end,
			Data).

-spec fold_refresh_token_dt(fun((riakauth_account:rawdt(), any()) -> any()), any(), riakauth:account()) -> any().
fold_refresh_token_dt(Handle, AccIn, A) ->
	case riakauth_account:find_data_rawdt(A) of
		{ok, Data} ->
			case lists:keyfind({<<"refresh_token">>, map}, 1, Data) of
				{_, Input} ->
					lists:foldl(Handle, AccIn, Input);
				_ ->
					%% There is no "refresh_token" property in the account object,
					%% so that our work is done.
					AccIn
			end;
		_ ->
			%% There is no "data" property in the account object,
			%% so that our work is done.
			AccIn
	end.

%% =============================================================================
%% Internal functions
%% =============================================================================

-spec enable_(enable | disable, binary(), riakauth_account:account(), map()) -> ok.
enable_(Op, Akey, A, Rdesc) ->
	#{account := #{pool := KVpool, bucket := Ab}} = Rdesc,
	KVpid = riakc_pool:lock(KVpool),
	_ =
		riakauth_account:put(
			KVpid, Ab, Akey,
			riakauth_account:update_data_dt(
				fun(Data) ->
					idp_account:update_enabled_dt(Op, Data)
				end, A)),
	riakc_pool:unlock(KVpool, KVpid),
	ok.

-spec format_resource(binary(), riakauth_account:account()) -> map().
format_resource(Tkey, _T) ->
	#{id => Tkey}.
	
-spec to_us(non_neg_integer()) -> non_neg_integer().
to_us(Sec) ->
	Sec *1000000.
