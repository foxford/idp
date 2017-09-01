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

-module(account_auth_SUITE).
-include_lib("common_test/include/ct.hrl").

-compile(export_all).

%% =============================================================================
%% Common Test callbacks
%% =============================================================================

all() ->
	application:ensure_all_started(idp),
	application:ensure_all_started(gun),
	[{group, account_auth}].

groups() ->
	[{account_auth, [parallel], ct_helper:all(?MODULE)}].

init_per_suite(Config) ->
	idp_cth:init_config() ++ Config.

init_per_testcase(_Test, Config) ->
	#{account := #{pool := KVpool}} = idp:resources(),
	HandleData = fun(Data) -> Data end,
	I = [<<"oauth2">>, <<"example">>, idp_cth:make_uid()],
	Accounts = [user, admin, anonymous],

	KVpid = riakc_pool:lock(KVpool),
	Admin = idp_cli_account:create(KVpid, #{acl => [{<<"admin">>, riakacl_group:new_dt()}], identities => [I]}, #{}),
	User = idp_cli_account:create(KVpid, #{identities => [I]}, #{}),
	UserNoIdentity = idp_cli_account:create(KVpid, #{}, #{}),
	riakc_pool:unlock(KVpool, KVpid),

	[	{admin, Admin},
		{user, User},
		{user_noidentities, UserNoIdentity},
		{identity, I},
		{accounts, Accounts}
		| Config ].

end_per_testcase(_Test, Config) ->
	Config.

end_per_suite(Config) ->
	Config.

%% =============================================================================
%% Tests
%% =============================================================================

%% Returns a list of account's identities.
%% An empty list is returned for accounts that don't have any linked identities.
%% The 404 'Not Found' error is returned for accounts that don't exist.
list(Config) ->
	#{id := Key, access_token := Token} = ?config(admin, Config),
	#{id := KeyNoIdentities} = ?config(user_noidentities, Config),
	KeyNotExist = idp:make_uuid(),
	AuthorizationH = {<<"authorization">>, [<<"Bearer ">>, Token]},
	Test =
		[	%% account w/ identity
			{[<<"/api/v1/accounts/">>, Key, <<"/auth">>], 200},
			%% account w/o identity
			{[<<"/api/v1/accounts/">>, KeyNoIdentities, <<"/auth">>], 200},
			%% account doesn't exist
			{[<<"/api/v1/accounts/">>, KeyNotExist, <<"/auth">>], 404} ],

	Pid = idp_cth:gun_open(Config),
	[begin
		Ref = gun:request(Pid, <<"GET">>, Path, [AuthorizationH]),
		case Status of
			404 -> {404, _Hs, _Body} = idp_cth:gun_await(Pid, Ref);
			200 ->
				{200, _Hs, L} = idp_cth:gun_await_json(Pid, Ref),
				[#{<<"id">> := _} =Obj || Obj <- L]
		end
	end || {Path, Status} <- Test].

%% Access is granted only for accounts themselves or accounts that
%% are members of 'admin' (predefined) group.
list_permissions(Config) ->
	Accounts = ?config(accounts, Config),
	Test =
		[	{200, [user], <<"me">>},
			{200, [user], maps:get(id, ?config(user, Config))},
			{200, [admin], maps:get(id, ?config(user, Config))},
			{403, Accounts -- [admin], maps:get(id, ?config(admin, Config))} ],

	Pid = idp_cth:gun_open(Config),
	[begin
		[begin
			Path = [<<"/api/v1/accounts/">>, Key, <<"/auth">>],
			Ref = gun:request(Pid, <<"GET">>, Path, idp_cth:authorization_headers(A, Config)),
			{St, _Hs, _Body} = idp_cth:gun_await(Pid, Ref)
		end || A <- As]
	end || {St, As, Key} <- Test].

%% Removes the specified identity.
%% Returns the removed identity.
%% The 404 'Not Found' error is returned for accounts or identies
%% that don't exist.
delete(Config) ->
	#{id := Key, access_token := Token} = ?config(admin, Config),
	#{id := KeyNoIdentities} = ?config(user_noidentities, Config),
	KeyNotExist = idp:make_uuid(),
	I = ?config(identity, Config),
	Ibin = idp_account_auth:identity(I),
	AuthorizationH = {<<"authorization">>, [<<"Bearer ">>, Token]},
	Test =
		[	%% account w/ identity
			{[<<"/api/v1/accounts/">>, Key, <<"/auth/">>, Ibin], 200},
			%% account w/o identity
			{[<<"/api/v1/accounts/">>, KeyNoIdentities, <<"/auth/">>, Ibin], 404},
			%% account doesn't exist
			{[<<"/api/v1/accounts/">>, KeyNotExist, <<"/auth/">>, Ibin], 404} ],

	Pid = idp_cth:gun_open(Config),
	[begin
		Ref = gun:request(Pid, <<"DELETE">>, Path, [AuthorizationH]),
		case Status of
			200 -> {200, _Hs, #{<<"id">> := Ibin}} = idp_cth:gun_await_json(Pid, Ref);
			404 -> {404, _Hs, <<>>} = idp_cth:gun_await(Pid, Ref)
		end
	end || {Path, Status} <- Test].

%% Access is granted only for accounts themselves or accounts that
%% are members of 'admin' (predefined) group.
delete_permissions_owner_me(Config) -> do_delete_permissions(200, [user], <<"me">>, Config).
delete_permissions_owner_id(Config) -> do_delete_permissions(200, [user], maps:get(id, ?config(user, Config)), Config).
delete_permissions_admin(Config)    -> do_delete_permissions(200, [admin], maps:get(id, ?config(user, Config)), Config).
delete_permissions(Config)          -> do_delete_permissions(403, ?config(accounts, Config) -- [admin], maps:get(id, ?config(admin, Config)), Config).

do_delete_permissions(Status, Accounts, Key, Config) ->
	I = ?config(identity, Config),
	Ibin = idp_account_auth:identity(I),
	Path = [<<"/api/v1/accounts/">>, Key, <<"/auth/">>, Ibin],

	Pid = idp_cth:gun_open(Config),
	[begin
		Ref = gun:request(Pid, <<"DELETE">>, Path, idp_cth:authorization_headers(A, Config)),
		{Status, _Hs, _Body} = idp_cth:gun_await(Pid, Ref)
	end || A <- Accounts].
