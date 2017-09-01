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

-module(account_SUITE).
-include_lib("common_test/include/ct.hrl").

-compile(export_all).

%% =============================================================================
%% Common Test callbacks
%% =============================================================================

all() ->
	application:ensure_all_started(idp),
	application:ensure_all_started(gun),
	[{group, account}].

groups() ->
	[{account, [parallel], ct_helper:all(?MODULE)}].

init_per_suite(Config) ->
	idp_cth:init_config() ++ Config.

init_per_testcase(_Test, Config) ->
	#{account := #{pool := KVpool}} = idp:resources(),
	Accounts = [admin, user, user_other, anonymous],

	KVpid = riakc_pool:lock(KVpool),
	%% Creating accounts
	Admin = idp_cli_account:create(KVpid, #{acl => [{<<"admin">>, riakacl_group:new_dt()}]}, #{}),
	User = idp_cli_account:create(KVpid, #{}, #{}),
	UserOther = idp_cli_account:create(KVpid, #{}, #{}),
	riakc_pool:unlock(KVpool, KVpid),

	[	{admin, Admin},
		{user, User},
		{user_other, UserOther},
		{accounts, Accounts}
		| Config ].

end_per_testcase(_Test, Config) ->
	Config.

end_per_suite(Config) ->
	Config.

%% =============================================================================
%% Tests
%% =============================================================================

%% Returns the specified account.
%% The 404 'Not Found' error is returned for accounts that don't exist.
read(Config) ->
	#{id := Akey} = ?config(admin, Config),
	AkeyNotExist = idp:make_uuid(),
	AuthorizationH = idp_cth:authorization_header(admin, Config),
	Test =
		[ %% account me
			{<<"/api/v1/accounts/me">>, 200},
			%% account exists
			{[<<"/api/v1/accounts/">>, Akey], 200},
			%% account doesn't exist
			{[<<"/api/v1/accounts/">>, AkeyNotExist], 404} ],

	[begin
		Pid = idp_cth:gun_open(Config),
		Ref = gun:request(Pid, <<"GET">>, Path, [AuthorizationH]),
		case Status of
			200 -> {200, _Hs, #{<<"id">> := _}} = idp_cth:gun_await_json(Pid, Ref);
			404 -> {404, _Hs, <<>>} = idp_cth:gun_await(Pid, Ref)
		end
	end || {Path, Status} <- Test].

%% Access is granted only for accounts` owners
%% or members of 'admin' (predefined) group.
read_permissions(Config) ->
	#{id := Akey} = ?config(user, Config),
	Path = [<<"/api/v1/accounts/">>, Akey],
	Accounts = ?config(accounts, Config),
	Test =
		[	{200, [user]},
			{200, [admin]},
			{403, Accounts -- [user, admin]} ],

	[begin
		[begin
			Pid = idp_cth:gun_open(Config),
			Ref = gun:request(Pid, <<"GET">>, Path, idp_cth:authorization_headers(A, Config)),
			{St, _Hs, _Body} = idp_cth:gun_await(Pid, Ref)
		end || A <- As]
	end || {St, As} <- Test].

%% Removes the specified account.
%% Returns the removed account.
%% The 404 'Not Found' error is returned for accounts that don't exist.
delete(Config) ->
	#{id := Akey} = ?config(user, Config),
	AkeyNotExist = idp:make_uuid(),
	Test =
		[	%% me
			{<<"/api/v1/accounts/me">>, user_other, 200},
			%% account exist
			{[<<"/api/v1/accounts/">>, Akey], admin, 200},
			%% account doesn't exist
			{[<<"/api/v1/accounts/">>, AkeyNotExist], admin, 404} ],

	[begin
		AuthorizationH = idp_cth:authorization_header(A, Config),
		Pid = idp_cth:gun_open(Config),
		Ref = gun:request(Pid, <<"DELETE">>, Path, [AuthorizationH]),
		case Status of
			200 -> {200, _Hs, #{<<"id">> := _}} = idp_cth:gun_await_json(Pid, Ref);
			404 -> {404, _Hs, <<>>} = idp_cth:gun_await(Pid, Ref)
		end
	end || {Path, A, Status} <- Test].

%% Access is granted only for accounts` owners
%% or members of 'admin' (predefined) group.
delete_permissions_owner(Config) -> do_delete_permissions(200, [user], Config).
delete_permissions_admin(Config) -> do_delete_permissions(200, [admin], Config).
delete_permissions(Config)       -> do_delete_permissions(403, ?config(accounts, Config) -- [user, admin], Config).

do_delete_permissions(Status, Accounts, Config) ->
	#{id := Akey} = ?config(user, Config),
	Path = [<<"/api/v1/accounts/">>, Akey],

	[begin
		Pid = idp_cth:gun_open(Config),
		Ref = gun:request(Pid, <<"DELETE">>, Path, idp_cth:authorization_headers(A, Config)),
		{Status, _Hs, _Body} = idp_cth:gun_await(Pid, Ref)
	end || A <- Accounts].
