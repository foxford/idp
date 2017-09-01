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

-module(account_enabled_SUITE).
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
	Accounts = [admin, user, user_disabled, anonymous],

	KVpid = riakc_pool:lock(KVpool),
	%% Creating accounts
	Admin = idp_cli_account:create(KVpid, #{acl => [{<<"admin">>, riakacl_group:new_dt()}]}, #{}),
	User = idp_cli_account:create(KVpid, #{}, #{}),
	UserDisabled = idp_cli_account:create(KVpid, #{enable => false}, #{}),
	riakc_pool:unlock(KVpool, KVpid),

	[	{admin, Admin},
		{user, User},
		{user_disabled, UserDisabled},
		{accounts, Accounts}
		| Config ].

end_per_testcase(_Test, Config) ->
	Config.

end_per_suite(Config) ->
	Config.

%% =============================================================================
%% Tests
%% =============================================================================

%% Retrieves a status of specified account: enabled or disabled.
%% The 204 'No content' is returned if account is enabled.
%% The 404 'Not Found' error is returned if account is disabled or don't exist.
read(Config) ->
	#{id := Akey} = ?config(user, Config),
	#{id := AkeyDisabled} = ?config(user_disabled, Config),
	AkeyNotExist = idp:make_uuid(),
	AuthorizationH = idp_cth:authorization_header(admin, Config),
	Test =
		[ %% account me (admin)
			{<<"/api/v1/accounts/me/enabled">>, 204},
			%% account exists
			{[<<"/api/v1/accounts/">>, Akey, <<"/enabled">>], 204},
			%% disabled account
			{[<<"/api/v1/accounts/">>, AkeyDisabled, <<"/enabled">>], 404},
			%% account doesn't exist
			{[<<"/api/v1/accounts/">>, AkeyNotExist, <<"/enabled">>], 404} ],

	[begin
		Pid = idp_cth:gun_open(Config),
		Ref = gun:request(Pid, <<"GET">>, Path, [AuthorizationH]),
		{Status, _Hs, <<>>} = idp_cth:gun_await(Pid, Ref)
	end || {Path, Status} <- Test].

%% Access is granted only for members of 'admin' (predefined) group.
read_permissions(Config) ->
	#{id := Akey} = ?config(user, Config),
	Path = [<<"/api/v1/accounts/">>, Akey, <<"/enabled">>],
	Accounts = ?config(accounts, Config),
	Test =
		[	{204, [admin]},
			{403, Accounts -- [admin]} ],

	[begin
		[begin
			Pid = idp_cth:gun_open(Config),
			Ref = gun:request(Pid, <<"GET">>, Path, idp_cth:authorization_headers(A, Config)),
			{St, _Hs, _Body} = idp_cth:gun_await(Pid, Ref)
		end || A <- As]
	end || {St, As} <- Test].

%% Enables the specified account.
%% The 204 'No content' is returned on success.
%% The 404 'Not Found' error is returned for accounts that don't exist.
update(Config) ->
	#{id := Akey} = ?config(user, Config),
	#{id := AkeyDisabled} = ?config(user_disabled, Config),
	AkeyNotExist = idp:make_uuid(),
	AuthorizationH = idp_cth:authorization_header(admin, Config),
	Test =
		[ %% account me (admin)
			{<<"/api/v1/accounts/me/enabled">>, 204},
			%% account exists
			{[<<"/api/v1/accounts/">>, Akey, <<"/enabled">>], 204},
			%% disabled account
			{[<<"/api/v1/accounts/">>, AkeyDisabled, <<"/enabled">>], 204},
			%% account doesn't exist
			{[<<"/api/v1/accounts/">>, AkeyNotExist, <<"/enabled">>], 404} ],

	[begin
		Pid = idp_cth:gun_open(Config),
		ct:log("curl -vk -XPUT https://localhost:8443~s -H'Authorization: ~s'~n", [iolist_to_binary(Path), begin {_, X} = AuthorizationH, iolist_to_binary(X) end]),
		Ref = gun:request(Pid, <<"PUT">>, Path, [AuthorizationH], <<>>),
		{Status, _Hs, <<>>} = idp_cth:gun_await(Pid, Ref)
	end || {Path, Status} <- Test].

%% Access is granted only for members of 'admin' (predefined) group.
update_permissions(Config) ->
	#{id := Akey} = ?config(user, Config),
	Path = [<<"/api/v1/accounts/">>, Akey, <<"/enabled">>],
	Accounts = ?config(accounts, Config),
	Test =
		[	{204, [admin]},
			{403, Accounts -- [admin]} ],

	[begin
		[begin
			Pid = idp_cth:gun_open(Config),
			Ref = gun:request(Pid, <<"PUT">>, Path, idp_cth:authorization_headers(A, Config)),
			{St, _Hs, _Body} = idp_cth:gun_await(Pid, Ref)
		end || A <- As]
	end || {St, As} <- Test].

%% Disables the specified account.
%% The 204 'No content' is returned on success.
%% The 404 'Not Found' error is returned for accounts that don't exist.
delete(Config) ->
	#{id := Akey} = ?config(user, Config),
	#{id := AkeyDisabled} = ?config(user_disabled, Config),
	AkeyNotExist = idp:make_uuid(),
	AuthorizationH = idp_cth:authorization_header(admin, Config),
	Test =
		[ %% account me (admin)
			{<<"/api/v1/accounts/me/enabled">>, 204},
			%% account exists
			{[<<"/api/v1/accounts/">>, Akey, <<"/enabled">>], 204},
			%% disabled account
			{[<<"/api/v1/accounts/">>, AkeyDisabled, <<"/enabled">>], 204},
			%% account doesn't exist
			{[<<"/api/v1/accounts/">>, AkeyNotExist, <<"/enabled">>], 404} ],

	[begin
		Pid = idp_cth:gun_open(Config),
		Ref = gun:request(Pid, <<"DELETE">>, Path, [AuthorizationH]),
		{Status, _Hs, <<>>} = idp_cth:gun_await(Pid, Ref)
	end || {Path, Status} <- Test].

%% Access is granted only for members of 'admin' (predefined) group.
delete_permissions_admin(Config) -> do_delete_permissions(204, [admin], Config).
delete_permissions(Config)       -> do_delete_permissions(403, ?config(accounts, Config) -- [admin], Config).

do_delete_permissions(Status, Accounts, Config) ->
	#{id := Akey} = ?config(user, Config),
	Path = [<<"/api/v1/accounts/">>, Akey, <<"/enabled">>],

	[begin
		Pid = idp_cth:gun_open(Config),
		Ref = gun:request(Pid, <<"DELETE">>, Path, idp_cth:authorization_headers(A, Config)),
		{Status, _Hs, _Body} = idp_cth:gun_await(Pid, Ref)
	end || A <- Accounts].
