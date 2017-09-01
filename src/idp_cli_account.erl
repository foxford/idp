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

-module(idp_cli_account).

-include("idp_log.hrl").

%% API
-export([
	create/2,
	create/3,
	remove/1
]).

%% Types
-type create_options() ::
	#{acl => [{binary(), riakacl_group:group()}],
		identities => [[binary()]],
		enable => boolean(),
		id => binary()}.

%% ============================================================================= 
%% API
%% ============================================================================= 

-spec create(create_options(), map()) -> map().
create(Opts, TokenOpts) ->
	#{account := #{pool := KVpool}, account_aclsubject := #{pool := KVpool}} = idp:resources(),
	KVpid = riakc_pool:lock(KVpool),
	Result = create(KVpid, Opts, TokenOpts),
	riakc_pool:unlock(KVpool, KVpid),
	Result.

-spec create(pid(), create_options(), map()) -> map().
create(KVpid, Opts, TokenOpts) ->
	#{account := #{bucket := Ab},
		account_aclsubject := #{bucket := AclSb}} = idp:resources(),
	#{expires_in := ExpiresIn,
		iss := Iss,
		aud := Aud,
		access_token := #{keyfile := KeyFile},
		refresh_token := #{alg := RefreshAlg}} = maps:merge(idp:tokens(), TokenOpts),

	{ok, Pem} = file:read_file(KeyFile),
	{Alg, Priv} = jose_pem:parse_key(Pem),
	Akey =
		case maps:find(id, Opts) of
			{ok, Val} -> Val;
			_         -> idp:make_uuid()
		end,
	Tpayload0 =
		#{iss => Iss,
			aud => Aud,
			sub => Akey},
	Tpayload1 =
		case ExpiresIn of
			infinity -> Tpayload0;
			_        -> Tpayload0#{exp => idp:unix_time() +ExpiresIn}
		end,
	AccessToken = jose_jws_compact:encode(Tpayload1, Alg, Priv),

	NowUs = idp:unix_time_us(),
	RefreshKey = idp_account:generate_refresh_token_key(RefreshAlg),
	HandleData =
		fun(Data0) ->
			Data1 = idp_account:update_refresh_token_dt(RefreshAlg, RefreshKey, NowUs, Data0),
			Data2 =
				case maps:get(enable, Opts, true) of
					true -> idp_account:update_enabled_dt(enable, Data1);
					_    -> Data1
				end,
			Data2
		end,
	RefreshToken =
		jose_jws_compact:encode(
			#{iss => Iss,
				aud => Aud,
				sub => Akey},
			RefreshAlg,
			RefreshKey),

	AclGroups = maps:get(acl, Opts, []),
	A0 = riakauth_account:update_data_dt(HandleData, riakauth_account:new_dt()),
	A1 =
		case maps:find(identities, Opts) of
			{ok, L}  -> lists:foldl(fun(I, Acc) -> riakauth_account:update_identity_dt(I, Acc) end, A0, L);
			_        -> A0
		end,

	_ = riakauth_account:put(KVpid, Ab, Akey, A1),
	_ = riakacl:put_subject_groups(KVpid, AclSb, Akey, AclGroups),
	?INFO_REPORT(
		[	{reason, access_token_issued},
			{access_token, Tpayload1},
			{aclgroups, [Gname || {Gname, _} <- AclGroups]} ]),

	#{id => Akey, access_token => AccessToken, refresh_token => RefreshToken}.

-spec remove(binary()) -> ok.
remove(Akey) ->
	#{account := #{pool := KVpool, bucket := Ab},
		account_aclsubject := #{pool := KVpool, bucket := AclSb}} = idp:resources(),
	KVpid = riakc_pool:lock(KVpool),
	riakacl_entry:remove(KVpid, AclSb, Akey),
	riakauth_account:remove(KVpid, Ab, Akey),
	riakc_pool:unlock(KVpool, KVpid),
	ok.
