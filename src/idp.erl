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

-module(idp).

%% API
-export([
	unix_time/0,
	unix_time/1,
	unix_time_us/0,
	unix_time_us/1,
	make_uuid/0,
	priv_path/1,
	conf_path/1,
	authorize_subject/3,
	authorize_admin/3,
	decode_access_token/2,
	decode_refresh_token/3
]).

%% Configuration
-export([
	http_options/0,
	httpd_options/0,
	allowed_origins/0,
	preflight_request_max_age/0,
	riak_connection_pools/0,
	identity_providers/0,
	tokens/0,
	authentication/0,
	resources/0
]).

%% Definitions
-define(APP, ?MODULE).

%% =============================================================================
%% API
%% =============================================================================

-spec unix_time() -> non_neg_integer().
unix_time() ->
	unix_time(erlang:timestamp()).

-spec unix_time(erlang:timestamp()) -> non_neg_integer().
unix_time({MS, S, _US}) ->
	MS * 1000000 + S.

-spec unix_time_us() -> non_neg_integer().
unix_time_us() ->
	unix_time_us(erlang:timestamp()).

-spec unix_time_us(erlang:timestamp()) -> non_neg_integer().
unix_time_us({MS, S, US}) ->
	MS * 1000000000000 + S * 1000000 + US.

-spec make_uuid() -> binary().
make_uuid() ->
	uuid:uuid_to_string(uuid:get_v4(), binary_standard).

-spec priv_path(binary()) -> binary().
priv_path(Path) ->
	Priv =
		case code:priv_dir(?APP) of
			{error, _} -> "priv";
			Dir        -> Dir
		end,
	<<(list_to_binary(Priv))/binary, $/, Path/binary>>.

-spec conf_path(binary()) -> binary().
conf_path(Path) ->
	case filename:pathtype(Path) of
		relative -> priv_path(Path);
		_        -> Path
	end.

-spec authorize_subject(binary(), map(), map()) -> {ok, binary(), map()} | {error, any()}.
authorize_subject(Akey, AuthM, Rdesc) ->
	#{account_aclsubject := #{bucket := Sb, pool := KVpool},
		admin_aclgroup := AdminGroupName} = Rdesc,

	OwnerRW = AdminRW = #{read => true, write => true},
	AdminAccess = {AdminGroupName, AdminRW},
	KVpid = riakc_pool:lock(KVpool),
	Result =
		case maps:find(<<"sub">>, AuthM) of
			{ok, Skey} when Akey =:= <<"me">> -> {ok, Skey, OwnerRW};
			{ok, Skey} when Akey =:= Skey     -> {ok, Akey, OwnerRW};
			{ok, Skey} ->
				case riakacl:authorize_predefined_object(KVpid, Sb, Skey, [AdminAccess], riakacl_rwaccess) of
					{ok, RW} -> {ok, Akey, RW};
					Err      -> Err
				end;
			_ ->
				{error, missing_aclsubject_key}
		end,
	riakc_pool:unlock(KVpool, KVpid),
	Result.

-spec authorize_admin(binary(), map(), map()) -> {ok, binary(), map()} | {error, any()}.
authorize_admin(Akey, AuthM, Rdesc) ->
	#{account_aclsubject := #{bucket := Sb, pool := KVpool},
		admin_aclgroup := AdminGroupName} = Rdesc,

	AdminRW = #{read => true, write => true},
	AdminAccess = {AdminGroupName, AdminRW},
	KVpid = riakc_pool:lock(KVpool),
	Result =
		case maps:find(<<"sub">>, AuthM) of
			{ok, Skey} ->
				case riakacl:authorize_predefined_object(KVpid, Sb, Skey, [AdminAccess], riakacl_rwaccess) of
					{ok, RW} ->
						case Akey of
							<<"me">> -> {ok, Skey, RW};
							_        -> {ok, Akey, RW}
						end;
					Err ->
						Err
				end;
			_ ->
				{error, missing_aclsubject_key}
		end,
	riakc_pool:unlock(KVpool, KVpid),
	Result.

-spec decode_access_token(binary(), map()) -> map().
decode_access_token(Token, AuthConf) ->
	jose_jws_compact:decode_fn(
		fun(Data, _Opts) -> select_authentication_key(Data, AuthConf) end,
		Token).

-spec decode_refresh_token(binary(), map(), map()) -> map().
decode_refresh_token(Token, _AuthConf, Rdesc) ->
	jose_jws_compact:decode_fn(
		fun([ _, #{<<"sub">> := Akey} | _ ], Opts) ->
			#{account := #{bucket := Ab, pool := KVpool}} = Rdesc,
			KVpid = riakc_pool:lock(KVpool),
			MaybeA = riakauth_account:find(KVpid, Ab, Akey),
			riakc_pool:unlock(KVpool, KVpid),

			case MaybeA of
				{ok, A} ->
					case  idp_account:refresh_token_dt(A) of
						#{alg := RefreshAlg, key := RefreshKey} -> {ok, {RefreshAlg, RefreshKey, Opts}};
						_                                       -> {error, missing_refresh_token}
					end;
				_ ->
					{error, bad_account_key}
			end
		end,
		Token).

%% =============================================================================
%% Configuration
%% =============================================================================

-spec http_options() -> list().
http_options() ->
	Default =
		[	{port, 8443},
			{certfile, conf_path(<<"ssl/idp.crt">>)},
			{keyfile, conf_path(<<"ssl/idp.key">>)} ],
	application:get_env(?APP, ?FUNCTION_NAME, Default).

-spec httpd_options() -> map().
httpd_options() ->
	application:get_env(?APP, ?FUNCTION_NAME, #{}).

-spec allowed_origins() -> Origin | [Origin] | '*' when Origin :: {binary(), binary(), 0..65535}.
allowed_origins() ->
	application:get_env(?APP, ?FUNCTION_NAME, '*').

-spec preflight_request_max_age() -> binary().
preflight_request_max_age() ->
	application:get_env(?APP, ?FUNCTION_NAME, <<"0">>).

-spec riak_connection_pools() -> [map()].
riak_connection_pools() ->
	case application:get_env(?APP, ?FUNCTION_NAME) of
		{ok, Val} -> Val;
		_ ->
			%% Getting default values from the Docker environment
			%% configuration file, if it's available.
			try
				{ok, S, _} = erl_scan:string(os:getenv("DEVELOP_ENVIRONMENT")),
				{ok, Conf} = erl_parse:parse_term(S),
				#{kv_protobuf := #{host := Host, port := Port}} = Conf,
				[	#{name => kv_protobuf,
						size => 5,
						connection =>
							#{host => Host,
								port => Port,
								options => [queue_if_disconnected]}} ]
			catch _:Reason -> error({missing_develop_environment, ?FUNCTION_NAME, Reason}) end
	end.

-spec identity_providers() -> list().
identity_providers() ->
	DevelopConf =
		[ %% oauth2.example
			#{key => [<<"oauth2">>, <<"example">>],
				options =>
					#{access => #{admin => true, moderator => true},
						keyfile => conf_path(<<"keys/example.pub.pem">>),
						verify_options => #{verify => [exp, {iss, <<"example.org">>}]}}},
			%% oauth2.example-restricted
			#{key => [<<"oauth2">>, <<"example-restricted">>],
				options =>
					#{access => #{},
						keyfile => conf_path(<<"keys/example.pub.pem">>),
						verify_options => #{verify => [exp, {iss, <<"example.org">>}]}}} ],
		Default = [],
		case application:get_env(?APP, ?FUNCTION_NAME) of
			{ok, Val} -> Val;
			_ ->
				%% Getting development values, if environment variable is defined.
				case os:getenv("DEVELOP_ENVIRONMENT") of
					Env when Env =:= false; Env =:= [] -> Default;
					_                                  -> DevelopConf
				end
		end.

-spec tokens() -> map().
tokens() ->
	DevelopConf =
		#{type => <<"Bearer">>,
			expires_in => 600, %% 10 minutes
			iss => <<"idp.example.org">>,
			aud => <<"app.example.org">>,
			access_token => #{keyfile => conf_path(<<"keys/idp.priv.pem">>)},
			refresh_token => #{alg => <<"HS256">>}},
	M =
		case application:get_env(?APP, ?FUNCTION_NAME) of
			{ok, Val} -> Val;
			_ ->
				%% Getting development values, if environment variable is defined.
				case os:getenv("DEVELOP_ENVIRONMENT") of
					Env when Env =:= false; Env =:= [] -> error(missing_access_token_options_config);
					_                                  -> DevelopConf
				end
		end,
	M#{access_token => load_auth_key(maps:get(access_token, M))}.

-spec authentication() -> map().
authentication() ->
	%% Examples:
	%% #{<<"iss">> =>
	%% 		#{keyfile => <<"keys/example.pem">>,
	%% 			verify_options => DefaultVerifyOpts}}
	%% #{{<<"iss">>, <<"kid">>} =>
	%% 		#{keyfile => <<"keys/example.pem">>,
	%% 			verify_options => DefaultVerifyOpts}}
	DevelopConf =
		#{<<"idp.example.org">> =>
				#{keyfile => conf_path(<<"keys/idp.pub.pem">>),
					verify_options => #{verify => [exp]}}},
	DefaultVerifyOpts =
		#{parse_header => map,
			parse_payload => map,
			parse_signature => binary,
			verify => [exp, nbf, iat],
			leeway => 1},
	Default = #{},
	M =
		case application:get_env(?APP, ?FUNCTION_NAME) of
			{ok, Val} -> Val;
			_ ->
				%% Getting development values, if environment variable is defined.
				case os:getenv("DEVELOP_ENVIRONMENT") of
					Env when Env =:= false; Env =:= [] -> Default;
					_                                  -> DevelopConf
				end
		end,
	try configure_auth(M, DefaultVerifyOpts)
	catch throw:R -> error({invalid_authentication_config, R, M}) end.

-spec resources() -> map().
resources() ->
	Default =
		#{account =>
				#{pool => kv_protobuf,
					bucket => {<<"idp_account_t">>, <<"idp-account">>},
					index => <<"idp_account_idx">>,
					handler => idp_accounth_stub},
			account_aclsubject =>
				#{pool => kv_protobuf,
					bucket => {<<"idp_account_aclsubject_t">>, <<"idp-account-aclsubject">>}},
			anonymous_aclgroup => <<"anonymous">>,
			admin_aclgroup => <<"admin">>},
	application:get_env(?APP, ?FUNCTION_NAME, Default).

%% =============================================================================
%% Internal functions
%% =============================================================================

-spec configure_auth(map(), map()) -> map().
configure_auth(M, DefaultVerifyOpts) ->
	maps:map(
		fun(_Iss, Conf) ->
			load_auth_key(Conf#{verify_options => maps:merge(DefaultVerifyOpts, maps:get(verify_options, Conf, #{}))})
		end, M).

-spec load_auth_key(map()) -> map().
load_auth_key(#{alg := _, key := _} =M) -> M;
load_auth_key(#{keyfile := Path} =M) ->
	try
		{ok, Pem} = file:read_file(conf_path(Path)),
		{Alg, Key} = jose_pem:parse_key(Pem),
		M#{alg => Alg, key => Key}
	catch _:_ ->
		throw({bad_keyfile, Path})
	end;
load_auth_key(_) ->
	throw(missing_key).

-spec select_authentication_key(list(), map()) -> jose_jws_compact:select_key_result().
select_authentication_key([ _, #{<<"iss">> := Iss} | _ ], Conf) ->
	select_authentication_config(Iss, Conf);
select_authentication_key([ #{<<"kid">> := Kid}, #{<<"iss">> := Iss} | _ ], Conf) ->
	select_authentication_config({Iss, Kid}, Conf);
select_authentication_key(_Data, _Conf) ->
	{error, missing_access_token_iss}.

-spec select_authentication_config(binary() | {binary(), binary()}, map()) -> jose_jws_compact:select_key_result().
select_authentication_config(IssKid, Conf) ->
	case maps:find(IssKid, Conf) of
		{ok, M} ->
			#{alg := Alg, key := Key, verify_options := Opts} = M,
			{ok, {Alg, Key, Opts}};
		_ ->
			{error, {missing_authentication_config, IssKid}}
	end.
