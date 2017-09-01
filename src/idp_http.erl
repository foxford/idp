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

-module(idp_http).

-include("idp_log.hrl").

%% API
-export([
	start/0,
	access_token_type/0,
	access_token/1,
	find_access_token/1,
	decode_access_token/2,
	decode_refresh_token/3,
	handle_response/3,
	handle_response/4,
	control_response/5,
	handle_payload/3,
	handle_payload/4,
	handle_payload/5,
	control_payload/5,
	encode_payload/2
]).

%% Definitions
-define(DEFAULT_CONTENT_TYPE, <<"application/json">>).
-define(AUTHORIZATION, <<"authorization">>).
-define(BEARER, <<"Bearer">>).

%% Types

%% TODO: probably it shoud be just an opaque binary,
%% because we can't control all possible error reasons,
%% but we can convert them to a binary instead.
%% On the other hand, there is could be a problem with binary
%% (which is encoded json for instance) - creating nesting data structures.
-type payload() :: map() | binary().

%% =============================================================================
%% API
%% =============================================================================

start() ->
	Env =
		#{dispatch => dispatch(),
			allowed_origins => idp:allowed_origins(),
			preflight_request_max_age => idp:preflight_request_max_age()},
	HttpOpts = idp:http_options(),
	HttpdRequiredOpts =
		#{stream_handlers => [idp_streamh_log, cowboy_stream_h],
			middlewares => [idp_httpm_cors, cowboy_router, cowboy_handler],
			env => Env},
	HttpdStart =
		case lists:keyfind(certfile, 1, HttpOpts) of
			{certfile, _Val} -> start_tls;
			_                -> start_clear
		end,
	cowboy:HttpdStart(
		httpd,
		HttpOpts,
		maps:merge(HttpdRequiredOpts, idp:httpd_options())).

-spec dispatch() -> cowboy_router:dispatch_rules().
dispatch() ->
	cowboy_router:compile(routes()).

-spec access_token_type() -> binary().
access_token_type() -> ?BEARER.

-spec find_access_token(cowboy_req:req()) -> {ok, binary()} | error.
find_access_token(Req) ->
	case cowboy_req:parse_header(?AUTHORIZATION, Req) of
		{bearer, Token} -> {ok, Token};
		_               -> error
	end.

-spec access_token(cowboy_req:req()) -> binary().
access_token(Req) ->
	case find_access_token(Req) of
		{ok, Token} -> Token;
		_           -> throw(missing_access_token)
	end.

-spec decode_access_token(cowboy_req:req(), map()) -> map().
decode_access_token(Req, AuthConf) ->
	case find_access_token(Req) of
		{ok, Token} -> idp:decode_access_token(Token, AuthConf);
		_           -> #{}
	end.

-spec decode_refresh_token(cowboy_req:req(), map(), map()) -> map().
decode_refresh_token(Req, AuthConf, Rdesc) ->
	case find_access_token(Req) of
		{ok, Token} -> idp:decode_refresh_token(Token, AuthConf, Rdesc);
		_           -> #{}
	end.

-spec handle_response(Req, State, HandleSuccess) -> {Result, Req, State}
	when
		Req           :: cowboy_req:req(),
		State         :: any(),
		HandleSuccess :: fun(() -> ok | binary() | map()),
		Result        :: true | stop | binary().
handle_response(Req, State, Handler) ->
	handle_response(Req, State, ?DEFAULT_CONTENT_TYPE, Handler).

-spec handle_response(Req, State, ContentType, HandleSuccess) -> {Result, Req, State}
	when
		Req           :: cowboy_req:req(),
		State         :: any(),
		ContentType   :: binary(),
		HandleSuccess :: fun(() -> ok | binary() | map()),
		Result        :: true | stop | binary().
handle_response(Req, State, ContentType, HandleSuccess) ->
	HandleFailure =
		fun(_Fpayload, Freq, Fstate) ->
			{stop, cowboy_req:reply(422, Freq), Fstate}
		end,
	control_response(Req, State, ContentType, HandleSuccess, HandleFailure).

-spec control_response(Req, State, ContentType, HandleSuccess, HandleFailure) -> {Result, Req, State}
	when
		Req           :: cowboy_req:req(),
		State         :: any(),
		ContentType   :: binary(),
		HandleSuccess :: fun(() -> ok | binary() | map()),
		HandleFailure :: fun((payload(), Req, any()) -> {Result, Req, State}),
		Result        :: true | stop | binary().
control_response(Req, State, ContentType, HandleSuccess, HandleFailure) ->
	AfterSuccess =
		fun
			(<<"GET">>, Body)    -> {encode_payload(ContentType, Body), Req, State};
			(<<"HEAD">>, Body)   -> {encode_payload(ContentType, Body), Req, State};
			(_Method, ok)        -> {true, Req, State};
			(_Method, Body) ->
				Req2 = cowboy_req:set_resp_header(<<"content-type">>, ContentType, Req),
				Req3 = cowboy_req:set_resp_body(encode_payload(ContentType, Body), Req2),
				{true, Req3, State}
		end,
	try HandleSuccess() of
		Body -> AfterSuccess(maps:get(method, Req), Body)
	catch
		T:R ->
			?ERROR_REPORT(idp_http_log:format_request(Req), T, R),
			%% TODO: provide an informative error payload as a first argument
			HandleFailure(#{}, Req, State)
	end.

-spec handle_payload(Req, State, HandleSuccess) -> {Result, Req, State}
	when
		Req             :: cowboy_req:req(),
		State           :: any(),
		HandleSuccess   :: fun((any(), Req) -> {Result, Req, State}),
		Result          :: true | stop | binary().
handle_payload(Req, State, HandleSuccess) ->
	handle_payload(Req, State, #{}, HandleSuccess).

-spec handle_payload(Req, State, ReadOpts, HandleSuccess) -> {Result, Req, State}
	when
		Req             :: cowboy_req:req(),
		State           :: any(),
		ReadOpts        :: map(),
		HandleSuccess   :: fun((any(), Req) -> {Result, Req, State}),
		Result          :: true | stop | binary().
handle_payload(Req, State, ReadOpts, HandleSuccess) ->
	handle_payload(Req, State, ReadOpts, ?DEFAULT_CONTENT_TYPE, HandleSuccess).

-spec handle_payload(Req, State, ReadOpts, RespContentType, HandleSuccess) -> {Result, Req, State}
	when
		Req             :: cowboy_req:req(),
		State           :: any(),
		ReadOpts        :: map(),
		RespContentType :: binary(),
		HandleSuccess   :: fun((any(), Req) -> {Result, Req, State}),
		Result          :: true | stop | binary().
handle_payload(Req, State, ReadOpts, RespContentType, HandleSuccess) ->
	HandleFailure =
		fun
			%% Only POST, PUT, PATCH requests have a payload
			(Fpayload, Freq0, Fstate) ->
				Freq1 = cowboy_req:set_resp_header(<<"content-type">>, RespContentType, Freq0),
				Freq2 = cowboy_req:set_resp_body(encode_payload(RespContentType, Fpayload), Freq1),
				{false, Freq2, Fstate}
		end,
	control_payload(Req, State, ReadOpts, HandleSuccess, HandleFailure).

-spec control_payload(Req, State, ReadOpts, HandleSuccess, HandleFailure) -> {Result, Req, State}
	when
		Req             :: cowboy_req:req(),
		State           :: any(),
		ReadOpts        :: map(),
		HandleSuccess   :: fun((any(), Req) -> {Result, Req, State}),
		HandleFailure   :: fun((payload(), Req, any()) -> {Result, Req, State}),
		Result          :: true | stop | binary().
control_payload(Req0, State, ReadOpts, HandleSuccess, HandleFailure) ->
	case cowboy_req:read_body(Req0, ReadOpts) of
		{ok, <<>>, Req1} ->
			HandleFailure(#{error => missing_payload}, Req1, State);
		{ok, Body, Req1} ->
			try HandleSuccess(Body, Req1)
			catch T:R ->
				?ERROR_REPORT(idp_http_log:format_request(Req1), T, R),
				HandleFailure(#{error => bad_payload, payload => Body}, Req1, State)
			end;
		{more, _, Req1}  ->
			HandleFailure(#{error => bad_payload_length}, Req1, State)
	end.

-spec encode_payload(binary(), payload()) -> iodata().
encode_payload(_ContentType, Body) when is_binary(Body) -> Body;
encode_payload(<<"application/json", _/bits>>, Body)    -> jsx:encode(Body);
encode_payload(ContentType, _Body)                      -> error({unsupported_content_type, ContentType}).

%% =============================================================================
%% Internal functions
%% =============================================================================

-spec routes() -> list(tuple()).
routes() ->
	Auth =
		lists:foldl(
			fun
				(#{key := [<<"oauth2">> | _] = Key, options := Opts} = Conf0, Acc) ->
					Conf1 =
						try
							#{resources => idp:resources(),
								tokens => idp:tokens(),
								authentication => idp:authentication(),
								identity_providers => Conf0#{options => load_auth_key(Opts)}}
						catch throw:Reason -> error({bad_auth_config, Reason, Conf0}) end,
					[	authtoken_route(Key, idp_httph_oauth2_token, Conf1),
						authlink_route(Key, idp_httph_oauth2_token, Conf1)
						| Acc ];
				(Conf, _Acc) ->
					error({bad_auth_config, bad_prot, Conf})
			end, [], idp:identity_providers()),

	Opts = #{resources => idp:resources(), authentication => idp:authentication()},
	AuthKeys = [AuthKey || #{key := AuthKey} <- idp:identity_providers()],
	Accounts =
		[	{<<"/api[/v1]/accounts/:key/refresh">>, idp_httph_account_refresh, Opts#{tokens => idp:tokens()}},
			{<<"/api[/v1]/accounts/:key/revoke">>, idp_httph_account_revoke, Opts#{tokens => idp:tokens()}},
			{<<"/api[/v1]/accounts/:key/enabled">>, idp_httph_account_enabled, Opts},
			{<<"/api[/v1]/accounts/:key/auth/:identity">>, idp_httph_account_auth, Opts},
			{<<"/api[/v1]/accounts/:key/auth">>, idp_httph_account_auths, Opts#{authentication_keys => AuthKeys}},
			{<<"/api[/v1]/accounts/:key">>, idp_httph_account, Opts} ],

	[{'_', Auth ++ Accounts}].

-spec load_auth_key(map()) -> map().
load_auth_key(#{alg := _, key := _} =M) -> M;
load_auth_key(#{keyfile := Path} =M) ->
	try
		{ok, Pem} = file:read_file(idp:conf_path(Path)),
		{Alg, Key} = jose_pem:parse_key(Pem),
		M#{alg => Alg, key => Key}
	catch _:_ ->
		throw({bad_keyfile, Path})
	end;
load_auth_key(_) ->
	throw(missing_key).

-spec authtoken_route(idp_auth:key(), module(), map()) -> tuple().
authtoken_route([Prot, Prov], Handler, Opts) ->
	KeyB = <<Prot/binary, $., Prov/binary>>,
	Uri = <<"/api[/v1]/auth/", KeyB/binary, "/token">>,
	{Uri, Handler, Opts#{operation => create}}.

-spec authlink_route(idp_auth:key(), module(), map()) -> tuple().
authlink_route([Prot, Prov], Handler, Opts) ->
	KeyB = <<Prot/binary, $., Prov/binary>>,
	Uri = <<"/api[/v1]/auth/", KeyB/binary, "/link">>,
	{Uri, Handler, Opts#{operation => link}}.
