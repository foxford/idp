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

-module(idp_httph_oauth2_token).

-include("idp_log.hrl").

%% REST handler callbacks
-export([
	init/2,
	is_authorized/2,
	forbidden/2,
	content_types_accepted/2,
	allowed_methods/2,
	options/2
]).

%% Content callbacks
-export([
	from_wform/2,
	from_json/2
]).

%% Types
-record(state, {
	op             :: create | link,
	rdesc          :: map(),
	tokens         :: map(),
	authconf       :: map(),
	idpsconf       :: map(),
	authm    = #{} :: map()
}).

%% =============================================================================
%% REST handler callbacks
%% =============================================================================

init(Req, Opts) ->
	#{operation := Op,
		resources := Rdesc,
		tokens := Tokens,
		authentication := AuthConf,
		identity_providers := IdpsConf} = Opts,
	State =
		#state{
			op = Op,
			rdesc = Rdesc,
			tokens = Tokens,
			authconf = AuthConf,
			idpsconf = IdpsConf},
	{cowboy_rest, Req, State}.

is_authorized(#{method := <<"OPTIONS">>} =Req, State)             -> {true, Req, State};
is_authorized(Req, #state{op = create} =State)                    -> {true, Req, State};
is_authorized(Req, #state{op = link, authconf = AuthConf} =State) ->
	try idp_http:decode_access_token(Req, AuthConf) of
		TokenPayload ->
			?INFO_REPORT([{access_token, TokenPayload}|idp_http_log:format_request(Req)]),
			{true, Req, State#state{authm = TokenPayload}}
	catch
		T:R ->
			?ERROR_REPORT(idp_http_log:format_unauthenticated_request(Req), T, R),
			{{false, idp_http:access_token_type()}, Req, State}
	end.

forbidden(#{method := <<"OPTIONS">>} =Req, State)                   -> {false, Req, State};
forbidden(Req, #state{op = create} =State)                          -> {false, Req, State};
forbidden(Req, #state{op = link, authm = #{<<"sub">> := _}} =State) -> {false, Req, State};
forbidden(Req, State)                                               -> {true, Req, State}.

content_types_accepted(Req, State) ->
	Handlers =
		[	{{<<"application">>, <<"json">>, '*'}, from_json},
			{{<<"application">>, <<"x-www-form-urlencoded">>, '*'}, from_wform} ],
	{Handlers, Req, State}.

allowed_methods(Req, State) ->
	Methods = [<<"POST">>, <<"OPTIONS">>],
	{Methods, Req, State}.

options(Req0, State) ->
	Req1 = cowboy_req:set_resp_header(<<"access-control-allow-methods">>, <<"POST">>, Req0),
	Req2 = cowboy_req:set_resp_header(<<"access-control-allow-headers">>, <<"authorization, content-length, content-type">>, Req1),
	Req3 = cowboy_req:set_resp_header(<<"access-control-allow-credentials">>, <<"true">>, Req2),
	{ok, Req3, State}.

%% =============================================================================
%% Content callbacks
%% =============================================================================

%% According to RFC 6749 - The OAuth 2.0 Authorization Framework
%% 5.2. Issuing an Access Token. Error Response
%% https://tools.ietf.org/html/rfc6749#section-5.2
from_wform(Req, #state{rdesc = Rdesc, tokens = Tokens, idpsconf = IdpsConf, authm = AuthM, op = Op} =State) ->
	FailureContentType = <<"application/x-www-form-urlencoded">>,
	SuccessContentType = <<"application/json">>,
	idp_http:control_payload(
		Req, State, #{},
		fun(Payload, Sreq) ->
			L = cow_qs:parse_qs(Payload),
			{_, <<"client_credentials">>} = lists:keyfind(<<"grant_type">>, 1, L),
			{_, ClientToken} = lists:keyfind(<<"client_token">>, 1, L),
			#{options :=
				#{key := Key,
					alg := Alg,
					verify_options := Opts}} = IdpsConf,
			ClientTokenPayload = jose_jws_compact:decode(ClientToken, Alg, Key, Opts#{parse_payload => map}),
			idp_http:control_response(
				Sreq, State, SuccessContentType,
				fun() ->
					case Op of
						create -> idp_account:create(ClientTokenPayload, Rdesc, Tokens, IdpsConf);
						link   -> idp_account:link(ClientTokenPayload, AuthM, Rdesc, Tokens, IdpsConf)
					end
				end,
				fun(_Fpayload, Freq, Fstate) ->
					RespHeaders = #{<<"content-type">> => FailureContentType},
					RespPayload = <<"error=invalid_client">>,
					{stop, cowboy_req:reply(400, RespHeaders, RespPayload, Freq), Fstate}
				end)
		end,
		fun(_Fpayload, Freq, Fstate) ->
			RespHeaders = #{<<"content-type">> => FailureContentType},
			RespPayload = <<"error=invalid_request">>,
			{stop, cowboy_req:reply(400, RespHeaders, RespPayload, Freq), Fstate}
		end).

%% According to RFC 6749 - The OAuth 2.0 Authorization Framework
%% 5.2. Issuing an Access Token. Error Response
%% https://tools.ietf.org/html/rfc6749#section-5.2
from_json(Req0, #state{rdesc = Rdesc, tokens = Tokens, idpsconf = IdpsConf, authm = AuthM, op = Op} =State) ->
	ContentType = <<"application/json">>,
	idp_http:control_payload(
		Req0, State, #{},
		fun(Payload, Req1) ->
			L = jsx:decode(Payload),
			{_, <<"client_credentials">>} = lists:keyfind(<<"grant_type">>, 1, L),
			{_, ClientToken} = lists:keyfind(<<"client_token">>, 1, L),
			#{options :=
				#{key := Key,
					alg := Alg,
					verify_options := Opts}} = IdpsConf,
			ClientTokenPayload = jose_jws_compact:decode(ClientToken, Alg, Key, Opts#{parse_payload => map}),
			idp_http:control_response(
				Req1, State, ContentType,
				fun() ->
					case Op of
						create -> idp_account:create(ClientTokenPayload, Rdesc, Tokens, IdpsConf);
						link   -> idp_account:link(ClientTokenPayload, AuthM, Rdesc, Tokens, IdpsConf)
					end
				end,
				fun(_Fpayload, Freq, Fstate) ->
					RespHeaders = #{<<"content-type">> => ContentType},
					RespPayload = idp_http:encode_payload(ContentType, #{error => invalid_client}),
					{stop, cowboy_req:reply(400, RespHeaders, RespPayload, Freq), Fstate}
				end)
		end,
		fun(Fpayload, Freq, Fstate) ->
			RespHeaders = #{<<"content-type">> => ContentType},
			RespPayload = idp_http:encode_payload(ContentType, #{error => invalid_request, error_description => Fpayload}),
			{stop, cowboy_req:reply(400, RespHeaders, RespPayload, Freq), Fstate}
		end).
