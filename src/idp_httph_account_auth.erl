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

-module(idp_httph_account_auth).

-include("idp_log.hrl").

%% REST handler callbacks
-export([
	init/2,
	is_authorized/2,
	forbidden/2,
	resource_exists/2,
	delete_resource/2,
	content_types_provided/2,
	allowed_methods/2,
	options/2
]).

%% Types
-record(state, {
	rdesc                :: map(),
	authconf             :: map(),
	key      = undefined :: undefined | iodata(),
	identity = undefined :: undefined | iodata(),
	authm    = #{}       :: map(),
	rbox     = undefined :: undefined | idp_account_auth:rbox()
}).

%% =============================================================================
%% REST handler callbacks
%% =============================================================================

init(Req, Opts) ->
	#{authentication := AuthConf, resources := Rdesc} = Opts,
	State =
		#state{
			rdesc = Rdesc,
			authconf = AuthConf,
			key = cowboy_req:binding(key, Req),
			identity = cowboy_req:binding(identity, Req)},
	{cowboy_rest, Req, State}.

is_authorized(#{method := <<"OPTIONS">>} =Req, State)  -> {true, Req, State};
is_authorized(Req, #state{authconf = AuthConf} =State) ->
	try idp_http:decode_access_token(Req, AuthConf) of
		TokenPayload ->
			?INFO_REPORT([{access_token, TokenPayload} | idp_http_log:format_request(Req)]),
			{true, Req, State#state{authm = TokenPayload}}
	catch
		T:R ->
			?ERROR_REPORT(idp_http_log:format_unauthenticated_request(Req), T, R),
			{{false, idp_http:access_token_type()}, Req, State}
	end.

forbidden(#{method := <<"OPTIONS">>} =Req, State)                      -> {false, Req, State};
forbidden(Req, #state{key = Key, authm = AuthM, rdesc = Rdesc} =State) ->
	try idp:authorize_subject(Key, AuthM, Rdesc) of
		{ok, Skey, #{write := true}} -> {false, Req, State#state{key = Skey}};
		_                            -> {true, Req, State}
	catch T:R ->
		?ERROR_REPORT(idp_http_log:format_request(Req), T, R),
		{stop, cowboy_req:reply(422, Req), State}
	end.

resource_exists(Req, #state{key = Key, identity = Ibin, rdesc = Rdesc} =State) ->
	try idp_account_auth:read(Key, Ibin, Rdesc) of
		{ok, Rbox} -> {true, Req, State#state{rbox = Rbox}};
		_          -> {false, Req, State}
	catch T:R ->
		?ERROR_REPORT(idp_http_log:format_request(Req), T, R),
		{stop, cowboy_req:reply(422, Req), State}
	end.

delete_resource(Req, #state{key = Key, identity = Ibin, rbox = Rbox, rdesc = Rdesc} =State) ->
	idp_http:handle_response(Req, State, fun() ->
		jsx:encode(idp_account_auth:delete(Key, Ibin, Rbox, Rdesc))
	end).

content_types_provided(Req, State) ->
	Handlers = [{{<<"application">>, <<"json">>, '*'}, ignore}],
	{Handlers, Req, State}.

allowed_methods(Req, State) ->
	Methods = [<<"DELETE">>, <<"OPTIONS">>],
	{Methods, Req, State}.

options(Req0, State) ->
	Req1 = cowboy_req:set_resp_header(<<"access-control-allow-methods">>, <<"DELETE">>, Req0),
	Req2 = cowboy_req:set_resp_header(<<"access-control-allow-headers">>, <<"authorization">>, Req1),
	Req3 = cowboy_req:set_resp_header(<<"access-control-allow-credentials">>, <<"true">>, Req2),
	{ok, Req3, State}.
