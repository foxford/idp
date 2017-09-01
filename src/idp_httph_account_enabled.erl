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

-module(idp_httph_account_enabled).

-include("idp_log.hrl").

%% REST handler callbacks
-export([
	init/2,
	is_authorized/2,
	forbidden/2,
	resource_exists/2,
	delete_resource/2,
	content_types_accepted/2,
	content_types_provided/2,
	allowed_methods/2,
	options/2
]).

%% Content callbacks
-export([
	from_any/2,
	to_none/2
]).

%% Types
-record(state, {
	rdesc                :: map(),
	authconf             :: map(),
	key      = undefined :: undefined | iodata(),
	authm    = #{}       :: map(),
	r        = undefined :: undefined | riakauth_account:account()
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
			key = cowboy_req:binding(key, Req)},
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
	try idp:authorize_admin(Key, AuthM, Rdesc) of
		{ok, Skey, #{write := true}} -> {false, Req, State#state{key = Skey}};
		_                            -> {true, Req, State}
	catch T:R ->
		?ERROR_REPORT(idp_http_log:format_request(Req), T, R),
		{stop, cowboy_req:reply(422, Req), State}
	end.

resource_exists(#{method := Method} =Req, #state{key = Key, rdesc = Rdesc} =State) ->
	try idp_account:read(Key, Rdesc, read_options(Method)) of
		{ok, A} -> {true, Req, State#state{r = A}};
		_       -> {false, Req, State}
	catch T:R ->
		?ERROR_REPORT(idp_http_log:format_request(Req), T, R),
		{stop, cowboy_req:reply(422, Req), State}
	end.

delete_resource(Req, #state{key = Akey, r = A, rdesc = Rdesc} =State) ->
	idp_http:handle_response(Req, State, fun() ->
		idp_account:disable(Akey, A, Rdesc)
	end).

content_types_accepted(Req, State) ->
	Handlers = [{'*', from_any}],
	{Handlers, Req, State}.

content_types_provided(Req, State) ->
	Handlers = [{{<<"text">>, <<"plain">>, '*'}, to_none}],
	{Handlers, Req, State}.

allowed_methods(Req, State) ->
	Methods = [<<"GET">>, <<"PUT">>, <<"DELETE">>, <<"OPTIONS">>],
	{Methods, Req, State}.

options(Req0, State) ->
	Req1 = cowboy_req:set_resp_header(<<"access-control-allow-methods">>, <<"GET, PUT, DELETE">>, Req0),
	Req2 = cowboy_req:set_resp_header(<<"access-control-allow-headers">>, <<"authorization">>, Req1),
	Req3 = cowboy_req:set_resp_header(<<"access-control-allow-credentials">>, <<"true">>, Req2),
	{ok, Req3, State}.

%% =============================================================================
%% Content callbacks
%% =============================================================================

from_any(Req, #state{r = undefined} =State) ->
	{stop, cowboy_req:reply(404, Req), State};
from_any(Req, #state{key = Akey, r = A, rdesc = Rdesc} =State) ->
	idp_http:handle_response(Req, State, fun() ->
		idp_account:enable(Akey, A, Rdesc)
	end).

to_none(Req0, #state{r = A} =State) ->
	Req1 =
		case idp_account:is_enabled(A) of
			true -> cowboy_req:reply(204, Req0);
			_    -> cowboy_req:reply(404, Req0)
		end,
	{stop, Req1, State}.

%% =============================================================================
%% Internal functions
%% =============================================================================

%% We use strict quorum (pr=quorum) for create or update operations
%% on account's 'enable' property and sloppy quorum for read operations.
-spec read_options(binary()) -> [proplists:property()].
read_options(<<"GET">>)    -> [];
read_options(<<"PUT">>)    -> [{pr, quorum}];
read_options(<<"DELETE">>) -> [{pr, quorum}].
