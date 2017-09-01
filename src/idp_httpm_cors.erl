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

-module(idp_httpm_cors).

%% Middleware callbacks
-export([
	execute/2
]).

%% Definitions
-define(DEFAULT_ALLOWED_ORIGINS, '*').

%% =============================================================================
%% Middleware callbacks
%% =============================================================================

-spec execute(Req, Env) -> {ok | stop, Req, Env} when Req :: cowboy_req:req(), Env :: any().
execute(#{headers := #{<<"origin">> := HeaderVal}} =Req0, Env) ->
	[Origin] = cow_http_hd:parse_origin(HeaderVal),
	case check_origin(Origin, maps:get(allowed_origins, Env, ?DEFAULT_ALLOWED_ORIGINS)) of
		true ->
			Req1 = cowboy_req:set_resp_header(<<"access-control-allow-origin">>, HeaderVal, Req0),
			Req2 = cowboy_req:set_resp_header(<<"vary">>, <<"Origin">>, Req1),
			Req3 = maybe_set_access_control_max_age_header(Req2, Env),
			{ok, Req3, Env};
		_ ->
			{ok, Req0, Env}
	end;
execute(Req, Env) ->
	{ok, Req, Env}.

%% =============================================================================
%% Internal functions
%% =============================================================================

-spec check_origin(Origin, Origin | [Origin] | '*') -> boolean() when Origin :: {binary(), binary(), 0..65535} | reference().
check_origin(Val, '*') when is_reference(Val) -> true;
check_origin(_, '*')                          -> true;
check_origin(Val, Val)                        -> true;
check_origin(Val, L) when is_list(L)          -> lists:member(Val, L);
check_origin(_, _)                            -> false.

maybe_set_access_control_max_age_header(#{method := <<"OPTIONS">>} =Req, #{preflight_request_max_age := <<"0">>}) ->
	Req;
maybe_set_access_control_max_age_header(#{method := <<"OPTIONS">>} =Req, #{preflight_request_max_age := Val}) ->
	cowboy_req:set_resp_header(<<"access-control-max-age">>, Val, Req);
maybe_set_access_control_max_age_header(Req, _Env) ->
	Req.
