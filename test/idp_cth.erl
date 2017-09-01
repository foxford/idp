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

-module(idp_cth).

-include_lib("riakc/include/riakc.hrl").

%% API
-export([
	init_config/0,
	gun_open/1,
	gun_await/2,
	gun_await_json/2,
	gun_down/1,
	make_uid/0,
	authorization_headers/2,
	authorization_header/2
]).

%% =============================================================================
%% API
%% =============================================================================

-spec init_config() -> list().
init_config() ->
	[].

-spec gun_open(list()) -> pid().
gun_open(_Config) ->
	Host = "localhost",
	{_, Port} = lists:keyfind(port, 1, idp:http_options()),
	{ok, Pid} = gun:open(Host, Port, #{retry => 0, protocols => [http2], transport => ssl}),
	Pid.

-spec gun_down(pid()) -> ok.
gun_down(Pid) ->
	receive {gun_down, Pid, _, _, _, _} -> ok
	after 500 -> error(timeout) end.

-spec gun_await(pid(), reference()) -> {100..999, [{binary(), iodata()}], binary()}.
gun_await(Pid, Ref) ->
	case gun:await(Pid, Ref) of
		{response, fin, St, Hs}   -> {St, Hs, <<>>};
		{response, nofin, St, Hs} ->
			{ok, Body} = gun:await_body(Pid, Ref),
			{St, Hs, Body}
	end.

-spec gun_await_json(pid(), reference()) -> {100..999, [{binary(), iodata()}], map()}.
gun_await_json(Pid, Ref) ->
	{St, Hs, Body} = gun_await(Pid, Ref),
	try {St, Hs, jsx:decode(Body, [return_maps, strict])}
	catch _:_ -> error({bad_response, {St, Hs, Body}}) end.

-spec make_uid() -> iodata().
make_uid() ->
	list_to_binary(vector(8, alphanum_chars())).

-spec authorization_headers(atom(), list()) -> [{binary(), iodata()}].
authorization_headers(anonymous, _Config) -> [];
authorization_headers(Account, Config)    -> [authorization_header(Account, Config)].

-spec authorization_header(atom(), list()) -> {binary(), iodata()}.
authorization_header(Account, Config) ->
	{_, #{access_token := Token}} = lists:keyfind(Account, 1, Config),
	{<<"authorization">>, [<<"Bearer ">>, Token]}.

%%% =============================================================================
%%% Internal functions
%%% =============================================================================

-spec oneof(list()) -> integer().
oneof(L) ->
	lists:nth(rand:uniform(length(L)), L).

-spec vector(non_neg_integer(), list()) -> list().
vector(MaxSize, L) ->
	vector(0, MaxSize, L, []).

-spec vector(non_neg_integer(), non_neg_integer(), list(), list()) -> list().
vector(Size, MaxSize, L, Acc) when Size < MaxSize ->
	vector(Size +1, MaxSize, L, [oneof(L)|Acc]);
vector(_, _, _, Acc) ->
	Acc.

-spec alphanum_chars() -> list().
alphanum_chars() ->
	"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".
