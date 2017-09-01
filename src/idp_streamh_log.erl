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

-module(idp_streamh_log).
-behaviour(cowboy_stream).

-include("idp_log.hrl").

%% Stream handler callbacks
-export([
	init/3,
	data/4,
	info/3,
	terminate/3,
	early_error/5
]).

%% Types
-record(state, {
	next :: any(),
	cat  :: non_neg_integer(),
	ctx  :: idp_http_log:kvlist()
}).

%% =============================================================================
%% Stream handler callbacks
%% =============================================================================

init(StreamId, Req, Opts) ->
	_ = exometer:update([idp,request,http,count], 1),

	StartedAt = idp:unix_time_us(),
	Context = [{http_started_at, StartedAt} | idp_http_log:format_request(Req)],
	?INFO_REPORT(Context),

	{Ncmd, Nstate} = cowboy_stream:init(StreamId, Req, Opts),
	{Ncmd, #state{next = Nstate, cat = StartedAt, ctx = Context}}.

data(StreamId, IsFin, Data, #state{next = Nstate0} =State) ->
	{Ncmd, Nstate1} = cowboy_stream:data(StreamId, IsFin, Data, Nstate0),
	{Ncmd, State#state{next = Nstate1}}.

info(StreamId, Response, #state{next = Nstate0, cat = StartedAt, ctx = Context} =State) ->
	_ =
		case Response of
			{response, Status, Headers, _Body} -> handle_response(StartedAt, Status, Headers, Context);
			{headers, Status, Headers}         -> handle_response(StartedAt, Status, Headers, Context);
			_                                  -> ignore
		end,
	{Ncmd, Nstate1} = cowboy_stream:info(StreamId, Response, Nstate0),
	{Ncmd, State#state{next = Nstate1}}.

terminate(StreamId, Reason, #state{next = Nstate, ctx = Context, cat = StartedAt}) ->
	handle_terminate(Reason, StartedAt, Context),
	cowboy_stream:terminate(StreamId, Reason, Nstate).

early_error(StreamId, Reason, PartialReq, Resp, Opts) ->
	?ERROR_REPORT(idp_http_log:format_request(PartialReq)),
	cowboy_stream:early_error(StreamId, Reason, PartialReq, Resp, Opts).

%% =============================================================================
%% Internal function
%% =============================================================================

-spec handle_response(non_neg_integer(), integer(), map(), idp_http_log:kvlist()) -> ok.
handle_response(StartedAt, Status, Headers, Context) ->
	Duration = duration(StartedAt),
	_ = exometer:update([idp,request,http,duration], Duration),
	?INFO_REPORT([{http_duration, Duration} | idp_http_log:format_response(Status, Headers, Context)]).

-spec handle_terminate(atom(), non_neg_integer(), idp_http_log:kvlist()) -> ok.
handle_terminate(normal, _StartedAt, _Context)        -> ok;
handle_terminate(shutdown, _StartedAt, _Context)      -> ok;
handle_terminate({shutdown, _}, _StartedAt, _Context) -> ok;
handle_terminate(Reason, StartedAt, Context) ->
	Duration = duration(StartedAt),
	_ = exometer:update([idp,http,duration], Duration),
	?ERROR_REPORT([{exception_reason, Reason}, {http_duration, Duration} | Context]).

-spec duration(non_neg_integer()) -> non_neg_integer().
duration(StartedAt) ->
	Now = idp:unix_time_us(),
	Now - StartedAt.
