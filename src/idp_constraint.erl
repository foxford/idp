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

-module(idp_constraint).

%% API
-export([
	binary/2,
	int/2
]).

%% Types
-type constraint() :: fun((forward | reverse | format_error, iodata()) -> {ok, any()} | {error, any()} | iodata()).

%% =============================================================================
%% API
%% =============================================================================

-spec binary(non_neg_integer(), non_neg_integer()) -> constraint().
binary(Min, Max) ->
	fun
		(forward, Val) ->
			try
				Size = iolist_size(Val),
				true = Size =< Max,
				true = Size >= Min,
				{ok, Val}
			catch _:_ -> {error, {invalid_binary, Val}} end;
		(reverse, Val) ->
			{ok, Val};
		(format_error, {invalid_binary, Val}) ->
			<<"The value ", Val/binary,
				"should be a binary whose length is (", (integer_to_binary(Min))/binary,
				$,, (integer_to_binary(Max))/binary, ").">>
	end.

-spec int(non_neg_integer(), non_neg_integer()) -> constraint().
int(Min, Max) ->
	fun
		(forward, Val) ->
			try
				Num = binary_to_integer(Val),
				true = Num =< Max,
				true = Num >= Min,
				{ok, Num}
			catch _:_ -> {error, {invalid_integer, Val}} end;
		(reverse, Val) ->
			try {ok, integer_to_binary(Val)}
			catch _:_ -> {error, {invalid_integer, Val}} end;
		(format_error, {invalid_integer, Val}) ->
			<<"The value ", (integer_to_binary(Val))/binary,
				"should be an integer whose range is (", (integer_to_binary(Min))/binary,
				$,, (integer_to_binary(Max))/binary, ").">>
	end.
