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

-define(INFO_REPORT(L),
	error_logger:info_report(
		[	{module, ?MODULE},
			{function, ?FUNCTION_NAME},
			{function_arity, ?FUNCTION_ARITY}
			| L ])).

-define(WARNING_REPORT(L),
	error_logger:warning_report(
		[	{module, ?MODULE},
			{function, ?FUNCTION_NAME},
			{function_arity, ?FUNCTION_ARITY}
			| L ])).

-define(ERROR_REPORT(L),
	error_logger:error_report(
		[	{module, ?MODULE},
			{function, ?FUNCTION_NAME},
			{function_arity, ?FUNCTION_ARITY}
			| L ])).

-define(ERROR_REPORT(L, Class, Reason),
	error_logger:error_report(
		[	{module, ?MODULE},
			{function, ?FUNCTION_NAME},
			{function_arity, ?FUNCTION_ARITY},
			{stacktrace, erlang:get_stacktrace()},
			{exception_class, Class},
			{exception_reason, Reason}
			| L ])).
