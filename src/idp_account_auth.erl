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

-module(idp_account_auth).

%% CRUD API
-export([
	list/2,
	read/3,
	delete/4
]).

%% API
-export([
	identity/1,
	parse_identity/1
]).

%% Types
-type resource() :: [riakacl_group:rawdt()].

-record(rbox, {
	r :: resource(),
	p :: riakauth_account:account()
}).
-type rbox() :: #rbox{}.

%% =============================================================================
%% CRUD API
%% =============================================================================

-spec list([binary()], riakauth_account:account()) -> [map()].
list(AuthKeys, A) ->
	format_resources(AuthKeys, A).

-spec read(binary(), binary(), map()) -> {ok, rbox()} | error.
read(Akey, Ibin, Rdesc) ->
	#{account := #{pool := KVpool, bucket := Ab}} = Rdesc,
	KVpid = riakc_pool:lock(KVpool),
	MaybeA = riakauth_account:find(KVpid, Ab, Akey),
	riakc_pool:unlock(KVpool, KVpid),
	case MaybeA of
		{ok, A} -> find_resource(parse_identity(Ibin), A);
		_       -> error
	end.

-spec delete(binary(), binary(), rbox(), map()) -> map().
delete(Akey, Ibin, #rbox{p = A0} =Rbox, Rdesc) ->
	#{account := #{pool := KVpool, bucket := Ab}} = Rdesc,

	%% We do not allow deleting identities of disabled accounts.
	true = idp_account:is_enabled(A0),

	A1 = riakauth_account:remove_identity_dt(parse_identity(Ibin), A0),
	KVpid = riakc_pool:lock(KVpool),
	_ = riakauth_account:put(KVpid, Ab, Akey, A1),
	riakc_pool:unlock(KVpool, KVpid),
	to_map(Ibin, Rbox).

%% =============================================================================
%% API
%% =============================================================================

-spec to_map(binary(), rbox()) -> map().
to_map(Ibin, #rbox{r = Raw}) ->
	format_resource_dt(Ibin, Raw).

-spec identity(riakauth_account:identity()) -> binary().
identity([])    -> <<>>;
identity([H|T]) -> identity(T, H).

-spec parse_identity(binary()) -> [binary()].
parse_identity(Bin) ->
	parse_identity(Bin, <<>>, []).

%% =============================================================================
%% Internal functions
%% =============================================================================

-spec identity(riakauth_account:identity(), binary()) -> binary().
identity([Val|T], Acc) -> identity(T, <<Acc/binary, $., Val/binary>>);
identity([], Acc)      -> Acc.

-spec parse_identity(binary(), binary(), [binary()]) -> [binary()].
parse_identity(<<$., Rest/bits>>, AccV, AccL) -> parse_identity(Rest, <<>>, [AccV|AccL]);
parse_identity(<<C, Rest/bits>>, AccV, AccL)  -> parse_identity(Rest, <<AccV/binary, C>>, AccL);
parse_identity(<<>>, AccV, AccL)              -> lists:reverse([AccV|AccL]).

-spec format_resources([binary()], riakauth_account:account()) -> [map()].
format_resources(AuthKeys, A) ->
	riakauth_account:fold_identities_dt(
		fun(Identity, Raw, Acc) ->
			[format_resource_dt(identity(Identity), Raw) | Acc]
		end, AuthKeys, [], A).

-spec format_resource_dt(binary(), resource()) -> map().
format_resource_dt(Ibin, _Raw) ->
	#{id => Ibin}.

-spec find_resource(riakauth_account:identity(), riakauth_account:account()) -> {ok, rbox()} | error.
find_resource(Identity, A) ->
	case riakauth_account:find_identity_rawdt(Identity, A) of
		{ok, Raw} -> {ok, #rbox{r = Raw, p = A}};
		error     -> error
	end.
