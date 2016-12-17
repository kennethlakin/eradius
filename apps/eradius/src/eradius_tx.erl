-module(eradius_tx).

-behavior(gen_server).

%gen_server stuff:
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
%External API
-export([findCachedEntry/3, send/5, resend/4]).
%Housekeeping
-export([start_link/0, getName/0]).

send(Addr, Port, Data, TriggeringData, Sock) ->
  gen_server:cast(getName(), {send, Addr, Port, Data, TriggeringData, Sock}).

findCachedEntry(Addr, _Port, Data) ->
  Key={Addr, Data},
  case ets:lookup(radius_server:txTableName(), Key) of
    [] -> none;
    [{E, _}] -> {ok, E}
  end.

%Used by clients that have determined that there's an entry in the Tx cache
%that they'd like to resend.
resend(Addr, Port, Data, Sock) ->
  gen_server:cast(getName(), {send, Addr, Port, Data, Sock}).

start_link() ->
  gen_server:start_link({local, getName()}, ?MODULE, [], []).

init(_) ->
  {ok, #{}}.

handle_call(_, _, State) -> {noreply, State}.
%Used by clients that have determined that there's an entry in the Tx cache
%that they'd like to resend.
handle_cast({send, Addr, Port, Data, Sock}, S) ->
  ok=gen_udp:send(Sock, Addr, Port, Data),
  {noreply, S};
handle_cast({send, Addr, Port, Data, TriggeringData, Sock}, S) ->
  Now=erlang:monotonic_time(),
  Key={Addr, TriggeringData},
  ok=gen_udp:send(Sock, Addr, Port, Data),
  ets:insert(radius_server:txTableName(), {Key, {Data, Now}}),
  {noreply, S};
handle_cast(_, State) -> {noreply, State}.
handle_info(_, State) -> {noreply, State}.

terminate(_, _) -> ok.
code_change(_, S, _) -> {ok, S}.

getName() ->
  eradius_tx.
