-module(eradius_tx).

-behavior(gen_server).

%gen_server stuff:
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
%External API
-export([findCachedEntry/3, send/4, resend/3]).
%Housekeeping
-export([start_link/0, getName/0]).

send(Addr, Port, Data, TriggeringData) ->
  Key={Addr, TriggeringData},
  Now=erlang:monotonic_time(),
  gen_server:cast(getName(), {send, Addr, Port, Data}),
  ets:insert(radius_server:txTableName(), {Key, {Data, Now}}),
  ets:insert(radius_server:txTableTimeName(), {Now, Key}).

findCachedEntry(Addr, _Port, Data) ->
  Key={Addr, Data},
  case ets:lookup(radius_server:txTableName(), Key) of
    [] -> none;
    [{E, _}] -> {ok, E}
  end.

%Used by clients that have determined that there's an entry in the Tx cache
%that they'd like to resend.
resend(Addr, Port, Data) ->
  gen_server:cast(getName(), {send, Addr, Port, Data}).

start_link() ->
  gen_server:start_link({local, getName()}, ?MODULE, [], []).

init(_) ->
  UdpSock=radius_sock:get_sock(),
  {ok, #{udp_sock => UdpSock}}.

handle_call(_, _, State) -> {noreply, State}.
handle_cast({send, Addr, Port, Data}, S=#{udp_sock := Sock}) ->
  ok=gen_udp:send(Sock, Addr, Port, Data),
  {noreply, S};
handle_cast(_, State) -> {noreply, State}.
handle_info(_, State) -> {noreply, State}.

terminate(_, _) -> ok.
code_change(_, S, _) -> {ok, S}.

getName() ->
  eradius_tx.
