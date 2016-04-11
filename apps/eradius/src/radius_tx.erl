-module(radius_tx).

-compile(export_all).

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
  process_flag(trap_exit, true),
  UdpSock=radius_sock:get_sock(),
  {ok, #{udp_sock => UdpSock}}.

handle_call(C, _, State) ->
  lager:warning("~p: Unexpected call ~p", [?MODULE, C]),
  {noreply, State}.
handle_cast({send, Addr, Port, Data}, S=#{udp_sock := Sock}) ->
  ok=gen_udp:send(Sock, Addr, Port, Data),
  {noreply, S};
handle_cast(C, State) ->
  lager:warning("~p: Unexpected cast ~p", [?MODULE, C]),
  {noreply, State}.
handle_info(C, State) ->
  lager:warning("~p: Unexpected info ~p", [?MODULE, C]),
  {noreply, State}.

terminate(_, _) -> ok.

getName() ->
  eradius_radius_tx.
