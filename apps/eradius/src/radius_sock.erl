-module(radius_sock).

-compile(export_all).

-compile([{parse_transform, lager_transform}]).

get_sock() ->
  gen_server:call(getName(), get_sock, infinity).

take_ownership(Sock) ->
  gen_server:call(getName(), {take_ownership, self(), Sock}, infinity).

release_ownership(Sock) ->
  case whereis(getName()) of
    undefined -> ok;
    Name -> gen_udp:controlling_process(Sock, Name)
  end.

start_link() ->
  gen_server:start_link({local, getName()}, ?MODULE, [], []).

init(_) ->
  process_flag(trap_exit, true),
  %FIXME: Make this port configurable.
  {ok, UdpSock} = gen_udp:open(1812, [binary, {active, false}]),
  {ok, UdpSock}.

getName() -> 
  eradius_radius_sock.

handle_call(get_sock, _, UdpSock) -> {reply, UdpSock, UdpSock};
handle_call({take_ownership, Pid, UdpSock}, _, UdpSock) -> 
  Ret=gen_udp:controlling_process(UdpSock, Pid),
  {reply, Ret, UdpSock};
handle_call(C, _, State) ->
  lager:warning("~p: Unexpected call ~p", [?MODULE, C]),
  {noreply, State}.

handle_cast(C, _, State) ->
  lager:warning("~p: Unexpected cast ~p", [?MODULE, C]),
  {noreply, State}.

handle_info(C, State) ->
  lager:warning("~p: Unexpected info ~p", [?MODULE, C]),
  {noreply, State}.

terminate(_,UdpSock) -> 
  gen_udp:close(UdpSock).

code_change(_, S, _) -> {ok, S}.
