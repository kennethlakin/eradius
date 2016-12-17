-module(radius_sock).

-behavior(gen_server).

%gen_server stuff:
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
%External API
-export([get_sock/0, get_accounting_sock/0, take_ownership/1, release_ownership/1]).
%Housekeeping
-export([start_link/0, getName/0]).

-compile([{parse_transform, lager_transform}]).
-record(radius_sock, {rad_sock, acct_sock}).

get_sock() ->
  gen_server:call(getName(), get_sock, infinity).

get_accounting_sock() ->
  gen_server:call(getName(), get_accounting_sock, infinity).

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
  %FIXME: Make these ports configurable.
  Port=1812,
  AccountingPort=1813,
  lager:info("RADIUS Listening on ports rad:~w acct:~w", [Port, AccountingPort]),
  {ok, UdpSock} = gen_udp:open(Port, [binary, {active, false}]),
  {ok, AcctSock} = gen_udp:open(AccountingPort, [binary, {active, false}]),
  {ok, #radius_sock{rad_sock=UdpSock, acct_sock=AcctSock}}.

getName() -> 
  eradius_radius_sock.

handle_call(get_sock, _, S=#radius_sock{rad_sock=Sock}) ->
  {reply, Sock, S};
handle_call(get_accounting_sock, _, S=#radius_sock{acct_sock=Sock}) ->
  {reply, Sock, S};
handle_call({take_ownership, Pid, Sock}, _, S=#radius_sock{rad_sock=UdpSock, acct_sock=AccSock}) ->
  case Sock of
    UdpSock -> TheSock=UdpSock;
    AccSock -> TheSock=AccSock
  end,
  lager:debug("RADIUS Setting socket controlling process to ~p", [Pid]),
  Ret=gen_udp:controlling_process(TheSock, Pid),
  {reply, Ret, S};
handle_call(_, _, State) ->
  {reply, error, State}.

terminate(_,_) -> ok.
handle_cast(_, State) -> {noreply, State}.
handle_info(_, State) -> {noreply, State}.
code_change(_, S, _) -> {ok, S}.
