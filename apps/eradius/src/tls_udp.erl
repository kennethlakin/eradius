-module(tls_udp).

-compile([{parse_transform, lager_transform}]).
-behavior(gen_server).

%gen_server stuff:
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
%Public API
-export([start_link/0]).
%radius_worker "behavior" stuff:
-export([start_worker/1]).
%Housekeeping API
-export([getName/0]).
%Internal API
-export([createNewServer/3, startSslServer/4]).
%inets mock API
-export([getopts/2, setopts/2, controlling_process/2, listen/2, close/1
         ,peername/1, port/1, send/2]).

%%FIXME: connTableName/0 and getPid/1 are unused. Why?

connTableName() ->
  tls_udp_conn_table.

fakeSockTabName() ->
  tls_udp_fakesock_table.

start_link() ->
  gen_server:start_link({local, getName()}, ?MODULE, [], []).

%Called by the TLS start helper code to start the process of starting a new TLS
%connection.
createNewServer(TlsMessageSink, PeerIp, Packet) ->
  case gen_server:call(?MODULE:getName(), {eradius_handle_packet, TlsMessageSink, PeerIp, Packet}, infinity) of
    ok -> ok;
    Err ->
      TlsMessageSink ! {tls_udp_server_start_error, Err},
      Err
  end.

createFakeSockAndSignal(PeerIp, PeerPort) ->
  FakeSock=erlang:open_port({spawn_driver, "udp_inet"}, [binary]),
  %These are the default opts for a newly created UDP socket.
  Opts=#{mode => list, packet => 0, active => true, header => 0, packet_size => 0},
  Peername={PeerIp, PeerPort},
  ets:insert(fakeSockTabName(), {FakeSock, #{opts => Opts, peername => Peername,
                                             pid => self()}}),
  %FIXME: Sending messages directly to the gen_server is really odd.
  %       We're doing this because the handle_info({udp...) is in
  %       waitForFakeSock/3
  ?MODULE:getName() ! {fakeSock, PeerIp, PeerPort, FakeSock},
  FakeSock.


init(_) ->
  process_flag(trap_exit, true),
  %%Contains the state of each fake socket. Used to fake out getopts and
  %%setopts.
  ets:new(fakeSockTabName(), [named_table, public]),
  %Load our SSL certs and passwords for the same and such.
  {ok, App}=application:get_application(),
  Opts=application:get_env(App, ssl_opts, []),
  {ok, #{pidIpMap => #{}
         ,freePortMap => #{}
         ,ipPortMap => #{}
         ,fakeSockMap => #{}
         ,sslOpts => Opts
         }}.

handle_call({send, Sock, Data}, _, State) ->
  FSMap=maps:get(fakeSockMap, State),
  {Pid, _}=maps:get(Sock, FSMap),
  eradius_peap_tls_srv:sendCyphertext(Pid, Data),
  {reply, ok, State};

handle_call({eradius_handle_packet, SinkPid, Addr, Data}, _From,
            State=#{pidIpMap := PidIpMap, ipPortMap := IpPortMap, fakeSockMap := FakeSockMap,
                   sslOpts := SslOpts}) ->
  %Check to see if this pid has a fakesock alloced to it.
  case maps:get({SinkPid, Addr}, PidIpMap, undefined) of
    undefined ->
      lager:debug("TLS_UDP Starting TLS server for ~p ~p", [SinkPid, Addr]),
      case getFreePort(Addr, State) of
        {error, Reason} ->
          {reply, {error, Reason}, State};
        {ok, Port, NewState} ->
          {ok, Pid}=startSslServerHelper(Addr, Port, SinkPid, SslOpts),
          MonRef=monitor(process, Pid),
          case waitForFakeSock(Addr, Port, MonRef, Pid) of
            {ok, FakeSock} ->
              case waitForSslPid(FakeSock, MonRef, Pid) of
                {ok, SslPid} ->
                  case waitForTransToActive(FakeSock, MonRef, Pid) of
                    {error, proc_down} ->
                      lager:error("TLS_UDP TLS startup process crashed, waiting to get set to active."),
                      {reply, {error, proc_down}, NewState};
                    ok ->
                      demonitor(MonRef, [flush]),
                      SslPid ! {tls_udp, FakeSock, Data},

                      NewPIM=PidIpMap#{{SinkPid, Addr} => {SslPid, Port, FakeSock, undefined}},
                      NewIPM=IpPortMap#{{Addr, Port} => ok},
                      NewFSM=FakeSockMap#{FakeSock => {SinkPid, Addr}},
                      {reply, ok, NewState#{pidIpMap := NewPIM, ipPortMap := NewIPM, fakeSockMap := NewFSM}}
                  end;
                {error, proc_down} ->
                  lager:error("TLS_UDP SSL startup process crashed, waiting for TLS Pid."),
                  {reply, {error, proc_down}, NewState}
              end;
            {error, proc_down} ->
              lager:error("TLS_UDP TLS startup proccess crashed, waiting for FakeSock."),
              {reply, {error, proc_down}, NewState}
          end
      end;
    {SslPid, _, FakeSock, _} ->
      lager:debug("TLS_UDP Found TLS server ~p. Using it", [SslPid]),
      SslPid ! {tls_udp, FakeSock, Data},
      {reply, ok, State}
  end.

handle_cast({eradius_ssl_close, FakeSock}, State=#{fakeSockMap := FakeSockMap, ipPortMap := IpPortMap
                                                   ,pidIpMap := PidIpMap}) ->
  SA={_, Ip}=maps:get(FakeSock, FakeSockMap),
  {_, Port, _, _}=maps:get(SA, PidIpMap),
  NewFSM=maps:remove(FakeSock, FakeSockMap),
  NewPIM=maps:remove(SA, PidIpMap),
  NewIPM=maps:remove({Ip, Port}, IpPortMap),
  {ok, NewState}=freePort(Ip, Port, State#{fakeSockMap := NewFSM, ipPortMap := NewIPM
                                           ,pidIpMap := NewPIM}),
  ets:delete(fakeSockTabName(), FakeSock),
  {noreply, NewState}.

handle_info({sslSock, FakeSock, SSLSock}, State=#{pidIpMap := PidIpMap, fakeSockMap := FakeSockMap}) ->
  PIKey={Pid, _}=maps:get(FakeSock, FakeSockMap),
  {SslPid, Port, FakeSock, undefined}=maps:get(PIKey, PidIpMap),
  NewPIM=PidIpMap#{PIKey := {SslPid, Port, FakeSock, SSLSock}},
  eradius_peap_tls_srv:tlsSocketReady(Pid, SSLSock),
  {noreply, State#{pidIpMap => NewPIM}}.

%FIXME: *Really* clean up.
terminate(_, _) ->  ok.

getName() ->
  tls_udp_conn_srv.

startSslServerHelper(Addr, Port, SinkPid, Opts) ->
  radius_worker:start(?MODULE, [Addr, Port, SinkPid, Opts]).

%Used by radius_worker:start
start_worker([Addr, Port, SinkPid, Opts]) ->
  Pid=spawn_link(?MODULE, startSslServer, [Addr, Port, SinkPid, Opts]),
  {ok, Pid}.

startSslServer(Addr, Port, SslSinkPid, AddlOpts) ->
  %Die if our SSL sink dies before ssl:ssl_accept returns.
  link(SslSinkPid),
  FakeSock=createFakeSockAndSignal(Addr, Port),
  %NOTE:  tls_udp is the tag applied to the messages that the ssl module will
  %       handle. Not sure if it should be configurable.
  %%This works, but it requires intercommunication between the setopts function
  %%and the SSL server initialization code. That's in there, and it works, but
  %%it's not pretty.
  Opts=[{cb_info, {?MODULE, tls_udp, closed, error}}]
        ++ AddlOpts
        %NOTE: This only works reliably with 19.1.1 and later: 19.0 introduced
        %      a regression in the handling of TLS records that combine
        %      multiple messages in a single record. Windows supplicants do
        %      exactly this, so handshaking failed with them.
        ++[{verify, verify_peer}],
  %NOTE: The default peer certificate validation function is the
  %following:
  %{fun(_,{bad_cert, _} = Reason, _) ->
  %       {fail, Reason};
  %     (_,{extension, _}, UserState) ->
  %       {unknown, UserState};
  %     (_, valid, UserState) ->
  %       {valid, UserState};
  %     (_, valid_peer, UserState) ->
  %       {valid, UserState}
  % end, []}
  %
  % Notice that this returns a validation error for certificates that are
  % expired. We can probably modify the function by adding a clause like so:
  %     (_,{bad_cert, cert_expired}, UserState) ->
  %       {valid, UserState};
  % if we want to also accept certs that have expired.
  %
  %FIXME: If the client presents us with a bad cert
  %       (e.g. one issued by another CA) this will return
  %       {error, {tls_alert, "bad certificate"}}
  {ok, SSock}=ssl:ssl_accept(FakeSock, Opts),
  unlink(SslSinkPid),
  %Setting binary mode immediately to avoid a race that
  %sometimes gave us data as lists.
  ssl:setopts(SSock, [binary]),
  ssl:controlling_process(SSock, SslSinkPid),
  %FIXME: Make this a proper call.
  ?MODULE:getName() ! {sslSock, FakeSock, SSock},
  ssl:setopts(SSock, [{active, true}]),
  ok.

waitForFakeSock(Addr, Port, MonRef, Pid) ->
  receive
    {fakeSock, Addr, Port, FakeSock} ->
      {ok, FakeSock};
    {'DOWN', MonRef, process, Pid, _} ->
      demonitor(MonRef, [flush]),
      {error, proc_down}
  end.

waitForSslPid(FakeSock, MonRef, Pid) ->
  receive
    {sslPid, FakeSock, SslPid} ->
      {ok, SslPid};
    {'DOWN', MonRef, process, Pid, _} ->
      demonitor(MonRef, [flush]),
      {error, proc_down}
  end.

waitForTransToActive(FakeSock, MonRef, Pid) ->
  receive
    {passiveToActiveTrans, FakeSock} ->
      ok;
    {'DOWN', MonRef, process, Pid, _} ->
      demonitor(MonRef, [flush]),
      {error, proc_down}
  end.

getPid(Sock) ->
  case ets:lookup(fakeSockTabName(), Sock) of
    [] -> undefined;
    [{Sock, #{pid := Pid}}] -> Pid
  end.

%"Fake port" management functions
freePort(Ip, Port, State=#{freePortMap := FreePortMap}) ->
  #{portsInUse := PIU, portsFree := PF}=PortStruct=maps:get(Ip, FreePortMap),
  NewPIU=lists:delete(Port, PIU),
  NewPF=queue:in(Port, PF),
  {ok, State#{freePortMap :=
              FreePortMap#{Ip := PortStruct#{portsInUse := NewPIU, portsFree := NewPF}}}}.

getFreePort(Ip, State=#{freePortMap := FreePortMap}) ->
  case maps:get(Ip, FreePortMap, undefined) of
    undefined ->
      Port=1,
      Chunk=100,
      PortStruct=#{portsInUse => [Port]
                   ,portsFree => queue:from_list(lists:seq(Port+1,Chunk))
                   ,next => Chunk+1, chunk => Chunk},
      {ok, Port, State#{freePortMap := FreePortMap#{Ip => PortStruct}}};
    #{portsInUse := PortsInUse, portsFree := PortsFree} = PortStruct ->
      case queue:is_empty(PortsFree) of
        false ->
          Port=queue:get(PortsFree),
          NewFree=queue:drop(PortsFree),
          NewInUse=[Port] ++ PortsInUse,
          NewPortStruct=PortStruct#{portsInUse := NewInUse
                                    ,portsFree := NewFree},
          {ok, Port, State#{freePortMap := FreePortMap#{Ip := NewPortStruct}}};
        true ->
          case allocPorts(PortStruct) of
            {ok, Port, NewPortStruct} ->
              {ok, Port, State#{freePortMap := FreePortMap#{Ip := NewPortStruct}}};
            {error, Reason} ->
              {error, Reason}
          end
      end
  end.

allocPorts(#{next := Next}) when Next >= 65535 ->
  {error, no_free_port};
allocPorts(PortStruct=#{portsInUse := InUse, next := Next, chunk := Chunk}) ->
  Port=Next,
  NewInUse=[Port] ++ InUse,
  NewFree=queue:from_list(
            lists:seq(min(Next+1, 65535)
                      ,min(Next+Chunk, 65535))),
  NewNext=min(Next+Chunk, 65535),
  NewChunk=min(Chunk*2, 1000),
  {ok, Port, PortStruct#{portsInUse := NewInUse, portsFree := NewFree, next := NewNext
                         ,chunk := NewChunk}}.
%End "Fake port" management functions

%inet:* socket functions required for fakesock
getopts(Sock, Opts) ->
  case ets:lookup(fakeSockTabName(), Sock) of
    [] -> {error, einval};
    [{Sock, #{opts := OptMap}}] ->
      %Pluck out the values from the options map for the socket, -if they exist-
      %and then put them in a {option, Value} tuple, and put it on the list to be
      %returned.
      OptList=
          lists:foldl(fun(Opt, Acc) ->
                          case maps:get(Opt, OptMap, garbageNotFound) of
                            garbageNotFound -> Acc;
                            Val -> [{Opt, Val}] ++ Acc
                          end
                      end, [], Opts),
          {ok, OptList}
  end.

setopts(Sock, Opts) ->
  case ets:lookup(fakeSockTabName(), Sock) of
    [] -> {error, einval};
    [{Sock, Map=#{opts := OptMap=#{active := false}}}] ->
      %If we're transitioning from passive to active mode, send a message.
      %but see the notes below about *why* we are doing this. It's odd.
      case proplists:get_value(active, Opts) of
        false -> ok;
        _ ->
          %FIXME: Sending messages directly to the gen_server is really odd.
          %       We're doing this because the handle_info({udp...) is probably
          %       creating a server right now, and the ssl code switches the
          %       socket mode to passive for a bit, and back to active. If we
          %       send a data message to the SSL server *before* it has
          %       switched back to active, then the message will be lost and
          %       the SSL handshaking won't happen.
          %       I... wonder if the ssl code is changing ownership of the
          %       FakeSock at some point, but isn't smart enough to forward
          %       messages RX'd during this time to the new PID.
          %       It might just be more robust to stand up a pair of UDP
          %       sockets and write the initial UDP packet into the socket.
          ?MODULE:getName() ! {passiveToActiveTrans, Sock}
      end,
      NewOptMap=createNewOptMap(OptMap, Opts),
      ets:insert(fakeSockTabName(), {Sock, Map#{opts := NewOptMap}}),
      ok;
    [{Sock, Map=#{opts := OptMap}}] ->
      NewOptMap=createNewOptMap(OptMap, Opts),
      ets:insert(fakeSockTabName(), {Sock, Map#{opts := NewOptMap}}),
      ok
  end.

createNewOptMap(OptMap, Opts) ->
  lists:foldl(fun
                ({K, V}, M) -> M#{K => V};
                %This is the binary-or-list mode, so treat it specially.
                (V, M) when V == binary
                            orelse V == list ->
                  M#{mode => V}
              end, OptMap, Opts).

controlling_process(Sock, NewPid) ->
  case ets:lookup(fakeSockTabName(), Sock) of
    [] -> {error, einval};
    [{Sock, Map}] ->
      Self=self(),
      case maps:get(pid, Map) of
        Self ->
          ets:insert(fakeSockTabName(), {Sock, Map#{pid := NewPid}}),
          %FIXME: Sending messages directly to the gen_server is really odd.
          %       We're doing this because the handle_info({udp...) is in
          %       waitForSslPid/3
          ?MODULE:getName() ! {sslPid, Sock, NewPid},
          ok;
        Other ->
          lager:warning("TLS_UDP controlling_process called by ~p but ~p is owner. returning not_owner",
                        [Self, Other]),
          {error, not_owner}
      end
  end.

listen(Sock, _) ->
  case ets:lookup(fakeSockTabName(), Sock) of
    [] -> {error, einval};
    [{Sock, _}] -> {ok, Sock}
  end.

close(Sock) ->
  gen_server:cast(getName(), {eradius_ssl_close, Sock}),
  ok.

peername(Sock) ->
  case ets:lookup(fakeSockTabName(), Sock) of
    [] -> {error, einval};
    [{Sock, #{peername := Peername}}] -> {ok, Peername}
  end.

port(Sock) ->
  case ets:lookup(fakeSockTabName(), Sock) of
    [] -> {error, einval};
    [{Sock, #{peername := {_, Port}}}] -> {ok, Port}
  end.

send(Sock, Packet) ->
  case ets:lookup(fakeSockTabName(), Sock) of
    [] -> {error, einval};
    [{Sock, _}] ->
      gen_server:call(getName(), {send, Sock, Packet}, infinity)
  end.
%End inet:* socket functions required for fakesock

code_change(_, State, _) -> {ok, State}.
