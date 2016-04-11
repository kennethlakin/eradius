-module(tls_udp).

-compile([{parse_transform, lager_transform}]).
-compile(export_all).

connTableName() ->
  tls_udp_conn_table.

fakeSockTabName() ->
  tls_udp_fakesock_table.

start_link() ->
  gen_server:start_link({local, getName()}, ?MODULE, [], []).

locateFreePort(Ip, State) ->
  locateFreePort(Ip, State, 0).
locateFreePort(_, _, 65530) ->
  {error, too_many_tries};
locateFreePort(Ip, State=#{ipPortMap := Map}, Iters) ->
  Port=crypto:rand_uniform(1,65535),
  Key={Ip, Port},
  case maps:is_key(Key, Map) of
    false ->  {ok, Port};
    true -> locateFreePort(Ip, State, Iters+1)
  end.

%Called by the TLS start helper code to start the process of starting a new TLS
createNewServer(TlsMessageSink, PeerIp, Packet) ->
  ok=gen_server:call(?MODULE:getName(), {eradius_handle_packet, TlsMessageSink, PeerIp, Packet}, infinity).

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
  %Load our SSL keys and passwords for the same and such.
  {ok, App}=application:get_application(),
  Opts=application:get_env(App, ssl_opts, []),

  %So. What to track?
  % * {Sink PID, PeerIp} -> {SslPid, Port, FakeSocket, SslSock}
  % * FakeSock -> {SinkPID, PeerIp}
  % * {PeerIp, Port} -> ok (this is used to check for uniqueness of
  %                     IP/port combo and nothing more.
  {ok, #{pidIpMap => #{}
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
      lager:info("SSL server not found for ~p ~p", [SinkPid, Addr]),
      {ok, Port}=locateFreePort(Addr, State),
      {ok, Pid}=startSslServerHelper(Addr, Port, SinkPid, SslOpts),
      MonRef=monitor(process, Pid),
      case waitForFakeSock(Addr, Port, MonRef, Pid) of
        {ok, FakeSock} ->
          case waitForSslPid(FakeSock, MonRef, Pid) of
            {ok, SslPid} ->
              case waitForTransToActive(FakeSock, MonRef, Pid) of
                {error, proc_down} ->
                  lager:warning("SSL startup proc crashed, waiting to get set to active."),
                  {reply, {error, proc_down}, State};
                ok ->
                  %NOTE: We do not yet have the TLS socket. That will come
                  %much later in the process, after several packet exchanges.
                  demonitor(MonRef, [flush]),
                  lager:info("Sending packet to SSL PID!"),
                  SslPid ! {tls_udp, FakeSock, Data},

                  lager:info("Setting Pid/Ip map {~p, ~p} => {~p, ~p, ~p, ~p}",
                              [SinkPid, Addr, SslPid, Port, FakeSock, undefined]),
                  NewPIM=PidIpMap#{{SinkPid, Addr} => {SslPid, Port, FakeSock, undefined}},
                  NewIPM=IpPortMap#{{Addr, Port} => ok},
                  NewFSM=FakeSockMap#{FakeSock => {SinkPid, Addr}},
                  {reply, ok, State#{pidIpMap := NewPIM, ipPortMap := NewIPM, fakeSockMap := NewFSM}}
              end;
            {error, proc_down} ->
              lager:warning("SSL startup proc crashed, waiting for SSL Pid."),
              {reply, {error, proc_down}, State}
          end;
        {error, proc_down} ->
          lager:warning("SSL startup proc crashed, waiting for FakeSock."),
          {reply, {error, proc_down}, State}
      end;
    {SslPid, _, FakeSock, _} ->
      lager:info("Found SSL Pid. Sending data to it"),
      lager:info("Packet: ~p", [radius_server:bin_to_hex(Data)]),
      SslPid ! {tls_udp, FakeSock, Data},
      {reply, ok, State}
  end.

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
  FakeSock=createFakeSockAndSignal(Addr, Port),
  %FIXME: tls_udp is the tag applied to the messages that the ssl module will
  %       handle. Not sure if it should be configurable.
  %%This works, but it requires intercommunication between the setopts function
  %%and the SSL server initialization code. That's in there, and it works, but
  %%it's not pretty.
  Opts = [{cb_info, {?MODULE, tls_udp, closed, error}}] ++ AddlOpts,
  {ok, SSock}=ssl:ssl_accept(FakeSock, Opts),
  %Transmit the SSL socket!
  %FIXME: Make this a proper call.
  ?MODULE:getName() ! {sslSock, FakeSock, SSock},
  ssl:controlling_process(SSock, SslSinkPid),
  %Set active to true to ensure that we get TLS packets as messages to our
  %process mailbox, rather than having to call ssl:recv/2.
  ssl:setopts(SSock, [{active, true}, binary]),
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

getopts(Sock, Opts) ->
  lager:info("getopts ~p ~p", [Sock, Opts]),
  %inet:getopts(Sock, Opts).
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
  lager:info("setopts ~p ~p", [Sock, Opts]),
  %inet:setopts(Sock, Opts).
  case ets:lookup(fakeSockTabName(), Sock) of
    [] -> {error, einval};
    [{Sock, Map=#{opts := OptMap=#{active := false}}}] ->
      %If we're transitioning from passive to active mode, send a message.
      %but see the notes below about *why* we are doing this. It's odd.
      case proplists:get_value(active, Opts) of
        Val when Val == true orelse Val == once ->
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
          ?MODULE:getName() ! {passiveToActiveTrans, Sock};
        _ -> ok
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
  lager:info("controlling_process ~p ~p", [Sock, NewPid]),
  %gen_udp:controlling_process(Sock, whereis(getName())),
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
          lager:warn("controlling_process called by ~p but ~p is owner. returning not_owner",
                     [Self, Other]),
          {error, not_owner}
      end
  end.

listen(Sock, Opts) ->
  lager:info("listen~p, ~p", [Sock, Opts]),
  case ets:lookup(fakeSockTabName(), Sock) of
    [] -> {error, einval};
    [{Sock, _}] -> {ok, Sock}
  end.

close(Sock) ->
  lager:info("close ~p", [Sock]),
  %Hmm. Do we need to close the fake port?!?!
  %We do *not* need to close the fake port. erlang:ports/0 doesn't list
  %it as a port! So, this is a port-shaped object, rather than a port.
  %erlang:port_close(Sock),
  %FIXME: Send a "cleanup" message to tls_udp server. It will trigger:
  %       Lookup FakeSock to get {SinkPID, PeerIP}, then delete.
  %       Look that up to get {SSLPid, Port, FakeSock, SSLSock}, then delete
  %       Delete {PeerIp, Port}.
  ets:delete(fakeSockTabName(), Sock),
  ok.

peername(Sock) ->
  lager:info("peername ~p", [Sock]),
  case ets:lookup(fakeSockTabName(), Sock) of
    [] -> {error, einval};
    [{Sock, #{peername := Peername}}] -> {ok, Peername}
  end.

port(Sock) ->
  lager:info("port ~p", [Sock]),
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
