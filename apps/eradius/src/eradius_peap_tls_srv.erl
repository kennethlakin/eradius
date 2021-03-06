-module(eradius_peap_tls_srv).

-behavior(gen_server).
%gen_server stuff:
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
%radius_worker "behavior" stuff:
-export([start_worker/1]).
%External API
-export([start_tls/4, handlePacket/3, peercert/1, run_prf/5, send/2]).
%Used by tls_udp
-export([sendCyphertext/2, tlsSocketReady/2]).

start_worker(Args) ->
  gen_server:start_link(?MODULE, Args, []).

init(FSMPid) when is_pid(FSMPid) ->
  %When the FSM exits, we need to as well.
  process_flag(trap_exit, true),
  link(FSMPid),
  {ok, #{fsm_pid => FSMPid, socket => undefined, rad_state => undefined, helper_pid => undefined}}.

%Start up a new TLS server and hand it its first packet.
start_tls(SrvPid, PeerIp, RadState, FirstPacket) ->
  gen_server:call(SrvPid, {eradius_start_tls, PeerIp, RadState, FirstPacket}, infinity).

run_prf(SrvPid, Secret, Label, Seed, Len) ->
  gen_server:call(SrvPid, {eradius_run_prf, Secret, Label, Seed, Len}, infinity).

peercert(SrvPid) ->
  gen_server:call(SrvPid, eradius_peercert, infinity).

% RADIUS ----> SSL --> RADIUS (makes use of ssl:send)
send(SrvPid, Data) ->
  gen_server:call(SrvPid, {eradius_send_plaintext, Data}, infinity).

% SSL ---> RADIUS
sendCyphertext(SrvPid, Data) ->
  gen_server:cast(SrvPid, {eradius_send_cyphertext, Data}).

% RADIUS ---> SSL
handlePacket(SrvPid, Ip, Data) ->
  gen_server:cast(SrvPid, {eradius_handle_packet, Ip, Data}).

%Called when the TLS connection has been established.
tlsSocketReady(SrvPid, Socket) ->
  gen_server:cast(SrvPid, {eradius_tls_socket, Socket}).

%Run the TLS PRF.
handle_call({eradius_run_prf, Secret, Label, Seed, Len}, _, State=#{socket := Socket})
  when Socket /= undefined ->
  Ret=ssl:prf(Socket, Secret, Label, Seed, Len),
  {reply, Ret, State};
handle_call(eradius_peercert, _, State=#{socket := Socket})
  when Socket /= undefined ->
  Ret=ssl:peercert(Socket),
  {reply, Ret, State};
%Start a new TLS connection.
handle_call({eradius_start_tls, PeerIp, RadState, FirstPacket}, _,
            State=#{socket := undefined, rad_state := undefined}) ->
  {ok, HelperPid}=eradius_peap_tls_start:startTlsConnectionHelper(self(), PeerIp, RadState, FirstPacket),
  NewState=State#{rad_state := RadState, helper_pid := HelperPid},
  {reply, ok, NewState};
%Feed plaintext to SSL to be encrypted
handle_call({eradius_send_plaintext, Data}, _, State=#{socket := Socket}) ->
  Ret=ssl:send(Socket, Data),
  {reply, Ret, State}.

%Notify the EAP FSM that the TLS socket is up.
handle_cast({eradius_tls_socket, Socket}, State=#{socket := undefined, fsm_pid := FSMPid,
                                                            rad_state := RadState}) ->
  eradius_eap:tls_up(FSMPid, {tls_up, RadState}),
  {noreply, State#{socket := Socket, helper_pid := undefined}};
%Feed cyphertext to the SSL machinery
handle_cast({eradius_handle_packet, PeerIp, Data}, State) ->
  gen_server:call(tls_udp:getName(), {eradius_handle_packet, self(), PeerIp, Data}, infinity),
  {noreply, State};
%Used for the SSL machinery to make the EAP machinery send bits on the wire.
handle_cast(Msg={eradius_send_cyphertext, _}, State=#{fsm_pid := Pid}) ->
  eradius_eap:send_cyphertext(Pid, Msg),
  {noreply, State}.

%FIXME: Handle {ssl_closed, SslSocket}
%       Handle {ssl_error, SslSocket, Reason}
handle_info(Msg={ssl, Socket, _}, State=#{socket := Socket, fsm_pid := FSMPid}) ->
  eradius_eap:handle_tls_data(FSMPid, Msg),
  {noreply, State};
handle_info(Msg={tls_udp_server_start_error, _}, State=#{fsm_pid := FSMPid}) ->
  eradius_eap:tls_server_start_error(FSMPid, Msg),
  {noreply, State};
handle_info({'EXIT', Pid, Reason}, State=#{fsm_pid := Pid}) ->
  {stop, Reason, State}.

terminate(_, _) -> ok.
code_change(_, State, _) -> {ok, State}.
