-module(eradius_peap_tls_start).

-compile(export_all).
-compile([{parse_transform, lager_transform}]).

startTlsConnectionHelper(TlsSinkPid, PeerIp, RadState, FirstPacket) ->
  radius_worker:start(?MODULE, [TlsSinkPid, PeerIp, RadState, FirstPacket]).

start_worker(Args) ->
  Pid=spawn_link(?MODULE, createNewServer, Args),
  {ok, Pid}.

createNewServer(TlsSinkPid, PeerIp, _RadState, FirstPacket) ->
  lager:notice("Ignoring RadState in createNewServer."),
  ok=tls_udp:createNewServer(TlsSinkPid, PeerIp, FirstPacket).
