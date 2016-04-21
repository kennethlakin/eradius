-module(eradius_peap_tls_start).

-compile(export_all).
-compile([{parse_transform, lager_transform}]).

startTlsConnectionHelper(TlsSinkPid, PeerIp, RadState, FirstPacket) ->
  radius_worker:start(?MODULE, [TlsSinkPid, PeerIp, RadState, FirstPacket]).

start_worker(Args) ->
  Pid=spawn_link(?MODULE, createNewServer, Args),
  {ok, Pid}.

%FIXME: Consider adding RadState to the key data.
createNewServer(TlsSinkPid, PeerIp, _RadState, FirstPacket) ->
  ok=tls_udp:createNewServer(TlsSinkPid, PeerIp, FirstPacket).
