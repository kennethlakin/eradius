-module(eradius_peap_tls_start).

-compile([{parse_transform, lager_transform}]).

%FIXME: Change this from camelCase to underscore_format.
-export([startTlsConnectionHelper/4]).
%radius_worker "behavior" stuff:
-export([start_worker/1]).
%Internal
-export([createNewServer/4]).

startTlsConnectionHelper(TlsSinkPid, PeerIp, RadState, FirstPacket) ->
  radius_worker:start(?MODULE, [TlsSinkPid, PeerIp, RadState, FirstPacket]).

start_worker(Args) ->
  Pid=spawn_link(?MODULE, createNewServer, Args),
  {ok, Pid}.

%FIXME: Consider adding RadState to the key data.
createNewServer(TlsSinkPid, PeerIp, _RadState, FirstPacket) ->
  ok=tls_udp:createNewServer(TlsSinkPid, PeerIp, FirstPacket).
