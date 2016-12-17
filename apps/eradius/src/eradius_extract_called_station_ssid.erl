-module(eradius_extract_called_station_ssid).

-behavior(eradius_preprocess).

%eradius_preprocess exports
-export([preprocess/2, start_module/0, reload/0, getName/0]).

%Extracts MAC and SSID from Called-Station-ID attributes
%of the form STATION_MAC:SSID and puts them in
%called_station_mac and called_station_ssid attributes.
preprocess(_, Attrs=#{called_station_id := CSID}) ->
  case binary:match(CSID, <<":">>) of
    nomatch -> {ok, Attrs};
    {Pos, 1} ->
      Len=byte_size(CSID),
      StationMAC=eradius_utils:normalizeMacAddr(binary:part(CSID, 0, Pos)),
      SSID=binary:part(CSID, Len, Pos-Len+1),
      NewAttrs=Attrs#{called_station_mac => StationMAC, called_station_ssid => SSID},
      {ok, NewAttrs}
  end;
preprocess(_, Attrs) -> {ok, Attrs}.

%Nothing to start.
start_module() -> ignore.

%No configuration
reload() -> ok.

getName() -> ?MODULE.
