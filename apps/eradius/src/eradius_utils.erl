-module(eradius_utils).

-export([normalizeMacAddr/1]).


%Change separators to "-" (or insert them) and change characters to uppercase.
normalizeMacAddr(<<A:16, B:16, C:16, D:16, E:16, F:16>>) ->
  S= <<"-">>,
  MA= <<A:16,S/binary,B:16,S/binary,C:16,S/binary
        ,D:16,S/binary,E:16,S/binary,F:16>>,
  uppercaseMacAddr(MA);
normalizeMacAddr(MA= <<_:16, "-", _:16, "-", _:16, "-"
                   ,_:16, "-", _:16, "-", _:16>>) ->
  uppercaseMacAddr(MA);
normalizeMacAddr(<<A:16, _:8, B:16, _:8, C:16, _:8
                   ,D:16, _:8, E:16, _:8, F:16>>) ->
  S= <<"-">>,
  MA= <<A:16,S/binary,B:16,S/binary,C:16,S/binary
        ,D:16,S/binary,E:16,S/binary,F:16>>,
  uppercaseMacAddr(MA).

uppercaseMacAddr(MacAddr) ->
  A=string:to_upper(erlang:binary_to_list(MacAddr)),
  erlang:list_to_binary(A).
