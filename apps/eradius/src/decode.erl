-module(decode).

-compile(export_all).
-compile([{parse_transform, lager_transform}]).

%RFC 3579, sec 3.3: More than one of user, chap, arap-password and eap-message
%is an error.
%FIXME: RFC 2865 sec 5.44 says that an Access-Request must have one of user,
%chap-password, OR state. We're not looking at state here at all.
verifyAuthPlausibility(#{user_password := _, chap_password := _, arap_password := _, eap_message := _}) -> error;
verifyAuthPlausibility(#{user_password := _, chap_password := _, arap_password := _}) -> error;
verifyAuthPlausibility(#{user_password := _, chap_password := _}) -> error;
verifyAuthPlausibility(#{user_password := _, arap_password := _, eap_message := _}) -> error;
verifyAuthPlausibility(#{user_password := _, arap_password := _}) -> error;
%FIXME: radtest sends user-password and eap-message and message-authenticator
%       when asked to do eap-md5. I'm pretty sure that radtest is in error, but
%       am not certain.
verifyAuthPlausibility(#{user_password := _, eap_message := _}) -> error;
verifyAuthPlausibility(#{chap_password := _, arap_password := _, eap_message := _}) -> error;
verifyAuthPlausibility(#{chap_password := _, arap_password := _}) -> error;
verifyAuthPlausibility(#{chap_password := _, eap_message := _}) -> error;
verifyAuthPlausibility(#{arap_password := _, eap_message := _}) -> error;
%We MUST have a message-authenticator if we have an eap-message.
verifyAuthPlausibility(#{eap_message := _, message_authenticator := _}) -> ok;
verifyAuthPlausibility(#{eap_message := _}) -> error;
verifyAuthPlausibility(#{}) -> ok.

%If we have an EAP-message, we MUST have a Message-Authenticator:
verifyPacket(NASSecret,
             _, #{message_authenticator := {[MsgAuth], AuthBin}},
             <<Type:1/bytes, Identifier:1/bytes, Len:2/bytes, ReqAuth:16/bytes, AttrBin/binary>>) ->
  BlankedAttrBin=zeroAttr(AttrBin, AuthBin),
  CalculatedAuth=crypto:hmac(md5, NASSecret,
                                 <<Type/binary, Identifier/binary, Len/binary,
                                   ReqAuth/binary, BlankedAttrBin/binary>>),
  lager:debug("DECODE MsgAuth  ~p", [MsgAuth]),
  lager:debug("DECODE CalcAuth ~p", [CalculatedAuth]),
  case CalculatedAuth == MsgAuth of
    true -> ok;
    false -> error
  end;


verifyPacket(NASSecret, Auth, #{user_password := {[MsgVerifier], _}
             ,user_name := {[UserName], _}}, _) ->
  {ok, Pass}=eradius_auth:lookup_user(UserName),
  PaddedPass=case byte_size(Pass) of
               Sz when Sz > 16 -> binary:part(Pass, 0, 16);
               Sz when Sz == 16 -> Pass;
               Sz ->
                 Padding=binary:copy(<<0>>, 16-Sz),
                 <<Pass/binary, Padding/binary>>
             end,
  SharedSecretDigest=crypto:hash(md5, <<NASSecret/binary, Auth/binary>>),
  CalculatedVerifier=crypto:exor(SharedSecretDigest, PaddedPass),
  lager:debug("DECODE MsgVerifier  ~p", [MsgVerifier]),
  lager:debug("DECODE CalcVerifier ~p", [CalculatedVerifier]),
  case CalculatedVerifier == MsgVerifier of
    true -> ok;
    false -> error
  end.

appendAttribute(AttrMap, HumType, Data, RawAttr) ->
  case maps:get(HumType, AttrMap, undefined) of
    undefined ->
      AttrMap#{HumType => {[Data], <<RawAttr/binary>>}};
    {List, RawAttrs} ->
      AttrMap#{HumType => {List ++ [Data], <<RawAttrs/binary, RawAttr/binary>>}}
  end.

getAttribute(AttrMap, Name) ->
  lists:foldl(fun (D, B) -> <<B/binary, D/binary>> end,
              <<>>, element(1, maps:get(Name, AttrMap))).

determineLength(Code, Id, Auth, Attrs) ->
  Len=byte_size(<<Code/binary, Id/binary, 0:16, Auth/binary>>)
    + iolist_size(Attrs),
  %FIXME: Do something other than crash if our packet is too large.
  %       Max packet length is 4096, per RFC 2865, section 3.
  true=Len =< 4096,
  <<Len:16>>.

%FIXME: This should get passed in a maximum packet size and create packets no
%       larger than that.
encodeAccess(Addr, T, I, A) ->
  encodeAccess(Addr, T, I, A, #{}).
encodeAccess(Addr, Type, Identifier, Auth, Attrs) ->
  {ok, NASPassword}=eradius_auth:lookup_nas(Addr),
  case Type of
    access_request -> Code= <<1>>;
    access_accept -> Code= <<2>>;
    access_reject -> Code= <<3>>;
    access_challenge -> Code= <<11>>
  end,

  AB=encodeAttributes(Attrs),
  Len=determineLength(Code, Identifier, Auth, AB),
  case Attrs of
    #{message_authenticator := MA} ->
      MsgAuth=crypto:hmac(md5, NASPassword,
                          <<Code/binary, Identifier/binary, Len/binary,
                            Auth/binary, AB/binary>>),
      MABin=encodeAttributes(#{message_authenticator => MA}),
      AttrBin=replaceAttr(AB, MABin, MsgAuth);
    _ ->
      AttrBin=AB
  end,
  RespAuth=crypto:hash(md5, <<Code/binary, Identifier/binary, Len/binary, Auth/binary, AttrBin/binary, NASPassword/binary>>),
  <<Code/binary, Identifier/binary, Len/binary, RespAuth/binary, AttrBin/binary>>.

%FIXME: This is awful and in the wrong module, but it should probably work.
encodeAttributes(Attrs) ->
  lists:foldl(fun({Key, Val}, Acc) ->
                  Bin=
                    lists:foldl(fun(Data, A) ->
                                    {ok, B}=rad_attr:encodeAttr(Key, Data),
                                    <<A/binary, B/binary>>
                                end,
                                <<>>,
                                Val),
                  <<Acc/binary, Bin/binary>>
              end,
              <<>>,
              maps:to_list(Attrs)).


%RFC 2895 section 5 dictates that if any attribute has an invalid
%length, the entire packet is to be considered invalid.
decodeAttributes(Pkt) ->
  decodeAttributes(Pkt, #{}).
decodeAttributes(<<>>,  Attrs) ->
  {ok, Attrs};
decodeAttributes(Pkt, _) when byte_size(Pkt) < 3 ->
  {error, attr_length_too_short};
decodeAttributes(Pkt= <<T:1/bytes, L:1/bytes, Rest/binary>>,  Attrs) ->
  Size=byte_size(Pkt),
  Length=binary:decode_unsigned(L),
  case Size >= Length of
    false -> {error, attr_length_too_short};
    true ->
      Type=binary:decode_unsigned(T),
      RawData=binary:part(Rest, 0, Length-2),
      case rad_attr:decodeAttr(Type, Length, RawData) of
        {error, attr_length_incorrect, _HumType, _Data} ->
          %FIXME: Maybe add some logging here.
          {error, attr_length_incorrect};
        {warn, unrecognized_attr} ->
          lager:notice("DECODE Unknown attr type ~p, data ~p", [Type, RawData]),
          decodeAttributes(binary:part(Pkt, Length, Size-Length), Attrs);
        {ok, HumType, Data} ->
          RawAttr= <<T/binary, L/binary, RawData/binary>>,
          NewAttrs=appendAttribute(Attrs, HumType, Data, RawAttr),
          decodeAttributes(binary:part(Pkt, Length, Size-Length), NewAttrs)
      end
  end.

%This will match packets of at *least* 20 bytes.
decodeRadius(P = <<_:1/bytes, _:1/bytes, L:2/bytes, _:16/bytes, _/binary>>) ->
  Length=binary:decode_unsigned(L),
  % Max packet length is 4096, according to RFC 2865, section 3.
  % Min packet length is 20. Note that "packet length" is the same as "byte_size/1
  % of entire packet"... but without any padding that might be present in the
  % packet. The RFC offers no guidance on what to do when the packet is larger
  % than 4096 bytes... so FIXME: print warning and discard packet if > 4096.
  case byte_size(P) >= Length of
    false ->
      {discard, packet_too_short};
    true ->
      %Trim any padding:
      <<Pkt:Length/bytes, _/binary>> =P,
      case doDecodeRadius(Pkt) of
        {ok, {Code, RequestType, Identifier, Authenticator, Rest}} ->
          {ok, {Code, RequestType, Identifier, Length, Authenticator, Rest}}
      end
  end;
%If we're here, our packet is obviously too short to contain the data required,
%so we MUST sliently discard it.
decodeRadius(Pkt) when is_binary(Pkt) ->
  {discard, packet_too_short}.

doDecodeRadius(<<C:1/bytes, Identifier:1/bytes, _:2/bytes, Authenticator:16/bytes, Rest/binary>>) ->
  Code=binary:decode_unsigned(C),
  RequestType=
  case Code of
    1 -> access_request;
    2 -> access_accept;
    3 -> access_reject;
    4 -> accounting_request;
    5 -> accounting_response;
    11 -> access_challenge;
    _ -> unrecognized
  end,
  {ok, {Code, RequestType, Identifier, Authenticator, Rest}}.

zeroAttr(Attrs, <<>>) -> Attrs;
%An attr with size 1 is invalid and should have been caught by other code.
zeroAttr(Attrs, Attr) when byte_size(Attr) == 2 -> Attrs;
zeroAttr(Attrs, Attr= <<Front:2/binary, _/binary>>) ->
  Zeroes=binary:copy(<<0>>, byte_size(Attr)-2),
  binary:replace(Attrs, Attr, <<Front/binary, Zeroes/binary>>).

replaceAttr(Attrs, <<>>, <<>>) -> Attrs;
%An attr with size 1 is invalid and should have been caught by other code.
%We only support replacing data with data of the same size.
replaceAttr(Attrs, Attr= <<Front:2/binary, _/binary>>, NewVal) when byte_size(Attr)-2 == byte_size(NewVal) ->
  binary:replace(Attrs, Attr, <<Front/binary, NewVal/binary>>).

%Change separators to "-" (or insert them) and change characters to lowercase.
normalizeMacAddr(<<A:16, B:16, C:16, D:16, E:16, F:16>>) ->
  S= <<"-">>,
  MA= <<A:16,S/binary,B:16,S/binary,C:16,S/binary
        ,D:16,S/binary,E:16,S/binary,F:16>>,
  lowercaseMacAddr(MA);
normalizeMacAddr(MA= <<_:16, "-", _:16, "-", _:16, "-"
                   ,_:16, "-", _:16, "-", _:16>>) ->
  lowercaseMacAddr(MA);
normalizeMacAddr(<<A:16, _:8, B:16, _:8, C:16, _:8
                   ,D:16, _:8, E:16, _:8, F:16>>) ->
  S= <<"-">>,
  MA= <<A:16,S/binary,B:16,S/binary,C:16,S/binary
        ,D:16,S/binary,E:16,S/binary,F:16>>,
  lowercaseMacAddr(MA).

lowercaseMacAddr(MacAddr) ->
  A=string:to_lower(erlang:binary_to_list(MacAddr)),
  erlang:list_to_binary(A).
