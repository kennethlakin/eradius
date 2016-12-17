-module(eradius_decode).

-compile([{parse_transform, lager_transform}]).
-export([encodeRadius/4, encodeRadius/5, decodeRadius/1, decodeAttributes/3
         ,verifyAuthPlausibility/1, verifyPacket/4]).

-include_lib("eradius/include/common.hrl").

%RFC 3579, sec 3.3: More than one of user, chap, arap-password and eap-message
%is an error.
%FIXME: RFC 2865 sec 5.44 says that an Access-Request must have one of user,
%chap-password, OR state. We're not looking at state here at all.
%%FIXME: radtest sends user-password and eap-message and message-authenticator
%%       when asked to do eap-md5. I'm pretty sure that radtest is in error, but
%%       am not certain.
verifyAuthPlausibility(#{user_password := _} = Attrs) ->
  case maps:is_key(chap_password, Attrs) orelse
       maps:is_key(arap_password, Attrs) orelse
       maps:is_key(eap_message, Attrs) of
       true -> error;
       false -> ok
  end;
verifyAuthPlausibility(#{chap_password := _} = Attrs) ->
  case maps:is_key(arap_password, Attrs) orelse
       maps:is_key(eap_message, Attrs) of
       true -> error;
       false -> ok
  end;
verifyAuthPlausibility(#{arap_password := _, eap_message := _}) -> error;
%We MUST have a message-authenticator if we have an eap-message.
verifyAuthPlausibility(#{eap_message := _, message_authenticator := _}) -> ok;
verifyAuthPlausibility(#{eap_message := _}) -> error;
verifyAuthPlausibility(#{}) -> ok.

%If we have an EAP-message, we MUST have a Message-Authenticator:
verifyPacket(NASSecret,
             _, #{message_authenticator := MsgAuth},
             <<Type:1/bytes, Identifier:1/bytes, Len:2/bytes, ReqAuth:16/bytes, AttrBin/binary>>) ->
  %message_authenticator has type 80 and len 18.
  BlankedAttrBin=zeroAttr(AttrBin, <<80, 18, MsgAuth/binary>>),
  CalculatedAuth=crypto:hmac(md5, NASSecret,
                                 <<Type/binary, Identifier/binary, Len/binary,
                                   ReqAuth/binary, BlankedAttrBin/binary>>),
  lager:debug("DECODE MsgAuth  ~p", [MsgAuth]),
  lager:debug("DECODE CalcAuth ~p", [CalculatedAuth]),
  case CalculatedAuth == MsgAuth of
    true -> ok;
    false -> error
  end;
%Accounting request:
verifyPacket(NASSecret,
             _, _,
             <<Type:1/bytes, Identifier:1/bytes, Len:2/bytes, MsgAuth:16/bytes, AttrBin/binary>>)
  when Type == <<4>> ->
  CalculatedAuth=crypto:hash(md5, <<Type/binary, Identifier/binary, Len/binary,
                                   0:(16*8), AttrBin/binary, NASSecret/binary>>),
  lager:debug("DECODE MsgAuth  ~p", [MsgAuth]),
  lager:debug("DECODE CalcAuth ~p", [CalculatedAuth]),
  case CalculatedAuth == MsgAuth of
    true -> ok;
    false -> error
  end;

verifyPacket(NASSecret, Auth, Attrs=#{user_password := MsgVerifier
             ,user_name := UserName}, _) ->
  %FIXME: We can get back a list of potential passwords now.
  {ok, Pass}=eradius_auth:lookup_user(UserName, Attrs),
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
  end;
verifyPacket(_, _, _, _) -> error.

determineLength(Code, Id, Auth, Attrs) ->
  Len=byte_size(<<Code/binary, Id, 0:16, Auth/binary>>)
    + iolist_size(Attrs),
  %FIXME: Do something other than crash if our packet is too large.
  %       Max packet length is 4096, per RFC 2865, section 3.
  true=Len =< 4096,
  <<Len:16>>.

%FIXME: This should get passed in a maximum packet size and create packets no
%       larger than that.
encodeRadius(Addr, T, I, A) ->
  encodeRadius(Addr, T, I, A, #{}).
encodeRadius(Addr, Type, Identifier, Auth, Attrs) ->
  {ok, NASPassword}=eradius_auth:lookup_nas(Addr, Attrs),
  case Type of
    access_request -> Code= <<1>>;
    access_accept -> Code= <<2>>;
    access_reject -> Code= <<3>>;
    accounting_request -> Code= <<4>>;
    accounting_response -> Code= <<5>>;
    access_challenge -> Code= <<11>>;
    status_server -> Code= <<12>>
  end,

  AB=encodeAttributes(Attrs, Addr, Auth),
  Len=determineLength(Code, Identifier, Auth, AB),
  case Attrs of
    #{message_authenticator := MA} ->
      MsgAuth=crypto:hmac(md5, NASPassword,
                          <<Code/binary, Identifier, Len/binary,
                            Auth/binary, AB/binary>>),
      MABin=encodeAttributes(#{message_authenticator => MA}, Addr, Auth),
      AttrBin=replaceAttr(AB, MABin, MsgAuth);
    _ ->
      AttrBin=AB
  end,
  RespAuth=crypto:hash(md5, <<Code/binary, Identifier, Len/binary, Auth/binary, AttrBin/binary, NASPassword/binary>>),
  <<Code/binary, Identifier, Len/binary, RespAuth/binary, AttrBin/binary>>.

encodeAttributes(Attrs, Addr, Auth) ->
  eradius_rad_attr:encode(Attrs, Addr, Auth).

decodeAttributes(Pkt, Addr, Auth) ->
  eradius_rad_attr:decode(Pkt, Addr, Auth).

%This will match packets of at *least* 20 bytes.
decodeRadius(P = <<_:1/bytes, _:1/bytes, L:2/bytes, _:16/bytes, _/binary>>) ->
  Len=binary:decode_unsigned(L),
  % Max packet length is 4096, according to RFC 2865, section 3.
  % Min packet length is 20. Note that "packet length" is the same as "byte_size/1
  % of entire packet"... but without any padding that might be present in the
  % packet. The RFC offers no guidance on what to do when the packet is larger
  % than 4096 bytes... so FIXME: print warning and discard packet if > 4096.
  case byte_size(P) >= Len of
    false ->
      {discard, packet_too_short};
    true ->
      %Trim any padding:
      <<Pkt:Len/bytes, _/binary>> =P,
      <<Code, Id, _:2/bytes, Auth:16/bytes, Attrs/binary>> =Pkt,
      Type=
        case Code of
          1 -> access_request;
          2 -> access_accept;
          3 -> access_reject;
          4 -> accounting_request;
          5 -> accounting_response;
          11 -> access_challenge;
          12 -> status_server;
          _ -> unrecognized
        end,
      {ok, #eradius_rad_raw{code=Code, type=Type, id=Id, length=Len, auth=Auth, attrs=Attrs}}
  end;
%If we're here, our packet is obviously too short to contain the data required,
%so we MUST sliently discard it.
decodeRadius(Pkt) when is_binary(Pkt) ->
  {discard, packet_too_short}.

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

