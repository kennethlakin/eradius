-module(eradius_rad_attr).
-compile([{parse_transform, lager_transform}]).

%Current API
-export([encode/3, decode/3]).

%Testing
%FIXME: Move this out to a testing module.
-export([testCompressedAttrs/0]).

%FIXME: Open this file and address the FIXME items inside.
-include_lib("eradius/include/eradius_attr.hrl").

decode(Pkt= <<_, _, _/binary>>, Ip, RadAuth) ->
  decode(Pkt, [], #{}, Ip, RadAuth);
decode(_, _, _) -> {error, attr_length_incorrect}.

decode(<<>>, _, Attrs, _, _) -> {ok, Attrs};
decode(P= <<Id, L, _/binary>>, IdStack, Attrs, Ip, RadAuth) ->
  case byte_size(P) >= L of
    false -> {error, attr_length_incorrect};
    true ->
      <<Data:L/bytes, Rest/binary>> = P,
      EmptyAttr=#eradius_attr{},
      CurrentIdStack=IdStack ++ [Id],
      case eradius_dict:id_lookup(CurrentIdStack) of
        EmptyAttr ->
          %FIXME: Make a nicer error signal
          {error, {attr_unknown, CurrentIdStack}};
        TypeInfo ->
          case decodeType(TypeInfo, Data, CurrentIdStack, Attrs, Ip, RadAuth) of
            {ok, NewAttrs} -> decode(Rest, IdStack, NewAttrs, Ip, RadAuth);
            E={error, _} -> E
          end
      end
  end.

decodeType(#eradius_attr{type=vsa}, <<_, _, _, VendorIdBin:3/bytes, Data/binary>>, IdStack, Attrs, Ip, RadAuth) ->
  EmptyRecord=#eradius_attr{},
  VendorId=binary:decode_unsigned(VendorIdBin),
  NewIdStack=IdStack ++ [VendorId],
  case eradius_dict:id_lookup(NewIdStack) of
    EmptyRecord -> {error, {unknown_vendor, VendorId}};
    _ -> decode(Data, NewIdStack, Attrs, Ip, RadAuth)
  end;
decodeType(#eradius_attr{type=vsa, name=Name}, _, _, _, _, _) ->
  {error, {attr_length_incorrect, Name}};
decodeType(#eradius_attr{type=extended}, <<_, L, ExtId, Data/binary>>, IdStack, Attrs, Ip, RadAuth) ->
  FixedUpData= <<ExtId, (L-1), Data/binary>>,
  decode(FixedUpData, IdStack, Attrs, Ip, RadAuth);
decodeType(#eradius_attr{type=extended, name=Name}, _, _, _, _, _) ->
  {error, {attr_length_incorrect, Name}};
decodeType(#eradius_attr{type=long_extended, name=Name}, <<_, _, _Data/binary>>, _IdStack, _Attrs, _Ip, _RadAuth) ->
  %long_extended type is defined as
  %<<Type, Len, ExtendedType, More:1, Reserved:7, Value/binary>>
  %If the More bit is set, then:
  %* Len must be 255
  %* The *next* attribute _must_ be the same Type and Extended Type
  %
  %The data in each packet in the chain is concatenated and presented as a
  %single binary.
  %So... See RFC 6929 Sec 2.2 for discussion. However...
  %FIXME: Not sure of the best way to do the control flow.
  %       For now, signal error.
  lager:warning("RAD_ATTR Decode: long-extended attributes not currently supported"),
  {error, {long_extended_attrs_unsupported, Name}};
  %{ok, Attrs};
decodeType(#eradius_attr{type=evs, name=Name}, <<_, _, _Data/binary>>, _IdStack, _Attrs, _Ip, _RadAuth) ->
  %evs type is defined as
  % <<VendorId:3/bytes, EvsType, EvsValue/binary>>.
  %
  %So... See RFC 6929 Sec 2.4 for discussion. However...
  %FIXME: Not sure of the best way to do the control flow and logic.
  %       For now, signal error.
  lager:warning("RAD_ATTR Decode: evs attributes not currently supported"),
  {error, {evs_attrs_unsupported, Name}};
decodeType(#eradius_attr{type=tlv}, <<_, _, Data/binary>>, IdStack, Attrs, Ip, RadAuth) ->
  decode(Data, IdStack, Attrs, Ip, RadAuth);
decodeType(#eradius_attr{type=tlv, name=Name}, _, _, _, _, _) ->
  {error, {attr_length_incorrect, Name}};
decodeType(A=#eradius_attr{}
           ,P= <<_, L, _/binary>>, _, Attrs, Ip, RadAuth) ->
  <<TLD:L/bytes, _/binary>> = P,
  NewAttrs=decode_attr_value(A, TLD, Attrs, Ip, RadAuth),
  {ok, NewAttrs}.

encode(Attrs, Ip, RadAuth) when is_map(Attrs) ->
  AttrInfo=getAttrInfoFromNames(maps:to_list(Attrs), Ip, RadAuth),
  encodeAttrTree(AttrInfo).

%NOTE:
%This handles attr trees of the form
%[
% [{CollectionId, Rec} [
%    {NonCollectionId, Rec}, ...]
%  {NonCollectionId, Rec} ...
%  {CollectionId, Rec} [
%    {CollectionId, Rec} [
%      {NonCollectionId, Rec} ...
%      ] ... ] ... ] ...
%]
encodeAttrTree([]) ->
  <<>>;
encodeAttrTree([LhList | Rest]) when is_list(LhList) ->
  LhListBin=encodeAttrTree(LhList),
  RestBin=encodeAttrTree(Rest),
  <<LhListBin/binary, RestBin/binary>>;
encodeAttrTree([{Id, Rec}, Rhs | Rest]) when is_list(Rhs) ->
  RecArgs=encodeAttrTree(Rhs),
  RestBin=encodeAttrTree(Rest),
  %FIXME: Find a better way to signal error.
  %       (probably by returning {ok, Bin} | {error, Error} from
  %       encodeAttrTree/1 and handling it appropriately inside encode/3)
  case doEncode(Rec, Id, RecArgs) of
    {ok, Data} ->
      <<Data/binary, RestBin/binary>>
  end;
encodeAttrTree([{Id, Rec} | Rest]) ->
  Bin=encodeAttrTree(Rest),
  %FIXME: Find a better way to signal error.
  %       (probably by returning {ok, Bin} | {error, Error} from
  %       encodeAttrTree/1 and handling it appropriately inside encode/3)
  case doEncode(Rec, Id, <<>>) of
    {ok, Data} ->
      <<Data/binary, Bin/binary>>
  end.

getAttrInfoFromNames(Names, Ip, RadAuth) ->
  getAttrInfoFromNames(Names, [], Ip, RadAuth).
getAttrInfoFromNames([], Ids, _, _) -> Ids;
getAttrInfoFromNames([{Name, V}|Rest], Ids, Ip, RadAuth) ->
  case eradius_dict:name_lookup(Name) of
    [] ->
      %FIXME: Is there a better way to signal failure?
      lager:warning("RAD_ATTR ID not found for name ~p", [Name]),
      getAttrInfoFromNames(Rest, Ids, Ip, RadAuth);
    Id ->
      case is_list(V) of
        true -> Values=V;
        false -> Values=[V]
      end,
      FilledEntries=fillEntries(Id, Values, Ip, RadAuth),
      getAttrInfoFromNames(Rest, Ids ++ FilledEntries, Ip, RadAuth)
  end.

fillEntries(_, [], _, _) -> [];
fillEntries(IdList, [Value|ValRest], Ip, RadAuth) ->
  [fillEntries(IdList, [], Value, Ip, RadAuth) | fillEntries(IdList, ValRest, Ip, RadAuth)].
fillEntries([Id], IdStack, Value, Ip, RadAuth) ->
  BaseRec=eradius_dict:id_lookup(IdStack ++ [Id]),
  %FIXME: Better error signalling if this is the case
  false = BaseRec==#eradius_attr{},
  {ok, PlainRec}=encodeValue(BaseRec, Value),
  {ok, Rec}=maybeEncryptValue(PlainRec, Ip, RadAuth),
  [{Id, Rec}];
fillEntries([Id | Rest], IdStack, Value, Ip, RadAuth) ->
  NextStack=IdStack ++ [Id],
  Rec=eradius_dict:id_lookup(NextStack),
  %FIXME: Better error signalling if this is the case
  false = Rec==#eradius_attr{},
  [{Id, Rec} | [fillEntries(Rest, NextStack, Value, Ip, RadAuth)]].

%FIXME: Try to handle encrypt_flag=3 (Ascend-Send-Secret)
maybeEncryptValue(A=#eradius_attr{value_data=Data, encrypt_flag=1}, Ip, RadAuth) ->
  ScrambledData=rfc2865_scramble(Data, Ip, RadAuth),
  {ok, A#eradius_attr{value_data=ScrambledData}};
maybeEncryptValue(A=#eradius_attr{value_data=Data, encrypt_flag=2}, Ip, RadAuth) ->
  ScrambledData=rfc2868_scramble(Data, Ip, RadAuth),
  {ok, A#eradius_attr{value_data=ScrambledData}};
maybeEncryptValue(#eradius_attr{encrypt_flag=3}, _, _) ->
  lager:error("RAD_ATTR Ascend encryption method not supported."),
  {error, {encrypt_unsupported, ascend}};
maybeEncryptValue(#eradius_attr{encrypt_flag=E}, _, _) when E /= undefined ->
  lager:warning("RAD_ATTR Unsupported encrypt type: ~w.", [E]),
  {error, {encrypt_unsupported, E}};
maybeEncryptValue(A, _, _) -> {ok, A}.

%See RFC2865 sec 5.2 (User-Password)
rfc2865_scramble(Key, Ip, RadAuth) ->
  Salt= <<>>,
  rfcScrambleGeneral(Key, Salt, Ip, RadAuth).
rfc2865_unscramble(Scrambled, Ip, RadAuth) ->
  Salt= <<>>,
  rfcUnscrambleGeneral(Scrambled, Salt, Ip, RadAuth).

%See RFC2868 sec 3.5 (Tunnel-Password)
rfc2868_scramble(Key, Ip, RadAuth) ->
  <<_:1, BaseSalt:15>> =crypto:strong_rand_bytes(2),
  Salt= <<1:1,BaseSalt:15>>,
  rfcScrambleGeneral(Key, Salt, Ip, RadAuth).
rfc2868_unscramble(<<Salt:2/bytes, Scrambled/binary>>, Ip, RadAuth) ->
  rfcUnscrambleGeneral(Scrambled, Salt, Ip, RadAuth).

rfcUnscrambleGeneral(Scrambled, Salt, Ip, RadAuth) ->
  {ok, NasSecret}=eradius_auth:lookup_nas(Ip),
  %Ensure that we're a multiple of 16 bytes.
  0=(byte_size(Scrambled) rem 16),
  <<Len, Data/binary>> =startGeneralUnscramble(Scrambled, NasSecret, RadAuth, Salt),
  %Trim padding. Len includes the length byte.
  binary:part(Data, 0, Len-1).

rfcScrambleGeneral(Key, Salt, Ip, RadAuth) ->
  {ok, NasSecret}=eradius_auth:lookup_nas(Ip),
  TotalLen=byte_size(Key)+1,
  case 16-(TotalLen rem 16) of
    16 -> PaddingLen=0;
    PaddingLen -> PaddingLen
  end,
  Padding=binary:copy(<<0>>, PaddingLen),
  Plain= <<TotalLen, Key/binary, Padding/binary>>,
  Scrambled=startGeneralScramble(Plain, NasSecret, RadAuth, Salt),
  <<Salt/binary, Scrambled/binary>>.

startGeneralScramble(<<Plain:16/bytes, Rest/binary>>, Secret, RadAuth, Salt) ->
  B=crypto:hash(md5, <<Secret/binary, RadAuth/binary, Salt/binary>>),
  C=crypto:exor(Plain, B),
  doGeneralScramble(Rest, Secret, C, C).
doGeneralScramble(<<>>, _, _, Acc) -> Acc;
doGeneralScramble(<<Plain:16/bytes, Rest/binary>>, Secret, PrevChunk, Acc) ->
  B=crypto:hash(md5, <<Secret/binary, PrevChunk/binary>>),
  C=crypto:exor(Plain, B),
  doGeneralScramble(Rest, Secret, C, <<Acc/binary, C/binary>>).

startGeneralUnscramble(<<Crypt:16/bytes, Rest/binary>>, Secret, RadAuth, Salt) ->
  B=crypto:hash(md5, <<Secret/binary, RadAuth/binary, Salt/binary>>),
  C=crypto:exor(Crypt, B),
  doGeneralUnscramble(Rest, Secret, Crypt, C).
doGeneralUnscramble(<<>>, _, _, Acc) -> Acc;
doGeneralUnscramble(<<Crypt:16/bytes, Rest/binary>>, Secret, PrevChunk, Acc) ->
  Md5Bin= <<Secret/binary, PrevChunk/binary>>,
  B=crypto:hash(md5, Md5Bin),
  C=crypto:exor(Crypt, B),
  doGeneralUnscramble(Rest, Secret, Crypt, <<Acc/binary, C/binary>>).

%Atoms refer to named values
encodeValue(A=#eradius_attr{val_name_map=ValueMap, name=Name}, ValueName) when is_atom(ValueName) ->
  case maps:get(ValueName, ValueMap, undefined) of
    undefined ->
      lager:error("RAD_ATTR Named value ~p not found for attr ~p", [ValueName, Name]),
      {error, {value, ValueName, not_found_for, Name}};
    Val ->
      encodeValue(A, Val)
  end;
%Assume that a binary has already been correctly prepared
encodeValue(A=#eradius_attr{}, Data) when is_binary(Data) ->
  {ok, A#eradius_attr{value_data=Data}};
encodeValue(A=#eradius_attr{type=byte}, Data) ->
  encodeValue(A, <<Data:8>>);
encodeValue(A=#eradius_attr{type=short}, Data) ->
  encodeValue(A, <<Data:16>>);
encodeValue(A=#eradius_attr{type=signed}, Data) ->
  case Data < 0 of
    true  -> Sign=1;
    false -> Sign=0
  end,
  encodeValue(A, <<Sign:1, Data:31>>);
%FIXME: Better support the structured datatypes.
%       Would be nice to put an Erlang-formatted IP tuple in here.
%       &etc.
encodeValue(A=#eradius_attr{type=Type}, Data) when
    (Type == integer orelse Type == date orelse Type == ipaddr) ->
  encodeValue(A, <<Data:32>>);
encodeValue(A=#eradius_attr{type=ipv4prefix}, Data) ->
  encodeValue(A, <<Data:48>>);
encodeValue(A=#eradius_attr{type=Type}, Data) when
    (Type == ifid orelse Type == integer64) ->
  encodeValue(A, <<Data:64>>);
encodeValue(A=#eradius_attr{type=ipv6addr}, Data) ->
  encodeValue(A, <<Data:128>>);
encodeValue(A=#eradius_attr{type=ipv6prefix}, Data) ->
  encodeValue(A, <<Data:144>>);
%Non-standard WIMAX datatype.
%It's either a IPv4 or v6 address under the obvious conditions.
%FIXME: Figure out how to encode combo_ip
%encodeValue(A=#eradius_attr{type=combo_ip}, Data) ->
encodeValue(#eradius_attr{type=Type}, _) -> {error, {unsupported_type, Type}}.

%% NOTE: To handle WiMAX "continuation byte", know these things:
%%       1) The high-bit is not set on each _attribute_, just on the outermost VSA
%%       2) The high-bit _MAY_ be set for "string" and "octet" types, but their
%%          max size is still 253 bytes.
%%       3) The high-bit _MAY_ be set for "vsa" types.
%%       4) The high-bit _MUST NOT_ be set for any other type.
%%       5) All other bits in the continuation octet _MUST_ be set to 0 by the
%%       sender and ignored by the reciever.
%%       Having said all that...
%%       we should detect when we're asked to either decode or encode an
%%       attribute with a WiMAX contintuation byte, and refuse to do so.
%%       I don't want to work out the logic required to actually deal with
%%       fragmented VSAs at this time.

%Okay. Here's how evs, extended, and long-extended attributes seem to work:
%      "TLV" attributes in the 24[1-4] ID space are "extended" attributes.
%      "TLV" attributes in the 24[5-6] ID space are "long extended" attributes.
%      "TLV" attributes in the 24[1-6].26 ID space are "extended vendor
%            specific" attributes.

decode_attr_value(A=#eradius_attr{type=Type}, <<_, _, Value/binary>>, Attrs, Ip, RadAuth) when
    Type == integer orelse Type == integer64 orelse Type == short
    orelse Type == date ->
  BinVal=binary:decode_unsigned(Value),
  {ok, DecVal}=maybeDecryptValue(A, BinVal, Ip, RadAuth),
  maybe_append_val(A, Attrs, DecVal);
%FIXME: Validate the length of length-restricted types like combo_ip.
decode_attr_value(A=#eradius_attr{type=Type}, <<_, _, Value/binary>>, Attrs, Ip, RadAuth) when
    Type == string orelse Type == octets orelse Type == ipv6addr orelse Type == ipv6prefix
    orelse Type == ifid orelse Type == ipaddr orelse Type == byte orelse Type == ipv4prefix
    orelse Type == combo_ip orelse Type == ether orelse Type == abinary ->
  {ok, DecVal}=maybeDecryptValue(A, Value, Ip, RadAuth),
  maybe_append_val(A, Attrs, DecVal);
decode_attr_value(A=#eradius_attr{type=signed}, <<_, _, Value:4/bytes>>, Attrs, Ip, RadAuth) ->
  {ok, <<Sign:1, DecVal:31>>}=maybeDecryptValue(A, Value, Ip, RadAuth),
  Val=binary:decode_unsigned(<<0:1, DecVal:31>>),
  case Sign of
    0 -> SignVal=Val;
    1 -> SignVal=-Val
  end,
  maybe_append_val(A, Attrs, SignVal).

maybeDecryptValue(#eradius_attr{encrypt_flag=1}, Data, Ip, RadAuth) ->
  UnscrambledData=rfc2865_unscramble(Data, Ip, RadAuth),
  {ok, UnscrambledData};
maybeDecryptValue(#eradius_attr{encrypt_flag=2}, Data, Ip, RadAuth) ->
  UnscrambledData=rfc2868_unscramble(Data, Ip, RadAuth),
  {ok, UnscrambledData};
maybeDecryptValue(#eradius_attr{encrypt_flag=3}, _, _, _) ->
  lager:error("RAD_ATTR Ascend encryption method not supported."),
  {error, {encrypt_unsupported, ascend}};
maybeDecryptValue(#eradius_attr{encrypt_flag=E}, _, _, _) when E /= undefined ->
  lager:warning("RAD_ATTR Unsupported encrypt type: ~w.", [E]),
  {error, {encrypt_unsupported, E}};
maybeDecryptValue(_, Data, _, _) ->
  {ok, Data}.

maybe_append_val(#eradius_attr{name=Name, concat_flag=true}, Attrs, Val) ->
  %NOTE: It makes no sense to concat predefined values together, so don't
  %      search val_val_map.
  case maps:get(Name, Attrs, undefined) of
    undefined -> Attrs#{Name => Val};
    PrevVal ->
      case {is_list(PrevVal), is_binary(PrevVal)} of
        {true, false} ->
          Attrs#{Name := PrevVal ++ Val};
        {false, true} ->
          Attrs#{Name := <<PrevVal/binary, Val/binary>>}
      end
  end;
maybe_append_val(#eradius_attr{name=Name, val_val_map=ValValMap, concat_flag=false}, Attrs, V) ->
  case maps:is_key(V, ValValMap) of
    true ->
      Val=maps:get(V, ValValMap);
    false ->
      Val=V
  end,
  case maps:get(Name, Attrs, undefined) of
    undefined -> Attrs#{Name => Val};
    PrevVal ->
      case is_list(PrevVal) of
        true ->
          Attrs#{Name := PrevVal ++ [Val]};
        false ->
          Attrs#{Name := [PrevVal] ++ [Val]}
      end
  end.

-spec doEncode(#eradius_attr{}, Id :: pos_integer(), PacketTail :: binary()) ->
  {ok, binary()} | {error, term()} | {warn, term()}.
%Each attr can only 255 bytes long, and the header is 2 bytes.
doEncode(#eradius_attr{name=Name, value_data=Data, len_width=LW, val_width=VW}, _, _) when byte_size(Data) > 255-(LW+VW) ->
  {error, {data_too_long, Name}};
%If this is a type that has a specified length, check it.
doEncode(A=#eradius_attr{declared_length=Len}, Id, <<>>) when Len /= undefined ->
  verifyLenAndPack(Len, A, Id);
doEncode(#eradius_attr{type=Type, value_data=Data, len_width=LW, val_width=VW}, Id, <<>>) when
    (Type == string orelse Type == text orelse Type == octets) ->
  DLen=byte_size(Data),
  {ok, <<Id:(LW*8), (DLen+2):(VW*8), Data/binary>>};
doEncode(A=#eradius_attr{type=byte}, Id, <<>>) ->
  verifyLenAndPack(1, A, Id);
doEncode(A=#eradius_attr{type=short}, Id, <<>>) ->
  verifyLenAndPack(2, A, Id);
doEncode(A=#eradius_attr{type=Type}, Id, <<>>) when
    (Type == integer orelse Type == signed orelse
     Type == date orelse Type == ipaddr) ->
  verifyLenAndPack(4, A, Id);
doEncode(A=#eradius_attr{type=ipv4prefix}, Id, <<>>) ->
  verifyLenAndPack(6, A, Id);
doEncode(A=#eradius_attr{type=Type}, Id, <<>>) when
    (Type == ifid orelse Type == integer64) ->
  verifyLenAndPack(8, A, Id);
doEncode(A=#eradius_attr{type=ipv6addr}, Id, <<>>) ->
  verifyLenAndPack(16, A, Id);
doEncode(A=#eradius_attr{type=ipv6prefix}, Id, <<>>) ->
  verifyLenAndPack(18, A, Id);
%Non-standard WIMAX datatype.
%It's either a IPv4 or v6 address under the obvious conditions.
doEncode(A=#eradius_attr{type=combo_ip, value_data=Data}, Id, <<>>) when
    byte_size(Data) == 4 orelse byte_size(Data) == 16 ->
  verifyLenAndPack(byte_size(Data), A, Id);
doEncode(#eradius_attr{type=vsa}, Id, PacketTail) ->
  {ok, <<Id, (byte_size(PacketTail)+2), PacketTail/binary>>};
%The vendor type is a pseudo-type. It should be enclosed in a 'vsa' attribute.
doEncode(#eradius_attr{type=vendor}, Id, PacketTail) ->
  {ok, <<0, Id:(3*8), PacketTail/binary>>};
doEncode(#eradius_attr{type=tlv, name=Name, len_width=LW, val_width=VW, wimax_continuation=WimaxContinuation}, Id, PacketTail) ->
  DataLen=byte_size(PacketTail),
  case WimaxContinuation of
    true ->
      %FIXME: Determine how to handle overlarge VSAs.
      lager:warning("RAD_ATTR Setting WiMAX continuation bit to 0, regardless of VSA size. ~p ~p", [Id, Name]),
      IsContinuation=0,
      Ret= <<Id:(VW*8), (DataLen+LW+VW+1):(LW*8), IsContinuation:1, 0:7,  PacketTail/binary>>;
    false ->
      Ret= <<Id:(VW*8), (DataLen+LW+VW):(LW*8), PacketTail/binary>>
  end,
  case LW of
    0 -> Ret;
    _ ->
      case byte_size(Ret) =< trunc(math:pow(2, LW*8)) of
        true -> {ok, Ret};
        false -> {error, {data_too_long, Name}}
      end
  end;
doEncode(#eradius_attr{type=evs, name=Name, value_data=Data}, _Id, _PacketTail) ->
  case byte_size(Data) >= 6 of
    true -> {warn, {unsupported, evs}};
    _ -> {error, {data_length_incorrect, Name}}
  end;
%Ascend binary filter format.
doEncode(#eradius_attr{type=abinary}, _Id, _PacketTail) ->
  {warn, {unsupported, abinary}};
doEncode(#eradius_attr{}, _, _) ->
  {warn, unrecognized_attr}.

verifyLenAndPack(Len, #eradius_attr{value_data=D, name=N, len_width=LW, val_width=VW}, Id) ->
  case byte_size(D) of
    Len ->
      {ok, <<Id:(VW*8), (Len+LW+VW):(LW*8), D/binary>>};
    _ -> {error, {data_length_incorrect, N}}
  end.

%%And now a digression into testing "compressed" nested Vendor Specific Attributes:
%%(Note that we don't yet compress VSAs, but both our decode and encode code
%% can handle compressed VSAs. It's "just" a matter of changing
%% getAttrInfoFromNames to create a compressed tree to feed to encodeAttrTree.)
%%
%%Our test packet should be
%%26.311.9 (2)
%%26.311.9 (1)
%%26.311.10.1 (1)
%%26.311.10.2 (2)
%%26.311.11.11.1 (6)
%%26.311.11.11.2 (7)
%%That is:
%%#{ms_ras_vendor=> [2, 1], ms_fake_nested_integer_ten_one => 1
%%  ,ms_fake_nested_integer_ten_two => 2
%%  ,ms_fake_nested_integer_eleven_one => 6
%%  ,ms_fake_nested_integer_eleven_two => 7}.
%%
%%It should be equal to
%%either
%%<<26, 48, 0, 311:(8*3),9, 6, 0,0,0,2,9, 6, 0,0,0,1,10, 14, 1, 6, 0, 0, 0, 1, 2, 6, 0, 0, 0, 2,11, 16, 11, 14, 1, 6, 0, 0, 0, 6, 2, 6, 0, 0, 0, 7>>
%%or more likely:
%%<<26, 54, 0, 311:(8*3),9, 6, 0,0,0,2,9, 6, 0,0,0,1,10, 8, 1, 6, 0, 0, 0, 1, 10, 8, 2, 6, 0, 0, 0, 2,11, 10, 11, 8, 1, 6, 0, 0, 0, 6,11, 10, 11, 8, 2, 6, 0, 0, 0, 7>>
%%Actually, even more likely:
%%<<26, 12, 0, 311:(8*3), 9, 6, 0, 0, 0, 2,
%%  26, 12, 0, 311:(8*3), 9, 6, 0, 0, 0, 1,
%%  26, 14, 0, 311:(8*3), 10, 8, 1, 6, 0, 0, 0, 1,
%%  26, 14, 0, 311:(8*3), 10, 8, 2, 6, 0, 0, 0, 2,
%%  26, 16, 0, 311:(8*3), 11, 10, 11, 8, 1, 6, 0, 0, 0, 6,
%%  26, 16, 0, 311:(8*3), 11, 10, 11, 8, 2, 6, 0, 0, 0, 7
%%>>,
%%but the order probably won't be the same...
%%
%%We can save space by organizing this as a tree:
%%              26
%%              311
%%         9    10      11
%%        I I  1   2    11
%%             I   I   1   2
%%                     I   I
%%
%% [[26, 311, [9, I1, I2], [10, [1, I3], [2, I4]], [11, 11, [1, I5], [2, I6]]]]
%%
%% And writing out the branches along a path, then all the nodes on that path
%% Then moving on to the next set of branches.
%% This will automatically give us ID compression, and give us the smallest
%% possible representation of our attrs.
%% NOTE: Compression of VSAs that have format=X,0 should either not be done, or
%%       should only be done for attributes that have a well-known length.
%%       (My money's on "Don't do it!")

%%For testing that our encode works correctly with a "compressed" attribute
%%tree:
%%FIXME: Note that this will only work with the fake definitions in the
%%       dict-test dictionary.
%%Begin Compressed Attribute Tree Test Code
getRasVendorAttrs() ->
  BaseRec=eradius_dict:id_lookup([26,311,9]),
  RecFirst=BaseRec#eradius_attr{value_data= <<0,0,0,2>>},
  RecSecond=BaseRec#eradius_attr{value_data= <<0,0,0,1>>},
  [RecFirst, RecSecond].
getElevenOne() ->
  BaseRec=eradius_dict:id_lookup([26, 311, 11, 11, 1]),
  BaseRec#eradius_attr{value_data= <<0, 0, 0, 6>>}.
getElevenTwo() ->
  BaseRec=eradius_dict:id_lookup([26, 311, 11, 11, 2]),
  BaseRec#eradius_attr{value_data= <<0, 0, 0, 7>>}.
getTenOne() ->
  BaseRec=eradius_dict:id_lookup([26, 311, 10, 1]),
  BaseRec#eradius_attr{value_data= <<0, 0, 0, 1>>}.
getTenTwo() ->
  BaseRec=eradius_dict:id_lookup([26, 311, 10, 2]),
  BaseRec#eradius_attr{value_data= <<0, 0, 0, 2>>}.

testCompressedAttrs() ->
  FakeIp={127,0,0,1},
  FakeRadAuth=binary:copy(<<0>>, 32),
  [RasAttrFirst, RasAttrSecond] = getRasVendorAttrs(),
  ElevenOne = getElevenOne(),
  ElevenTwo = getElevenTwo(),
  TenOne = getTenOne(),
  TenTwo = getTenTwo(),
  AttrOne=#{ms_ras_vendor => [2, 1]},
  TreeOne=[[{26, eradius_dict:id_lookup([26])}, [
            {311, eradius_dict:id_lookup([26, 311])}, [
             {9, RasAttrFirst}, {9, RasAttrSecond}]
            ]]],
  BinOne=encodeAttrTree(TreeOne),
  {ok, AttrOne} = decode(BinOne, FakeIp, FakeRadAuth),
  AttrTwo= #{ms_fake_nested_integer_eleven_one => 6,
             ms_fake_nested_integer_eleven_two => [7, 7],
             ms_fake_nested_integer_ten_one => 1,
             ms_fake_nested_integer_ten_two => 2,
             ms_ras_vendor => [2,1]},
  TreeTwo=[[{26, eradius_dict:id_lookup([26])}, [
            {311, eradius_dict:id_lookup([26, 311])}, [
             {9, RasAttrFirst}, {9, RasAttrSecond},
             {11, eradius_dict:id_lookup([26, 311, 11])}, [
              {11, eradius_dict:id_lookup([26, 311, 11, 11])}, [
               {1, ElevenOne}, {2, ElevenTwo}, {2, ElevenTwo}]],
             {10, eradius_dict:id_lookup([26, 311, 10])}, [
              {1, TenOne}, {2, TenTwo}]
             ]]]],
  BinTwo=encodeAttrTree(TreeTwo),
  {ok, AttrTwo}=decode(BinTwo, FakeIp, FakeRadAuth),
  %And verify that our regular encode<->decode round trip works:
  UncompressedTreeTwoBin=encode(AttrTwo, FakeIp, FakeRadAuth),
  {ok, AttrTwo}=decode(UncompressedTreeTwoBin, FakeIp, FakeRadAuth).
%%End Compressed Attribute Tree Test Code

