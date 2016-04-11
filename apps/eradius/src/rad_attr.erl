-module(rad_attr).

-export([decodeAttr/3, encodeAttr/2]).

decodeAttr(1, _Len, Data) ->
  {ok, user_name, Data};
decodeAttr(2, Len, Data) ->
  case Len >= 18 andalso Len =<  130 of
    true ->  {ok, user_password, Data};
    false -> {error, attr_length_incorrect, user_password, Data}
  end;
decodeAttr(3, Len, Data) ->
  case Len == 19 of
    true ->
      <<Ident:1/bytes, String:16/bytes>> = Data,
      {ok, chap_password, {Ident, String}};
    false -> {error, attr_length_incorrect, chap_password, Data}
  end;
decodeAttr(4, Len, Data) ->
  case Len == 6 of
    true ->
      {ok, nas_ip_address, Data};
    false -> {error, attr_length_incorrect, nas_ip_address, Data}
  end;
decodeAttr(5, Len, Data) ->
  case Len == 6 of
    true -> {ok, nas_port, Data};
    false -> {error, attr_length_incorrect, nas_port, Data}
  end;
decodeAttr(12, Len, Data) ->
  case Len == 6 of
    true -> {ok, framed_mtu, binary:decode_unsigned(Data)};
    false -> {error, attr_length_incorrect, framed_mtu, Data}
  end;
decodeAttr(24, _, Data) ->
  {ok, state, Data};
decodeAttr(30, _, Data) ->
  {ok, called_station_id, Data};
decodeAttr(31, _, Data) ->
  {ok, calling_station_id, Data};
decodeAttr(32, _, Data) ->
  {ok, nas_identifier, Data};
decodeAttr(33, _, Data) ->
  {ok, proxy_state, Data};
decodeAttr(60, Len, Data) ->
  case Len >= 6 of
    true -> {ok, chap_challenge, Data};
    false -> {error, attr_length_incorrect, chap_challenge, Data}
  end;
decodeAttr(61, Len, Data) ->
  case Len == 6 of
    true -> {ok, nas_port_type, binary:decode_unsigned(Data)};
    false -> {error, attr_length_incorrect, nas_port_type, Data}
  end;
decodeAttr(79, _, Data) ->
  {ok, eap_message, Data};
decodeAttr(80, Len, Data) ->
  case Len == 18 of
    true -> {ok, message_authenticator, Data};
    false -> {error, attr_length_incorrect, message_authenticator, Data}
  end;
decodeAttr(95, Len, Data) ->
  case Len == 18 of
    true ->
      {ok, nas_ipv6_address, Data};
    false -> {error, attr_length_incorrect, nas_ipv6_address, Data}
  end;
%This is a vendor-specific attribute. We need to take care to
%only work with attrs that we recognize.
decodeAttr(26, Len, Data) ->
  case Len >= 7 of
    true ->
      <<_:1/bytes, BVC:3/bytes, _/binary>> = Data,
      VendorCode=binary:decode_unsigned(BVC),
      case VendorCode of
        %Microsoft's Private Vendor Code
        311 ->
          %FIXME: Create VSA processing machinery for when we have multiple
          %       VSAs stuffed into a single RADIUS VSA.
          %       Also, check the VTypes to make sure that we know how to work
          %       with all of them, (and report unknown for ones that we don't)
          %       and the VLens to make sure that they match the data associated
          %       with the VSA slice and report the error if there is a
          %       mismatch.
          <<_:4/bytes, VT:1/bytes, VL:1/bytes, _/binary>> = Data,
          VType=binary:decode_unsigned(VT),
          VLen=binary:decode_unsigned(VL),
          {ok, vendor_specific, {VType, VLen}};
        _ ->
          {warn, unrecognized_attr}
      end;
    false -> {error, attr_length_incorrect, vendor_specific, Data}
  end;

decodeAttr(_, _, _) ->
  {warn, unrecognized_attr}.

encodeAttr(state, D) when is_binary(D) ->
  encodeString(<<24>>, D);
encodeAttr(eap_message, D) when is_binary(D) ->
  encodeString(<<79>>, D);
encodeAttr(message_authenticator, D) when is_binary(D) ->
  case byte_size(D)+2 of
    18 -> {ok, <<80, 18, D/binary>>};
    _ -> {error, data_length_incorrect}
  end;
encodeAttr(mschap_mppe_send_key, D) when is_binary(D) ->
  case byte_size(D) of
    50 -> {ok, <<26, 58, 311:32, 16, 52, D/binary>>};
    _ -> {error, data_length_incorrect}
  end;
encodeAttr(mschap_mppe_recv_key, D) when is_binary(D) ->
  case byte_size(D) of
    50 -> {ok, <<26, 58, 311:32, 17, 52, D/binary>>};
    _ -> {error, data_length_incorrect}
  end;
encodeAttr(_, _) ->
  {warn, unrecognized_attr}.

%Strings of length 0 are omitted.
encodeString(<<_:1/bytes>>, <<>>) -> {ok, <<>>};
encodeString(<<_:1/bytes>>, D) when byte_size(D) > 253 -> {error, data_too_long};
encodeString(<<Type:1/bytes>>, D) ->
  Sz=byte_size(D),
  {ok, <<Type/binary, (Sz+2), D/binary>>}.
