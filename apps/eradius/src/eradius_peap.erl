-module(eradius_peap).

%To work with public key records:
-include_lib("public_key/include/public_key.hrl").

-include_lib("eradius/include/common.hrl").

-compile([{parse_transform, lager_transform}]).
-export([handle/2]).

handle({handle, #eradius_eap{}, #eradius_rad{}},
       State=#{peap := MethodData=#{state := undefined}}) ->
  lager:info("PEAPv? Sending start"),
  StartFlag = <<0:1, 0:1, 1:1, 0:3>>,
  Version=1,
  Data = <<25, StartFlag/bitstring,  Version:2>>,
  NS=State#{peap := MethodData#{state := start_sent}},
  {enqueue_and_send, {access_challenge, request, Data}, NS};
handle({handle, #eradius_eap{typedata=TypeData}
        ,#eradius_rad{ip=Ip, state=RadState}},
       State=#{peap := MethodData=#{state := start_sent}}) ->
  %FIXME: Actually validate the TLS data
  <<LenIncluded:1, _:7, _/binary>> = TypeData,
  case LenIncluded of
    0 ->
      _TLSLen=undefined,
      <<_:1, _MoreFrags:1, _Start:1, 0:3, PeapVer:2, Data/binary>> = TypeData;
    1 ->
      <<_:1, _MoreFrags:1, _Start:1, 0:3, PeapVer:2, _TLSLen:4/bytes, Data/binary>> = TypeData
  end,
  case PeapVer of
    %We don't currently support PEAPv2.
    0 -> ok;
    1 -> ok
  end,
  lager:info("PEAPv~p Got reply", [PeapVer]),
  {TlsSrvPid, NewState}=
  case maps:get(tls_srv_pid, State) of
    undefined ->
      {ok, P}=radius_worker:start(eradius_peap_tls_srv, self()),
      lager:debug("PEAPv~p TLS Helper started ~p", [PeapVer, P]),
      link(P),
      {P, State#{tls_srv_pid := P}};
    P ->
      lager:debug("PEAPv~p Using TLS Helper ~p", [PeapVer, P]),
      {P, State}
  end,
  lager:info("PEAPv~p Continuing Phase 1", [PeapVer]),
  ok=eradius_peap_tls_srv:start_tls(TlsSrvPid, Ip, RadState, Data),
  {send_queued, NewState#{peap := MethodData#{state := tls_not_up
                                              ,peap_ver => PeapVer
                                              ,tls_state => server_hello_not_done
                                              ,tls_queue => <<>>}}};
handle({handle, #eradius_eap{typedata=TypeData}
        ,#eradius_rad{ip=Ip}},
       State=#{peap := #{state := tls_not_up, peap_ver := PeapVer}}) ->
  %FIXME: Actually validate the TLS data (PEAP version included.)
  case TypeData of
    <<0:6, PeapVer:2>> ->
      lager:info("PEAPv~p Sending queued data", [PeapVer]),
      {send_queued, State};
    <<LenIncluded:1, MoreFrags:1, Start:1, 0:3, PeapVer:2, _/binary>> ->
      case LenIncluded of
        1 ->
          <<LenIncluded:1, MoreFrags:1, Start:1, 0:3, PeapVer:2, _TLSLen:4/bytes, Data/binary>> = TypeData;
        0 ->
          _TLSLen=undefined,
          <<LenIncluded:1, MoreFrags:1, Start:1, 0:3, PeapVer:2, Data/binary>> = TypeData
      end,
      lager:info("PEAPv~p Handling TLS Data ~p bytes", [PeapVer, byte_size(Data)]),
      #{tls_srv_pid := SrvPid} = State,
      eradius_peap_tls_srv:handlePacket(SrvPid, Ip, Data),
      %If we have more TLS frags, it seems that we can get away
      %with sending the partial frags to the ssl module and grinding for more.
      case MoreFrags of
        %Send a PEAP ACK to get more fragments.
        1 ->
          %FIXME: Make this not hard-coded!
          EapMtu=1024,
          [Pkt]=encode_packets(EapMtu, not_start, PeapVer, <<>>),
          {enqueue_and_send, {access_challenge, request, Pkt}, State};
        %Send whatever the ssl module has for us to send.
        _ -> {send_queued, State}
      end
  end;
handle({handle, #eradius_eap{}, #eradius_rad{}},
       State=#{peap := MethodData=#{state := tls_up
                                   ,peap_ver := PeapVer}}) ->
  lager:info("PEAPv~p Starting Phase 2", [PeapVer]),
  lager:debug("PEAPv~p Tx TLS identity request.", [PeapVer]),
  ok=sendTlsIdentityRequest(State),
  {send_queued, State#{peap := MethodData#{state := inner_ident_sent}}};
handle({handle, #eradius_eap{typedata=TypeData}
        ,#eradius_rad{ip=Ip}},
       State=#{peap := #{state := inner_ident_sent, peap_ver := PeapVer}}) ->
  %FIXME: Actually validate the TLS data (PEAP version included.)
  <<LenIncluded:1, _:7, Rest/binary>> = TypeData,
  case byte_size(Rest) of
    0 ->
      lager:emergency("PEAPv~p ~p WARNING In state inner_ident_sent. Got something that's not a TLS record.",
                      [PeapVer, self()]),
      {send_queued, State};
    _ ->
      case LenIncluded of
        1 -> <<LenIncluded:1, _MoreFrags:1, _Start:1, 0:3, PeapVer:2, _TLSLen:4/bytes, Data/binary>> = TypeData;
        0 ->
          _TLSLen=undefined,
          <<LenIncluded:1, _MoreFrags:1, _Start:1, 0:3, PeapVer:2, Data/binary>> = TypeData
      end,
      lager:info("PEAPv~p Handling TLS Data ~p bytes", [PeapVer, byte_size(Data)]),
      SrvPid=maps:get(tls_srv_pid, State),
      eradius_peap_tls_srv:handlePacket(SrvPid, Ip, Data),
      {send_queued, State}
  end;
handle({handle, #eradius_eap{}, #eradius_rad{}},
       State=#{peap := #{state := inner_auth_success, peap_ver := PeapVer
                         ,success_attrs := SuccessAttrs}
               ,tls_msk := MSK}) ->
  <<MasterSendCryptKey:32/bytes, MasterRecvCryptKey:32/bytes>> =MSK,
  %Yes, these are backwards.
  MppeAttrs=#{ms_mppe_send_key => MasterRecvCryptKey, ms_mppe_recv_key => MasterSendCryptKey},
  AddlAttrs=maps:merge(SuccessAttrs, MppeAttrs),
  lager:info("PEAPv~p Inner auth success. Sending RADIUS accept", [PeapVer]),
  {auth_ok, {access_accept, success, <<>>, AddlAttrs}, State};
handle({handle, #eradius_eap{}, #eradius_rad{}},
       State=#{peap := #{state := inner_auth_failure, peap_ver := PeapVer
                        ,failure_attrs := FailureAttrs}}) ->
  lager:info("PEAPv~p Inner auth failure. Sending RADIUS reject", [PeapVer]),
  {auth_fail, {access_reject, failure, <<>>, FailureAttrs}, State};

handle({tls_up, RadState}, State=#{current_method := peap
                                        ,last_rad := #eradius_rad{state=RS}
                                        ,tls_msk := undefined
                                        ,tls_srv_pid := SrvPid
                                        ,peap := MethodData=
                                        #{peap_ver := PeapVer}})
  when RS == RadState ->
  % So, PEAPv0 uses "client EAP encryption" as the string.
  %     PEAPv1 uses "client PEAP encryption" as the string.
  % However... the documentation for wpa_supplicant.conf indicates
  % that many RADIUS servers work in PEAPv1 mode with
  % "client EAP encryption" as the string. In fact, using the
  % PEAPv0 string in PEAPv1 mode is the *DEFAULT* wpa_supplicant
  % configuration. So, keep this in mind. Becase we cannot *detect* a
  % keying mismatch, it might be safest to just use "client EAP encryption".
  % See:
  % https://w1.fi/cgit/hostap/plain/wpa_supplicant/wpa_supplicant.conf
  % for more info! This
  % https://w1.fi/cgit/hostap/plain/wpa_supplicant/eap_testing.txt
  % might also be of interest.
  PEAPLabel= <<"client EAP encryption">>,
  {ok, <<MSK:64/bytes>>}=eradius_peap_tls_srv:run_prf(SrvPid, master_secret, PEAPLabel,
                                                      [client_random, server_random], 64),
  lager:debug("PEAPv~p MSK is ~p", [PeapVer, radius_server:bin_to_hex(MSK)]),
  %If we've gotten the TLS up message after our peer has requested more data,
  %we need to reprocess the most recent EAP packet (which will be an empty PEAP
  %packet).
  #{tx_queue := TxQueue, tx_credits := TxCredits, peap := #{tls_queue := TlsQueue}} = State,
  case TxCredits == 1 andalso TlsQueue == <<>> andalso queue:is_empty(TxQueue) of
    true ->
      lager:debug("PEAPv~p Rehandling last EAP packet", [PeapVer]),
      gen_fsm:send_event(self(), rehandle_last_eap_packet);
    false -> ok
  end,
  {ok, State#{tls_msk := MSK, peap := MethodData#{state := tls_up}}};

%For wider compatiblity, enqueue the TLS records from ServerHello to
%ServerHelloDone, then send them in one batch. The spec says that we
%can send them spread across many messages, but many supplicants
%don't seem to like that very much.
%NOTE: OTP-19.0 (and presumably later) do this batching automatically.
handle({eradius_send_cyphertext, D}, State=#{current_method := peap
                                             ,do_tls_handshake_batching := Batching
                                             ,peap := MethodData=#{tls_state := server_hello_not_done
                                                                   ,peap_ver := PeapVer
                                                                   ,tls_queue := TlsQueue}}) ->
  Data= iolist_to_binary(D),
  NewQueue= <<TlsQueue/binary, Data/binary>>,
  <<22, _:4/bytes, MsgType:1/bytes, _/binary>> = Data,
  case Batching == false orelse MsgType == <<14>> of
    true ->
      case Batching of
        false -> ok;
        true -> lager:debug("PEAPv~p ServerHelloDone found. Tx backlog", [PeapVer])
      end,
      case handle({eradius_send_cyphertext, NewQueue},
                  State#{peap := MethodData#{tls_state := server_hello_sending
                                             ,tls_queue := <<>>}}) of
        {ok, Payload=#eradius_rad_handler_ret{}, NS} -> ok
      end,
      #{peap := MD2}=NS,
      {ok, Payload, NS#{peap := MD2#{tls_state := server_hello_done}}};
    _ ->
      lager:debug("PEAPv~p Enqueuing handshake type ~w", [PeapVer, MsgType]),
      {ok, State#{peap := MethodData#{tls_queue := NewQueue}}}
  end;
%Do the same queueing for ChangeCypher and Handshake with client.
%NOTE: OTP-19.0 (and presumably later) do this queueing automatically.
handle({eradius_send_cyphertext, D}, State=#{current_method := peap
                                             ,do_tls_handshake_batching := Batching
                                             ,peap := MethodData=#{tls_state := server_hello_done
                                                                   ,peap_ver := PeapVer
                                                                   ,tls_queue := TlsQueue}}) ->
  Data= iolist_to_binary(D),
  NewQueue= <<TlsQueue/binary, Data/binary>>,
  <<ContentType:1/bytes, _/binary>> = Data,
  case Batching == false orelse ContentType == <<22>> of
    true ->
      case Batching of
        false -> ok;
        true -> lager:debug("PEAPv~p ServerHandshake found. Tx backlog", [PeapVer])
      end,
      handle({eradius_send_cyphertext, NewQueue},
             State#{peap := MethodData#{tls_state := server_handshake_done
                                        ,tls_queue := <<>>}});
    _ ->
      lager:debug("PEAPv~p Enqueuing record type ~w", [PeapVer, ContentType]),
      {ok, State#{peap := MethodData#{tls_queue := NewQueue}}}
  end;

handle({eradius_send_cyphertext, D}, State=#{current_method := peap
                                            ,peap := #{peap_ver := PeapVer}}) ->
  #{tx_credits := Credits} = State,
  Data=iolist_to_binary(D),
  %FIXME: Make this not hard-coded!!
  EapMtu=1024,
  PktList=encode_packets(EapMtu, not_start, PeapVer, Data),
  {ok, NewState}=eradius_eap:enqueueWork(access_challenge, request, PktList, State),
  #{tx_queue := Q} = NewState,
  lager:debug("PEAPv~p Enqueued ~p bytes of cyphertext. Packet split into ~p parts. Work queue len: ~p Credits: ~p",
             [PeapVer, byte_size(Data), length(PktList), queue:len(Q), Credits]),
  case eradius_eap:transmitIfPossible(NewState) of
    {ok, Payload=#eradius_rad_handler_ret{}, SN} -> SN
  end,
  {ok, Payload, SN};

handle({ssl, SslSocket, SData}, State=#{current_method := peap
                                               ,tls_srv_pid := SrvPid
                                               ,last_rad := LastRad=#eradius_rad{attrs=RadAttrs}
                                               ,last_eap := LastEap=#eradius_eap{}
                                               ,peap := MethodState=
                                               #{peap_ver := PeapVer, state := PeapState
                                                ,success_attrs := SuccessAttrs
                                                ,failure_attrs := FailureAttrs}})
  when is_pid(SrvPid) ->
  case is_list(SData) of
    true ->
      lager:emergency("PEAPv~p WARNING Got SSL data as a LIST! Converting to binary. SSL Sock mode: ~p",
                      [PeapVer, ssl:getopts(SslSocket, [mode])]),
      SslData=binary:list_to_bin(SData);
    false ->
      SslData=SData
  end,
  lager:info("PEAPv~p Handling ~p bytes tunneled plaintext", [PeapVer, byte_size(SslData)]),
  {ok, InnerEap}=decodeTunneledMessage(SslData, LastEap, State),

  NewRadAttrs=RadAttrs#{eap_message := InnerEap},
  NewRad=LastRad#eradius_rad{attrs=NewRadAttrs},
  case eradius_eap:handle_rad_packet(NewRad, ?MODULE) of
    {ok, #eradius_rad_handler_ret{code=RadType, attrs=EapProcAttrs}} ->
      case RadType of
        access_challenge ->
          NewPS=PeapState,
          NewSA=SuccessAttrs,
          NewFA=FailureAttrs,
          WorkType=request;
        access_accept ->
          NewPS=inner_auth_success,
          NewSA=maps:remove(eap_message, EapProcAttrs),
          NewFA=FailureAttrs,
          WorkType=success;
        access_reject ->
          NewPS=inner_auth_failure,
          NewSA=SuccessAttrs,
          NewFA=maps:remove(eap_mssage, EapProcAttrs),
          WorkType=failure
      end,
      #{eap_message := EapPayload}=EapProcAttrs,
      {ok, TlsPacket}=prepareWork(WorkType, EapPayload, State),
      ok=eradius_peap_tls_srv:send(SrvPid, TlsPacket),
      NewState=State#{peap := MethodState#{state := NewPS, success_attrs := NewSA
                                           ,failure_attrs := NewFA}},
      {ok, NewState}
  end.

%So, we COULD do TLS renegotiate if we were doing certificate-based
%authentication. The renegotiation would technically still be a
%part of PEAP Phase 1.
%However, we're not going to be doing that for now, so we're
%going to move on to Phase 2. What's that? It's a second round of
%EAP conversation that proceedes exactly like the first, except
%entirely within the TLS tunnel.
%PEAPv0
sendTlsIdentityRequest(#{tls_srv_pid := SrvPid, peap := #{peap_ver := 0}}) ->
  Msg= <<1>>,
  ok=eradius_peap_tls_srv:send(SrvPid, Msg);
%PEAPv1
sendTlsIdentityRequest(#{tls_srv_pid := SrvPid, peap := #{peap_ver := 1}}) ->
  [Msg]=eradius_eap:encodeEapMessage(request, rand:uniform(100), <<1>>),
  ok=eradius_peap_tls_srv:send(SrvPid, Msg).

decodeTunneledMessage(<<Type, Data/binary>> =Message, #eradius_eap{code=Code, id=Id}, #{peap := #{peap_ver := 0}}) ->
  FakeLen=byte_size(Message)+4,
  case Code of
    request  -> C=1;
    response -> C=2;
    success  -> C=3;
    failure  -> C=4
  end,
  Ret = <<C, Id, FakeLen:16, Type, Data/binary>>,
  {ok, Ret};
decodeTunneledMessage(Message, _, #{peap := #{peap_ver := 1}}) ->
  {ok, Message}.

%FIXME: Support fragmented EAP payloads!
prepareWork(Type, [<<_, Id, _/binary>>], #{peap := #{peap_ver := 0}}) when
    Type == success orelse Type == failure ->
  %Code (1) (request)
  %ID (pulled from EAP packet)
  %Length of whole packet (two bytes)
  %Type (33)
  %1:1, 0:1 (is-mandatory flag, followed by reserved bit)
  %3:14 (Acknowledged result) (the only valid value for this field)
  %2:16 (Length of following value field, in bytes)
  %followed by either
  %1:16 (PEAPv0 success)
  %or
  %2:16 (PEAPv0 failure)
  case Type of
    success -> Value=1;
    failure -> Value=2
  end,
  D= <<1, Id, 11:16, 33, 1:1, 0:1, 3:14, 2:16, Value:16>>,
  11=byte_size(D),
  {ok, D};
%FIXME: Support fragmented EAP payloads!
prepareWork(request, [<<_:4/bytes, Data/binary>>], #{peap := #{peap_ver := 0}}) ->
  %PEAPv0 doesn't wrap things in EAP unless they're
  %success or failure packets.
  {ok, Data};
prepareWork(_, Payload, #{peap := #{peap_ver := 1}}) ->
  {ok, Payload}.

%Here are the rules:
% Flags:
% Len Included, More Frags, PEAP Start, Reserved (2 bits of 0)
% Version number:
% Reserved (1 bit of 0), Version number (2 bits).
%
% Len Included is set to 1 only in the FIRST message of a set.
%     If it is set to 1, then there is a FOUR BYTE TLS Length field
%     whose value is the length in bytes of the TLS data contained across
%     all of the packets in the message.
%     Len Included is set to 1 (and TLS len included) in the FIRST message
%     of a set regardless if there is more than one message in the set!!!
% More Fragments is set to 1 in EVERY message of a set except for the last
%     one, IF the TLS Length field and the TLS data sent is larger than can
%     fit in a single packet. More Fragments is NOT SET for the FINAL packet
%     in a set.
%     If the data fits in one packet, MF is not set.
% PEAP Start is set on a PEAP Start message. I don't know if it is set for
%     EVERY packet in that message, because I have no examples of a PEAP Start
%     message that spans multiple packets.

%If our data can fit in one packet, don't include TLS length.
%PEAP length-excluded header is 2 bytes.
encode_packets(EapMtu, IsStart, Version, Data)
  when is_atom(IsStart) andalso byte_size(Data) =< EapMtu-2 ->
  LenIncluded=0,
  MoreFrags=0,
  case IsStart of
    start -> Start=1;
    _ -> Start=0
  end,
  [<<25, LenIncluded:1, MoreFrags:1, Start:1, 0:3, Version:2, Data/binary>>];
%Otherwise, fragment the packet.
%PEAP length-included header is 6 bytes.
encode_packets(EapMtu, IsStart, Version, Data)
  when is_atom(IsStart) ->
  DSize=EapMtu-6,
  <<D:DSize/bytes, Rest/binary>> = Data,
  LenIncluded=1,
  MoreFrags=1,
  case IsStart of
    start -> Start=1;
    _ -> Start=0
  end,
  Elem=[<<25, LenIncluded:1, MoreFrags:1, Start:1, 0:3, Version:2, (byte_size(Data)):32, D/binary>>],
  lists:reverse(encode_packets(EapMtu, Start, Version, Rest, Elem)).
encode_packets(_, _, _, <<>>, Acc) ->
  Acc;
%Subsequent EAP messages don't include the length.
encode_packets(EapMtu, Start, Version, Data, Acc)
  when byte_size(Data) >= EapMtu-2 ->
  DSize=EapMtu-2,
  <<D:DSize/bytes, Rest/binary>> = Data,
  LenIncluded=0,
  MoreFrags=1,
  Elem=[<<25, LenIncluded:1, MoreFrags:1, Start:1, 0:3, Version:2, D/binary>>],
  encode_packets(EapMtu, Start, Version, Rest, Elem ++ Acc);
encode_packets(_, Start, Version, Data, Acc) ->
  LenIncluded=0,
  MoreFrags=0,
  Elem=[<<25, LenIncluded:1, MoreFrags:1, Start:1, 0:3, Version:2, Data/binary>>],
  Elem ++ Acc.

