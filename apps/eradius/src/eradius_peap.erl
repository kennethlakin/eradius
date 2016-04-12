-module(eradius_peap).

-compile([{parse_transform, lager_transform}]).
-export([handle/2]).

handle({handle, {_, Id, _, _Type, TypeData},
    {Ip, _, _, _, _, RadState}},
    State=#{peap := MethodData=#{state := MethodState}, tx_credits := Credits}) ->
  case MethodState of
    undefined ->
      lager:info("In PEAP startup! Sending PEAP Start!"),
      %PEAP Start Flag:
      StartFlag = <<0:1, 0:1, 1:1, 0:3>>,
      Version=1,
      Data = <<25, StartFlag/bitstring,  Version:2>>,
      NS=State#{peap := MethodData#{state := start_sent}},
      {enqueue_and_send, {access_challenge, request, Data}, NS};
    start_sent ->
      %FIXME: Actually validate the TLS data
      <<LenIncluded:1, _:7, _/binary>> = TypeData,
      case LenIncluded of
        0 ->
          _TLSLen=undefined,
          <<_:1, _MoreFrags:1, _Start:1, 0:3, PeapVer:2, Data/binary>> = TypeData;
        1 ->
          <<_:1, _MoreFrags:1, _Start:1, 0:3, PeapVer:2, _TLSLen:4/bytes, Data/binary>> = TypeData
      end,
      lager:info("Got a reply back from our start packet! It's probably a TLS start!"),
      {TlsSrvPid, NewState}=
        case maps:get(tls_srv_pid, State) of
          undefined ->
            lager:info("No TLS server helper. Starting one!"),
            {ok, P}=radius_worker:start(eradius_peap_tls_srv, self()),
            link(P),
            {P, State#{tls_srv_pid := P}};
          P ->
            lager:info("TLS server helper running. Using ~p", [P]),
            {P, State}
        end,
      lager:info("Peer wants PEAPv~p", [PeapVer]),
      ok=eradius_peap_tls_srv:start_tls(TlsSrvPid, Ip, RadState, Data),
      lager:info("start_tls kicked off. Returning."),
      {send_queued, NewState#{peap := MethodData#{state := tls_not_up
                                                  ,peap_ver => PeapVer
                                                  ,tls_state => server_hello_not_done
                                                  ,tls_queue => <<>>}}};
    tls_not_up ->
      %FIXME: Actually validate the TLS data (PEAP version included.)
      #{peap_ver := PeapVer}=MethodData,
      case TypeData of
        <<0:6, PeapVer:2>> ->
          lager:info("Oh cool! A request for more info! Sending more!"),
          {send_queued, State};
        <<LenIncluded:1, MoreFrags:1, Start:1, 0:3, _PeapVer:2, _/binary>> ->
          case LenIncluded of
            1 -> 
              <<LenIncluded:1, MoreFrags:1, Start:1, 0:3, _PeapVer:2, _TLSLen:4/bytes, Data/binary>> = TypeData;
            0 ->
              _TLSLen=undefined,
              <<LenIncluded:1, MoreFrags:1, Start:1, 0:3, _PeapVer:2, Data/binary>> = TypeData
          end,
          lager:info("More TLS negotiation"),
          #{tls_srv_pid := SrvPid} = State,
          eradius_peap_tls_srv:handlePacket(SrvPid, Ip, Data),
          {send_queued, State}
      end;
    tls_up ->
      lager:info("Got PEAP data prompt after TLS up"),
      true=eap:txQueueIsEmpty(State),
      ok=sendTlsIdentityRequest(Id, State),
      {send_queued, State#{peap := MethodData#{state := inner_ident_sent}}};
    inner_ident_sent ->
      %FIXME: Actually validate the TLS data (PEAP version included.)
      #{peap_ver := PeapVer}=MethodData,
      <<LenIncluded:1, _:7, _/binary>> = TypeData,
      case LenIncluded of
        1 -> <<LenIncluded:1, _MoreFrags:1, _Start:1, 0:3, PeapVer:2, _TLSLen:4/bytes, Data/binary>> = TypeData;
        0 ->
          _TLSLen=undefined,
          <<LenIncluded:1, _MoreFrags:1, _Start:1, 0:3, PeapVer:2, Data/binary>> = TypeData
      end,
      lager:info("More TLS cyphertext Current credits ~p Work len ~p", [Credits, queue:len(maps:get(tx_queue, State)) ]),
      SrvPid=maps:get(tls_srv_pid, State),
      eradius_peap_tls_srv:handlePacket(SrvPid, Ip, Data),
      {send_queued, State};
    inner_auth_success ->
      lager:info("Got PEAP prompt for more data after inner auth complete! Sending success!"),
      true=eap:txQueueIsEmpty(State),
      %FIXME: ACTUALLY! because we are doing MSCHAPv2, we should send
      %       a MS-MPPE-Recv-Key   and   MS-MPPE-Send-Key
      %       attribute with this access_accept.
      %FIXME: This means that we have to change our work queue data
      %       storage from {RadType, EapCode, EapMessages} to
      %       {RadType, EapCode, EapMessages, AddlRadAttributes}
      %       AddlRadAttributes will be a map, so that we can MERGE THE
      %       MAP with the existing Attrs map, and then rely on the
      %       Radius attrs encoding code to do the right thing.
      %   BUT. For now, we can detect if we're being passed an
      %   ACCEPT/SUCCESS packet with 0 EAP messages and just insert the
      %   data there... just to test the feasibility.
      {auth_ok, {access_accept, success, <<>>}, State}
  end;
handle({tls_up, RadState}, State=#{current_method := peap
                                        ,last_rad := {_,_,_,_,_,RS}
                                        ,tls_msk := undefined
                                        ,tls_srv_pid := SrvPid
                                        ,peap := MethodData})
  when RS == RadState ->
  % So, PEAP, section 2.8. Key derivation:
  %   This is how we'll do it on the server side:
  % FirstPRF =ssl:prf(SSLSock, master_secret, "client PEAP encryption", [client_random, server_random], 128),
  % SecondPRF=ssl:prf(SSLSock, <<"">>, "client PEAP encryption", [client_random, server_random], 64),
  %   and then we continue as per the RFC.
  %
  % Okay.... So, PEAPv0 uses "client EAP encryption" as the string.
  %              PEAPv1 uses "client PEAP encryption" as the string.
  %          However... the documentation for wpa_supplicant.conf indicates
  %          that many RADIUS servers work in PEAPv1 mode with
  %          "client EAP encryption" as the string. In fact, using the
  %          PEAPv0 string in PEAPv1 mode is the *DEFAULT* wpa_supplicant
  %          configuration. So, keep this in mind. Becase we cannot *detect* a
  %          keying mismatch, it might be safest to just use "client EAP encryption".
  %          See:
  %          https://w1.fi/cgit/hostap/plain/wpa_supplicant/wpa_supplicant.conf
  %          for more info! This
  %          https://w1.fi/cgit/hostap/plain/wpa_supplicant/eap_testing.txt
  %          might also be of interest.
  lager:info("****TLS UP!**** Credits: ~p Work queue ~p ", [maps:get(tx_credits, State), queue:len(maps:get(tx_queue, State))]),
  PEAPLabel= <<"client EAP encryption">>,
  {ok, <<MSK:64/bytes, _:64/bytes>>}=eradius_peap_tls_srv:run_prf(SrvPid, master_secret, PEAPLabel,
                                                                  [client_random, server_random], 128),
  {ok, <<MSK:64/bytes>>}=eradius_peap_tls_srv:run_prf(SrvPid, master_secret, PEAPLabel,
                                                                  [client_random, server_random], 64),
  %FIXME: wpa_supplicant disagrees with us about the result of running the PRF
  %       with the Master Secret as the secret, the above string as the label,
  %       and the client random concatted with the server random.
  %       So... not sure what's going on here. We can SEND and RECIEVE
  %       encrypted data just fine! So, it's not like stuff's TOTALLY broken!
  %       *grump*. Fix this after re-architecting the rest of the program to be
  %       presentable. The only thing left to do to make PEAPv1/MSCHAPv2 work
  %       for wpa_supplicant is to figure out this mystery... MPPE keys won't
  %       get distributed if we can't agree on the output of our PRF!!!
  %       FIXME: Maybe try the latest Erlang?
  %       FIXME: No. Just tried 18.3 on a 64-bit machine. I get the same
  %              problems; disagreement with PRF output and TLSv1.0
  %              communications failure.
  %       FIXME: Okay. The problem is with the TLS 1.1 and 1.2 PRF.
  %              TLS 1.0 works just fine. Not clear if this is an issue w/
  %              wpa_supplicant or with Erlang SSL.
  lager:info("MSK is ~p", [radius_server:bin_to_hex(MSK)]),
  {ok, State#{tls_msk := MSK, peap := MethodData#{state := tls_up}}};

%For wider compatiblity, enqueue the TLS records from ServerHello to
%ServerHelloDone, then send them in one batch. The spec says that we
%can send them spread across many messages, but many supplicants
%don't seem to like that very much.
handle({eradius_send_cyphertext, D}, State=#{current_method := peap
                                             ,peap := MethodData=#{tls_state := server_hello_not_done
                                                                  ,tls_queue := TlsQueue}}) ->
  Data= iolist_to_binary(D),
  NewQueue= <<TlsQueue/binary, Data/binary>>,
  <<22, _:4/bytes, MsgType:1/bytes, _/binary>> = Data,
  case MsgType of
    <<14>> ->
      lager:info("********Got ServerHelloDone. Sending backlog."),
      {Ret, NS}=handle({eradius_send_cyphertext, NewQueue},
                       State#{peap := MethodData#{tls_state := server_hello_sending
                                                  ,tls_queue := <<>>}}),
      #{peap := MD2}=NS,
      {Ret, NS#{peap := MD2#{tls_state := server_hello_done}}};
    _ ->
      lager:info("********Enqueuing. Waiting on ServerHelloDone."),
      {ok, State#{peap := MethodData#{tls_queue := NewQueue}}}
  end;
%Do the same queueing for ChangeCypher and Handshake with client.
%FIXME: This queueing is probably fragile and may break if we do
%       certificate authentication or anything else we haven't tried yet.
%       Double-check the TLS docs.
handle({eradius_send_cyphertext, D}, State=#{current_method := peap
                                             ,peap := MethodData=#{tls_state := server_hello_done
                                                                  ,tls_queue := TlsQueue}}) ->
  Data= iolist_to_binary(D),
  NewQueue= <<TlsQueue/binary, Data/binary>>,
  <<ContentType:1/bytes, _/binary>> = Data,
  case ContentType of
    <<22>> ->
      lager:info("********Got ServerHandshake. Sending backlog."),
      handle({eradius_send_cyphertext, NewQueue},
             State#{peap := MethodData#{tls_state := server_handshake_done
                                        ,tls_queue := <<>>}});
    _ ->
      lager:info("********Enqueuing. Waiting on ServerHandshake."),
      {ok, State#{peap := MethodData#{tls_queue := NewQueue}}}
  end;

handle({eradius_send_cyphertext, D}, State=#{current_method := peap
                                            ,peap := #{peap_ver := PEAPVersion}}) ->
  #{tx_credits := Credits} = State,
  Data=iolist_to_binary(D),
  %FIXME: Make this not hard-coded!!
  EapMtu=1024,
  PktList=encode_packets(EapMtu, not_start, PEAPVersion, Data),
  {ok, NewState}=eap:enqueueWork(access_challenge, request, PktList, State),
  #{tx_queue := Q} = NewState,
  lager:info("enqueued ~p bytes of cyphertext. Packet split into ~p parts. Work queue len: ~p Credits: ~p",
             [byte_size(Data), length(PktList), queue:len(Q), Credits]),
  %FIXME: Do NOT add a tx_credit here. This packet was sent internally, not
  %       from the peer.
  case eap:transmitIfPossible(NewState) of
    {ok, no_credits, SN} -> SN;
    {ok, SN} -> SN
  end,
  NQ=maps:get(tx_queue, SN),
  NC=maps:get(tx_credits, SN),
  lager:info("Cyphertext \"send\" done. Queue ~p Credits ~p", [queue:len(NQ), NC]),
  {ok, SN};

handle({ssl, _SslSocket, SslData}, State=#{current_method := peap
                                               ,tls_srv_pid := SrvPid
                                               ,last_rad := LastRad
                                               ,last_eap := LastEap={_, Id, _,_,_}
                                               ,peap := MethodState})
  when is_pid(SrvPid) ->
  %FIXME: we really need to track the EAP IDs for the
  %inner and outer conversations separately.
  {ok, DecodedMessage={_,Id,_,_,_}}=decodeTunneledMessage(SslData, LastEap, State),

  NewState=
    case maps:is_key(mschapv2, State) of
      false -> State#{mschapv2 => eap:getNewMethodData()};
      true -> State
    end,

    case eap:mschapv2({handle, DecodedMessage, LastRad}, NewState) of
    %If we get an ignore, we probably should signal an error.
    %{ignore, S} -> {reply, {warn, ignored}, starting, S};
    %{ignore, bad_packet, S} -> {reply, {warn, bad_packet}, starting, S};
    %{send_queued, S=#{tx_credits := Credits}} ->
    %  case transmitIfPossible(S#{tx_credits := Credits+1}) of
    %    {ok, NS} -> {reply, ok, running, NS};
    %    {ok, no_work, NS} -> {reply, ok, running, NS}
    %  end;
    %{send_handled, NS} -> {reply, ok, NS};
    {enqueue_and_send, {_, request, Packets}, S} ->
      {ok, D}=prepareWork(request, Id, Packets, S),
      ok=eradius_peap_tls_srv:send(SrvPid, D),
      {ok, S};
    {enqueue_and_send, {_, success, Packets}, S} ->
      {ok, D}=prepareWork(success, Id, Packets, S),
      ok=eradius_peap_tls_srv:send(SrvPid, D),
      {ok, S};
    {auth_ok, {_, success, Packets}, S} ->
      {ok, D}=prepareWork(success, Id, Packets, S),
      ok=eradius_peap_tls_srv:send(SrvPid, D),
      {ok, S#{peap := MethodState#{state := inner_auth_success}}};
    {auth_fail, {_, failure, Packets}, S} ->
      {ok, D}=prepareWork(failure, Id, Packets, S),
      ok=eradius_peap_tls_srv:send(SrvPid, D),
      {ok, S#{peap := MethodState#{state := inner_auth_failure}}}
  end.

%So, we COULD TLS renegotiate if we were doing certificate-based
%authentication. The renegotiation would technically still be a
%part of PEAP Phase 1.
%However, we're not going to be doing that for now, so we're
%going to move on to Phase 2. What's that? It's a second round of
%EAP conversation that proceedes exactly like the first, except
%entirely within the TLS tunnel.
%PEAPv0
sendTlsIdentityRequest(_, #{tls_srv_pid := SrvPid
                             ,peap := #{peap_ver := 0}}) ->
  lager:info("Sending TLS identity request."),
  Msg= <<1>>,
  ok=eradius_peap_tls_srv:send(SrvPid, Msg);
%PEAPv1
sendTlsIdentityRequest(Id, #{tls_srv_pid := SrvPid
                             ,peap := #{peap_ver := 1}}) ->
  %Ordinarily we would need to increment the EAP ID here.
  %But! We are establishing a new EAP session, and to keep the IDs in
  %THAT session in sync with the IDs in the PEAP session, we start
  %from the ID of the outer session.
  %
  %Although, the IDs between the two EAP conversations could drift
  %out of sync. So, FIXME: we really need to track the EAP IDs for the
  %inner and outer conversations separately.
  lager:info("Sending TLS identity request."),
  [Msg]=eap:encodeEapMessage(request, Id, <<1>>),
  ok=eradius_peap_tls_srv:send(SrvPid, Msg).

decodeTunneledMessage(Message, {Code,Id,_,_,_}, #{peap := #{peap_ver := 0}}) ->
  FakeLen=byte_size(Message)+4,
  case Message of
    <<26, Data/binary>> -> DecodedMessage={Code, Id, FakeLen, mschapv2, Data};
    <<1, Data/binary>> -> DecodedMessage={Code, Id, FakeLen, identity, Data}
    %<<1, _:1/bytes, _:2/bytes, 33, _/binary>> (FIXME: Possible EAP Extension packet)
  end,
  {ok, DecodedMessage};
decodeTunneledMessage(Message, {_,Id,_,_,_}, #{peap := #{peap_ver := 1}}) ->
  %FIXME: we really need to track the EAP IDs for the
  %inner and outer conversations separately.
  {ok, {_,Id,_,_,_}}=eap:decodeMessage(Message).

%FIXME: It's janky to be hard-coding EAP Extension success and failure packets,
%       but this works for now.
prepareWork(success, Id, <<>>, #{peap := #{peap_ver := 0}}) ->
  D= <<1, Id/binary, 11:16, 33, 1:1, 0:1, 3:14, 2:16, 1:16>>,
  11=byte_size(D),
  {ok, D};
prepareWork(failure, Id, <<>>, #{peap := #{peap_ver := 0}}) ->
  D= <<1, Id/binary, 11:16, 33, 1:1, 0:1, 3:14, 2:16, 2:16>>,
  11=byte_size(D),
  {ok, D};
prepareWork(request, _, Data, #{peap := #{peap_ver := 0}}) ->
  {ok, Data};
prepareWork(Type, Id, Data, #{peap := #{peap_ver := 1}}) ->
  {ok, [_]}=eap:prepareWork(Type, Id, Data).

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

