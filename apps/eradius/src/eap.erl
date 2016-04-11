-module(eap).

-compile([{parse_transform, lager_transform}]).
-compile(export_all).

-behavior(gen_fsm).

%This is plaintext that was decrypted by the TLS code.
handle_tls_data(FSMPid, Msg={ssl, _Sock, _Data}) ->
  gen_fsm:send_event(FSMPid, Msg).

%Used by the peap_tls_srv to get us to send cyphertext that came out of the SSL
%machinery to the RADIUS peer.
send_cyphertext(FSMPid, Msg={eradius_send_cyphertext, _Data}) ->
  gen_fsm:send_event(FSMPid, Msg).

tls_up(FSMPid, Msg={tls_up, _RadState}) ->
  gen_fsm:send_event(FSMPid, Msg).

handlePacket(RadData={Ip, _Port, _Auth, _RadId, _Data, RadState}, #{eap_message := {EM, _}, message_authenticator := _}) ->
  lager:info("Got packet. State data ~p", [RadState]),
  Message=concatMessage(EM),
  case decodeMessage(Message) of
    {ok, DecodedMessage={_, Id, _, _, _}} ->
      lager:info("Eap decode message says pkt is okay."),
      FSMPid =
        case radius_server:getWorkEntry(?MODULE, {Id, RadState, Ip}) of
          {ok, {FsmPid, working}} ->
            lager:info("~p is working on this. Dropping.", [FsmPid]),
            drop;
          {ok, {FsmPid, crashed}} ->
            %FIXME: What do do in this case?
            lager:info("~p was working on this but crashed. Odd.", [FsmPid]),
            drop;
          {ok, {FsmPid, waiting}} ->
            lager:info("~p has this convo and is waiting. Using it.", [FsmPid]),
            FsmPid;
          {error, work_entry_not_found} ->
            lager:info("Starting fsm because no workers for this convo exist."),
            {ok, FsmPid}=radius_worker:start(?MODULE, [DecodedMessage, RadData]),
            FsmPid
        end,
      case FSMPid of
        drop -> ok;
        _ ->
          Ret=gen_fsm:sync_send_event(FsmPid, {handle, DecodedMessage, RadData}, infinity),
          case Ret of
            ok -> ok;
            _ -> lager:info("Handler returned non-ok: ~p", [Ret])
          end
      end;
    {discard, packet_too_short} ->
      lager:warning("EAP: Packet too short!")
  end.

decodeMessage(P = <<Code:1/bytes, ID:1/bytes, L:2/bytes, Type:1/bytes, _/binary>>) ->
  Len=binary:decode_unsigned(L),
  case byte_size(P) < Len of
    true -> {discard, packet_too_short};
    false ->
      HeaderLen=5,
      TDLen=Len-HeaderLen,
      %Trim padding from TypeData.
      TypeData=binary:part(P, HeaderLen, TDLen),
      %FIXME: A non-response packet in an Access-Request is illegal. We're not acting as
      %       a proxy so, we should probably return {reject, non_response_message}
      %       if Code is not <<2>> . (and modify the radius_worker to do the
      %       right thing if it gets a reject).
      C=
        case Code of
          <<1>> -> request;
          <<2>> -> response;
          <<3>> -> success;
          <<4>> -> failure;
          _ -> {discard, invalid_code}
        end,
      T=decodeEapAuthType(Type),
      {ok, {C, ID, L, T, TypeData}}
  end.

getNewState(Id, RadState, Ip) ->
  #{ work_key => {Id, RadState, Ip}
     %FIXME: Make this configurable!
     ,default_method => md5
     %FIXME: Make this configurable!
     ,supported_methods => [peap, mschapv2, md5]
     ,current_method => undefined
     ,last_rad => undefined
     ,last_eap => undefined
     %Used when we have more EAP data to send than will fit in a single
     %message.
     ,tx_queue => queue:new()
     %Used to determine when we can send another item of EAP data.
     ,tx_credits => 0
     ,tls_srv_pid => undefined
     ,tls_msk => undefined
     %   mmm. EAP-TTLS says "multiple tunneled authentications may be
     %   performed." It gives as example: Once TTLS tunnel is established, it
     %   can be used to start an ENTIRELY NEW EAP SESSION. So, that would
     %   imply firing up a *second* EAP FSM. PEAP(v2) Also supports this:
     %   "[A]fter the TLS session is established another complete EAP negotiation
     %   will occur..."
     %   We... will not be supporting the establishment of a *second* tunnel
     %   within the first tunneled method, I think. At least, not at first.
     %
     %   NOW, related to that, EAP-TTLS (AND PEAPv2) *also* supports *chaining* EAP
     %   Authentications. So, you can *require* the user to auth with like GTC,
     %   then MSCHAPv2, or maybe something else if one of those two fails. The
     %   rules can get arbitrarily complex, really. So, we have both *nested*
     %   EAP FSMs and we have *chained* EAP FSMs.
     %
     %   Let's work on supporting *chained* methods for now.
     %   Just consider them a series of "inner" methods. (But read PEAPv2
     %    (doc #10) section 2.2.2!)
     %,username => undefined
     %,user_pass => undefined
     %FIXME: Look these up (or pass in) rather than hard-coding them.
     ,username => <<"user">>
     ,user_pass => <<"pass">>
   }.

%Also used to reset an EAP method's data.
getNewMethodData() ->
  #{ username => undefined
     ,user_pass => undefined
     ,state => undefined}.

start_worker(Args) ->
  lager:info("EAP Worker starting with args ~p", [Args]),
  gen_fsm:start_link(?MODULE, Args, []).

init([{_, Id, _, _, _}, {Ip, _Port, _Auth, _RadId, _Data, RadState}]) ->
  %Register self, using the provided data.
  %Should register self in 'working' status, so that we don't have a race
  ok=radius_server:insertWorkEntry(?MODULE, {Id, RadState, Ip}, working, self()),
  process_flag(trap_exit, true),
  State=getNewState(Id, RadState, Ip),
  {ok, starting, State}.

starting({handle, {response, _, _, nak, _}, _}, From, State) ->
  %FIXME: We probably shouldn't stop, but should rather ignore the packet.
  lager:info("Spurious NAK in startup."),
  gen_fsm:reply(From, {error, spurious_nak}),
  {stop, normal, State};
%FIXME: Handle both EAP-Start (reply with identity request)
%       and skip-right-to-the-EAP-method (just start running the method)
%       methods of starting the EAP conversation, too!
starting(Msg={handle,
                      Eap={response, Id, _, EapType, EapTypeData},
                      Rad={Ip, _Port, _Auth, _RadId, _Data, RadState}},
          From, State=#{tx_credits := Credits})
  when Credits == 0 ->
  ok=radius_server:updateWorkEntry(?MODULE, {Id, RadState, Ip}, working, self()),
  Continue =
    case EapType of
      identity -> proceed;
      _ -> drop
    end,
  case Continue of
    drop ->
      lager:info("Got a non-identity, non-NAK packet on startup! Stopping!"),
      %FIXME: We probably shouldn't stop, but should rather ignore the packet.
      gen_fsm:reply(From, {error, spurious_non_ident}),
      {stop, normal, State};
    proceed ->
      Username=EapTypeData,
      DefaultMethod=maps:get(default_method, State),
      NewState=State#{username := Username, current_method := DefaultMethod
                     ,DefaultMethod => getNewMethodData()},
      %Offer our default auth method
      DMFun=fun ?MODULE:DefaultMethod/2,
      handleOuterPacket(From, DMFun, [Msg, NewState])
  end.

running(Msg={handle, {response, Id, _, nak, BinMethods},
                      {Ip, _, _, _, _, RadState}},
          From,
          State=#{supported_methods := SupportedMethods, current_method := OldCurrentMethod
                  ,tx_credits := Credits})
  when Credits == 0 ->
  ok=radius_server:updateWorkEntry(?MODULE, {Id, RadState, Ip}, working, self()),
  %FIXME: This only works for methods with non-expanded types.
  SuggestedMethods =
    case decodeEapAuthType(BinMethods) of
      M when is_list(M) -> M;
      R -> [R]
    end,
  lager:info("Suggested methods: ~p", [SuggestedMethods]),
  NewState=maps:remove(OldCurrentMethod, State),
  case findFirstCompatible(SuggestedMethods, SupportedMethods) of
    {error, none_compatible} ->
      {ok, NextState}=enqueueAndMaybeTransmit(access_reject, failure, <<>>, NewState#{tx_credits := Credits+1}),
      gen_fsm:reply(From, ok),
      {stop, normal, NextState};
    {ok, Method} ->
      lager:info("Best Valid method! ~p", [Method]),

      NextState=NewState#{current_method := Method, Method => getNewMethodData()},
      Fun=fun handleMethod/3,
      Args=[Method, Msg, NextState],
      handleOuterPacket(From, Fun, Args)
  end;
running(Msg={handle,
                      {response, Id, _, EapType, _EapTypeData},
                      {Ip, _, _, _, _, RadState}},
          From, State=#{current_method := EapType, tx_credits := Credits})
  when Credits == 0 ->
  ok=radius_server:updateWorkEntry(?MODULE, {Id, RadState, Ip}, working, self()),
  handleOuterPacket(From, fun handleMethod/2, [Msg, State]).

handleOuterPacket(From, Fun, Args) ->
  case apply(Fun, Args) of
    {ignore, S} -> {reply, {warn, ignored}, starting, S};
    {ignore, bad_packet, S} -> {reply, {warn, bad_packet}, starting, S};
    {send_queued, S=#{tx_credits := Credits}} ->
      case transmitIfPossible(S#{tx_credits := Credits+1}) of
        {ok, NS} -> {reply, ok, running, NS};
        {ok, no_work, NS} -> {reply, ok, running, NS}
      end;
    %We probably should not see send_handled in a non-tunneled method.
    %{send_handled, NS} -> {reply, ok, NS};
    {enqueue_and_send, {RType, EType, Packets}, S=#{tx_credits := Credits}} ->
      NS=S#{tx_credits := Credits+1},
      case enqueueAndMaybeTransmit(RType, EType, Packets,
                                   NS) of
        {ok, FS} ->
          {reply, ok, running, FS}
      end;
    {auth_ok, {RType, EType, Packets}, S=#{tx_credits := Credits}} ->
      NS=S#{tx_credits := Credits+1},
      case enqueueAndMaybeTransmit(RType, EType, Packets, NS) of
        {ok, FS} ->
          %If we're going to shut down, our tx queue better be empty.
          true=txQueueIsEmpty(FS),
          gen_fsm:reply(From, ok),
          {stop, normal, FS}
      end;
    {auth_fail, {RType, EType, Packets}, S=#{tx_credits := Credits}} ->
      NS=S#{tx_credits := Credits+1},
      case enqueueAndMaybeTransmit(RType, EType, Packets, NS) of
        {ok, FS} ->
          true=txQueueIsEmpty(FS),
          gen_fsm:reply(From, ok),
          {stop, normal, FS}
      end
  end.

running(Msg={tls_up, _}, State=#{current_method := CurrMethod})
  when CurrMethod /= undefined ->
  %FIXME: Add a "lookup handler based on Method Name" function.
  Fun=fun ?MODULE:CurrMethod/2,
  {ok, NS}=Fun(Msg, State),
  {next_state, running, NS};
running(Msg={eradius_send_cyphertext, _}, State=#{current_method := CurrMethod})
  when CurrMethod /= undefined ->
  Fun=fun ?MODULE:CurrMethod/2,
  {ok, NS}=Fun(Msg, State),
  {next_state, running, NS};
running(Msg={ssl, _, _}, State=#{current_method := CurrMethod})
  when CurrMethod /= undefined ->
  Fun=fun ?MODULE:CurrMethod/2,
  {ok, NS}=Fun(Msg, State),
  {next_state, running, NS}.

handleMethod(TypeOverride, {Task, {C, I, L, _, TD}, Rad}, State) ->
  handleMethod({Task, {C,I,L,TypeOverride,TD}, Rad}, State).
handleMethod(Msg={Task, Eap={_Code, _Id, _L, Type, TypeData},
             Rad={_Ip, _Port, _Auth, _RadId, _RadData, _RadState}}, State) ->
  NewState=State#{last_rad := Rad, last_eap := Eap},
  case Type of
    identity ->
      DefaultMethod=maps:get(default_method, NewState),
      %Offer our default auth method
      DMFun=fun ?MODULE:DefaultMethod/2,
      DMFun(Msg, NewState);
    md5 ->
      md5(Msg, NewState);
    mschapv2->
      mschapv2(Msg, NewState);
    peap ->
      peap(Msg, NewState);
    _ ->
      %FIXME: We should probably send back an EAP Failure if we reach here.
      %       (rather than dropping the packet.)
      lager:warning("Method ~p not handled. Ignoring packet.", [Type]),
      {done, NewState}
  end.

%@returns (just like all other method handlers)
% {ignore, State} | {ignore, bad_packet, State} | {send_queued, State}
% | {send_handled, State}
% | {enqueue_and_send, {Radius_type, EapType, PacketList}, State}
% | {auth_okay, {Radius_type, EapType, PacketList}, State}
% | {auth_fail, {Radius_type, EapType, PacketList}, State}
md5({handle, Eap={_, Id, _, _Type, TypeData},
    Rad={_, _, _, _, _, _}},
    PassedState=#{tx_credits := Credits,
                  md5 := MethodData=#{ state := MethodState }})
  when Credits == 0 ->
  State=PassedState#{last_rad := Rad, last_eap := Eap},
  case MethodState of
    undefined ->
      %FIXME: RFC5281, sec 11.1 has something odd to say about Challenge
      %       generation. I *think* that doing things the way we do here
      %       alleviates the concern expressed. No. Section 11.2.2 and
      %       subsequent sections *alter* how these random bytes are selected.
      %       Yay... :/ So we do have to have TTLS-specific code in here. Yay.
      Challenge=crypto:strong_rand_bytes(16),
      ChallengeLen=binary:encode_unsigned(byte_size(Challenge)),
      Data= <<4,ChallengeLen/binary,Challenge/binary>>,
      Pkt={access_challenge, request, Data},
      NewState=State#{md5 := MethodData#{state => {challenge_sent, Challenge}}},
      {enqueue_and_send, Pkt, NewState};
    {challenge_sent, Challenge} ->
      Pass=maps:get(user_pass, State),
      CalculatedChallenge=crypto:hash(md5, <<Id/binary, Pass/binary, Challenge/binary>>),
      <<_:1/bytes, ReceivedChallenge/binary>> = TypeData,
      case CalculatedChallenge == ReceivedChallenge of
        true -> {auth_ok, {access_accept, success, <<>>}, State};
        false -> {auth_fail, {access_reject, failure, <<>>}, State}
      end
  end.

mschapv2(Msg, State) ->
  eradius_mschap:handle(Msg, State).

peap(Msg, State) ->
  eradius_peap:handle(Msg, State).

sendEapMessage(RadType, Type, Id, RadData, State) when Type == success
                                              orelse Type == failure ->
  sendEapMessage(RadType, Type, [], Id, RadData, State).
sendEapMessage(RadType, Type, EapMessageList, Id
               ,{Ip, Port, RadAuth, RadId, RadData, RadState}
               ,State=#{tx_credits := Credits}) 
  when Credits == 1 ->
  NID =
    case Type of
      Type when Type == success orelse Type == failure ->
        %When Tx success or failure, we must have a single
        %zero-payload EAP-Message.
        [<<_:1/bytes, _:1/bytes, _:2/bytes>>]=EapMessageList,
        Id;
      Type when Type == request ->
        incrementId(Id)
    end,
  Attrs=#{message_authenticator => [binary:copy(<<0>>, 16)]
          ,state => [RadState]
          ,eap_message => EapMessageList
         },

  %FIXME: The EAP method handling code should insert the MPPE keys at an
  %       appropriate time.
  %       For prototyping, we do it here.
  MPPEAttrs=
    case {RadType, Type} of
      {access_accept, success} ->
        case maps:get(tls_msk, State) of
          undefined -> #{};
          MSK ->
            LastRad=maps:get(last_rad, State),
            MasterRecvCryptKey=binary:part(MSK, 0, 32 ),
            MasterSendCryptKey=binary:part(MSK, 32, 32),
            <<RecvKey:50/bytes>> =radius_server:scramble_mppe_key(MasterRecvCryptKey, LastRad),
            <<SendKey:50/bytes>> =radius_server:scramble_mppe_key(MasterSendCryptKey, LastRad),
            #{mschap_mppe_send_key => [RecvKey]
              ,mschap_mppe_recv_key => [SendKey]}
        end;
      _ ->
        #{}
    end,
  TheAttrs=maps:merge(Attrs, MPPEAttrs),
  Pkt=decode:encodeAccess(Ip, RadType, RadId, RadAuth, TheAttrs),
  lager:info("Transmitting to ~p ~p Total eap message size ~p", [Ip, Port, erlang:iolist_size(EapMessageList)]),
  radius_tx:send(Ip, Port, Pkt, RadData),
  %If our EAP ID has changed, then we need to signal that we've moved on to
  %the next packet in the conversation.
  case NID of
    Id -> ok;
    NID ->
      ok=radius_server:insertWorkEntry(?MODULE, {NID, RadState, Ip}, waiting, self()),
      ok=radius_server:deleteWorkEntry(?MODULE, {Id, RadState, Ip})
  end,
  {ok, State#{work_key => {NID, RadState, Ip}, tx_credits := Credits-1}}.

incrementId(<<255>>) -> <<0>>;
incrementId(Id) when is_binary(Id) ->
  binary:encode_unsigned(
    binary:decode_unsigned(Id)+1).

txQueueIsEmpty(#{tx_queue := Q}) -> queue:is_empty(Q).

enqueueAndMaybeTransmit(RadType, EapCode, Data, State) ->
  {ok, NewState}=enqueueWork(RadType, EapCode, Data, State),
  transmitIfPossible(NewState).

transmitIfPossible(State=#{tx_credits := 0}) ->
  {ok, no_credits, State};
transmitIfPossible(State=#{tx_credits := Credits}) when Credits > 1 ->
  {error, {too_many_credits, Credits}, State};
transmitIfPossible(State=#{tx_queue := Queue
                           ,last_rad := Rad
                           ,last_eap := {_, Id, _,_,_}}) ->
  case queue:is_empty(Queue) of
    true ->
      {ok, no_work, State};
    false ->
      {RadType, EapCode, Data}=queue:get(Queue),
      NewQueue=queue:drop(Queue),
      {EapMessages, NewState}=
        case prepareWork(EapCode, Id, Data) of
          {ok, Messages} ->
            lager:info("Sending all of ~p with size ~p", [Data, byte_size(Data)]),
            {Messages, State#{tx_queue := NewQueue}};
          {data_too_large, Messages, Rest} ->
            lager:info("Sending part of ~p, leaving ~p bytes for the next iteration.", [Data, byte_size(Rest)]),
            NQ=queue:in_r(NewQueue, Rest),
            WNS=State#{tx_queue := NQ},
            {Messages, WNS}
        end,
      sendEapMessage(RadType, EapCode, EapMessages, Id, Rad, NewState)
  end.

enqueueWork(RadType, EapCode, Data, State) when is_list(Data) ->
  lager:info("enqueueWork multiple called"),
  FinalState=
      lists:foldl(fun(D, S) ->
                      {ok, NS}=enqueueWork(RadType, EapCode, D, S),
                      NS
                  end,
                  State, Data),
  {ok, FinalState};
enqueueWork(RadType, EapCode, Data, State=#{tx_queue := Queue}) ->
  lager:info("enqueueWork single called with ~p bytes data ~p CurrQueue ~p", [byte_size(Data), Data, queue:to_list(Queue)]),
  NewQueue=queue:in({RadType, EapCode, Data}, Queue),
  {ok, State#{tx_queue := NewQueue}}.

prepareWork(Code, Id) ->
  prepareWork(Code, Id, <<>>).
%FIXME: Pass in an actual EAP MTU, rather than doing this ad-hoc.
prepareWork(Code, Id, Data) when byte_size(Data) =< 1024 ->
  EapMessages=encodeEapMessage(Code, Id, Data),
  {ok, EapMessages};
%FIXME: Pass in an actual EAP MTU, rather than doing this ad-hoc.
prepareWork(Code, Id, <<Data:1024/bytes, Rest/binary>>) ->
  EapMessages=encodeEapMessage(Code, Id, Data),
  {data_too_large, EapMessages, Rest}.

%NOTE: There's no need to put any code _here_ that handles a link MTU because
%that is handled further up the stack.
encodeEapMessage(Code, Id) ->
  encodeEapMessage(Code, Id, <<>>).
encodeEapMessage(Code, Id, Data) when Code == request orelse Code == response ->
  NewId=incrementId(Id),
  doEncodeEapMessage(Code, NewId, Data);
encodeEapMessage(Code, Id, Data) when Code == success orelse Code == failure ->
  doEncodeEapMessage(Code, Id, Data).
doEncodeEapMessage('FRAGGING', <<>>, Acc) ->
  Acc;
doEncodeEapMessage('FRAGGING', Data, Acc) ->
  SliceSize=min(253, byte_size(Data)),
  <<D:SliceSize/bytes, Rest/bytes>> = Data,
  doEncodeEapMessage('FRAGGING', Rest, Acc ++ [D]);
doEncodeEapMessage(Code, Id, Data) ->
  C=
    case Code of
      request -> <<1>>;
      response -> <<2>>;
      success -> <<3>>;
      failure -> <<4>>
    end,
  ChunkSize=253,
  Length=byte_size(Data)+4,
  case Length > ChunkSize of
    false -> [<<C/binary, Id/binary, Length:16, Data/binary>>];
    true ->
      Sz=ChunkSize-4,
      <<D:Sz/bytes, Rest/binary>> = Data,
      A=[<<C/binary, Id/binary, Length:16, D/binary>>],
      doEncodeEapMessage('FRAGGING', Rest, A)
  end.

concatMessage(M) ->
  concatMessage(M, <<>>).
concatMessage([], B) -> B;
concatMessage([H|T], B) ->
  concatMessage(T, <<B/binary, H/binary>>).

findFirstCompatible([], _) -> {error, none_compatible};
findFirstCompatible([Suggested|Rest], Valid) ->
  case containsCompatible(Suggested, Valid) of
    [] -> findFirstCompatible(Rest, Valid);
    Method -> {ok, Method}
  end.
containsCompatible(_, []) -> [];
containsCompatible(Method, [V|Rest]) ->
  case Method of
    V -> Method;
    _ -> containsCompatible(Method, Rest)
  end.

%FIXME: This only works for methods with non-expanded types.
decodeEapAuthType(Type) when byte_size(Type) == 1 ->
  case Type of
    <<1>> -> identity;
    <<2>> -> notification;
    <<3>> -> nak;
    <<4>> -> md5;
    <<5>> -> otp;
    <<6>> -> gtc;
    <<13>> -> tls;
    <<21>> -> ttls;
    <<25>> -> peap;
    <<26>> -> mschapv2;
    <<52>> -> pwd; %EAP-PWD
    %FIXME: expanded_types correctly.
    <<254>> -> expanded_type;
    <<255>> -> experimental;
    _ -> unknown
  end;
decodeEapAuthType(Types) ->
  decodeEapAuthType(Types, []).
decodeEapAuthType(<<>>, Acc) ->
  lists:reverse(Acc);
decodeEapAuthType(<<T:1/bytes, R/binary>>, Acc) ->
  A2=[decodeEapAuthType(T)] ++ Acc,
  decodeEapAuthType(R, A2).

terminate(Reason, _, #{work_key := Key}) when Reason == normal
                                 orelse Reason == shutdown ->
  lager:info("Terminating because ~p, then deleting work record.", [Reason]),
  case Key of
    undefined -> ok;
    _ -> radius_server:deleteWorkEntry(?MODULE, Key)
  end;
terminate(Reason={shutdown, _}, _, #{work_key := Key}) ->
  lager:info("Terminating because ~p, then deleting work record.", [Reason]),
  case Key of
    undefined -> ok;
    _ -> radius_server:deleteWorkEntry(?MODULE, Key)
  end;
terminate(Reason, _, #{work_key := Key}) ->
  lager:info("Terminating because ~p, then indicating crash in work record.", [Reason]),
  case Key of
    undefined -> ok;
    _ -> radius_server:updateWorkEntry(?MODULE, Key, crashed, self())
  end.

%If our TLS helper dies or exits, we should terminate, too.
handle_info({'EXIT', Pid, Reason}, _, State=#{tls_srv_pid := Pid}) ->
  {stop, Reason, State};
handle_info(_, StateName, State) -> {next_state, StateName, State}.

%FIXME: Determine if any of these need to be non-stub functions:
handle_event(_, StateName,State) -> {next_state, StateName, State}.
handle_sync_event(_, _, StateName,State) -> {reply, {error, unexpected}, StateName, State}.
code_change(_, StateName, State, _) -> {ok, StateName, State}.
