-module(eradius_eap).

-compile([{parse_transform, lager_transform}]).

-include_lib("eradius/include/common.hrl").

-behavior(gen_fsm).

%%FIXME:
%%Okay, probably have a radius_handler behavior and an eap_handler behavior?
%%Handlers are listed in the config file. Maybe as part of their "load" process, they
%%register what packet types they're able to handle.
%%
%%Unrelated: add get_status/0 and get_status/1 function
%%           It returns a map that contains info about the worker's current
%%           state. Its primary use is to do debug prints if something goes
%%           wrong (say, if the worker is being reaped). Example:
%%           EAP-PEAP-MSCHAPv2
%%           #{radius =>
%%             #{id => 50
%%               ,ip => <<10,0,0,1>>
%%               ,rad_attrs => #{ rad_attr_map ... }
%%               ,eap => 
%%                #{id => 22
%%                  ,peap => 
%%                   #{ tls_state => tls_up
%%                      ,mschapv2 => 
%%                       #{ state => challenge_sent }
%%                    } } } }
%%

%gen_fsm stuff:
-export([init/1, code_change/4, handle_event/3, handle_info/3, handle_sync_event/4, terminate/3]).
%gen_fsm states:
-export([starting/3, running/3, running/2]).
%radius_worker "behavior" stuff:
-export([start_worker/1]).
%External API: FIXME: This should maybe converted from camelCase to
%                     underscore_format
%                     Or... it should be part of a radius_packet_handler
%                     behavior....
-export([handlePacket/1]).
%tls_udp client stuff:
-export([tls_up/2, send_cyphertext/2, handle_tls_data/2, tls_server_start_error/2]).
%Internal API stuff.
-export([incrementId/1, enqueueWork/4, transmitIfPossible/1, getNewMethodData/0
        ,encodeEapMessage/3, decodeMessage/1, prepareWork/3]).
%%FIXME: Temporary export of stuff that should be in its own module.
%%       (exported because of the apply call in handleOuterPacket/3 and
%%       elsewhere.)
-export([md5/2]).


%This is plaintext that was decrypted by the TLS code.
handle_tls_data(FSMPid, Msg={ssl, _Sock, _Data}) ->
  gen_fsm:send_event(FSMPid, Msg).

%Used by the peap_tls_srv to get us to send cyphertext that came out of the SSL
%machinery to the RADIUS peer.
send_cyphertext(FSMPid, Msg={eradius_send_cyphertext, _Data}) ->
  gen_fsm:send_event(FSMPid, Msg).

%Called when our TLS server is finally up and running.
tls_up(FSMPid, Msg={tls_up, _RadState}) ->
  gen_fsm:send_event(FSMPid, Msg).

%If the TLS server fails to start, this gets called.
tls_server_start_error(FSMPid, Msg={tls_udp_server_start_error, _}) ->
  gen_fsm:send_event(FSMPid, Msg).

handlePacket(RadData=#eradius_rad{ip=Ip, state=RadState, attrs=#{eap_message := EM, message_authenticator := _}}) ->
  %Just in case we've an incorrect dictionary loaded, concatenate multiple
  %eap_message items:
  Message=concatMessage(EM),
  case decodeMessage(Message) of
    {ok, DecodedMessage=#eradius_eap{id=Id}} ->
      lager:info("EAP Packet okay"),
      FSMPid =
        case radius_server:getWorkEntry(?MODULE, {Id, RadState, Ip}) of
          {ok, {FsmPid, working}} ->
            lager:info("EAP ~p is working on this. Dropping", [FsmPid]),
            {drop, working};
          {ok, {FsmPid, crashed}} ->
            %FIXME: What do do in this case?
            lager:notice("EAP ~p was working on this but crashed. Odd.", [FsmPid]),
            {drop, crashed};
          {ok, {FsmPid, waiting}} ->
            lager:info("EAP Handing off to ~p ", [FsmPid]),
            FsmPid;
          {error, work_entry_not_found} ->
            lager:info("EAP New conversation"),
            ok=radius_server:insertWorkEntry(?MODULE, {Id, RadState, Ip}, working, undefined),
            {ok, FsmPid}=radius_worker:start(?MODULE, [DecodedMessage, RadData]),
            FsmPid
        end,
      case FSMPid of
        {drop, Reason} -> {discard, Reason};
        _ ->
          %FIXME: What to do if essential RADIUS attributes have changed since
          %       we started the EAP handler?
          Ret=gen_fsm:sync_send_event(FsmPid, {handle, DecodedMessage, RadData}, infinity),
          case Ret of
            ok -> ok;
            _ ->
              lager:info("EAP Handler returned error ~p", [Ret]),
              Ret
          end
      end;
    {discard, packet_too_short} ->
      {discard, packet_too_short};
    {discard, Reason} ->
      {discard, Reason}
  end.

decodeMessage(P = <<Code, ID, L:2/bytes, Type:1/bytes, _/binary>>) ->
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
          1 -> request;
          2 -> response;
          3 -> success;
          4 -> failure;
          _ -> {discard, invalid_code}
        end,
      T=decodeEapAuthType(Type),
      {ok, #eradius_eap{code=C, id=ID, length=L, type=T, typedata=TypeData}}
  end.

getNewState(Id, RadState, Ip, RadAttrs) ->
  %Version 8.0 (OTP-19.0) of the ssl module added automatic TLS handshake
  %record batching. For earlier versions, we have to perform the batching
  %ourselves.
  {_,_,SslVer}=lists:keyfind(ssl, 1, application:which_applications()),
  {VerMaj,_}=string:to_integer(lists:nth(1, string:tokens(SslVer, "."))),
  HandshakeBatching=VerMaj < 8,
  lager:debug("EAP Running with ssl app version ~p. Doing TLS handshake batching? ~w", [SslVer,HandshakeBatching]),
  #{ work_key => {Id, RadState, Ip}
     ,do_tls_handshake_batching => HandshakeBatching
     %FIXME: Make this configurable!
     ,default_method => peap
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
     ,username => undefined
     ,rad_attrs => RadAttrs
   }.

%Used to reset an EAP method's data.
getNewMethodData() ->
  #{ username => undefined
     ,user_pass => undefined
     ,success_attrs => #{}
     ,failure_attrs => #{}
     ,state => undefined}.

%FIXME: There should be a registry or something, rather than having this
%       hard-coded.
discoverHandleMethod(Method) ->
  case Method of
    md5      -> fun ?MODULE:md5/2;
    mschapv2 -> fun eradius_mschap:handle/2;
    peap     -> fun eradius_peap:handle/2
  end.

start_worker(Args) ->
  lager:debug("EAP Worker started with args ~p", [Args]),
  gen_fsm:start_link(?MODULE, Args, []).

init([#eradius_eap{id=Id}, #eradius_rad{ip=Ip, state=RadState, attrs=RadAttrs}]) ->
  ok=radius_server:updateWorkEntry(?MODULE, {Id, RadState, Ip}, working, self()),
  process_flag(trap_exit, true),
  State=getNewState(Id, RadState, Ip, RadAttrs),
  {ok, starting, State}.

starting({handle, #eradius_eap{code=response, type=nak}, #eradius_rad{}}, _, State) ->
  lager:info("EAP Spurious NAK in conversation start"),
  {reply, {discard, spurious_nak}, starting, State};
starting(Msg={handle
              ,EAP=#eradius_eap{code=response, id=Id, type=EapType, typedata=EapTypeData}
              ,Rad=#eradius_rad{ip=Ip, state=RadState}}
         ,From, State=#{tx_credits := Credits})
  when Credits == 0 ->
  ok=radius_server:updateWorkEntry(?MODULE, {Id, RadState, Ip}, working, self()),
  case EapType of
    identity ->
      Username=EapTypeData,
      DefaultMethod=maps:get(default_method, State),
      NewState=State#{username := Username, current_method := DefaultMethod
                      ,last_rad := Rad, last_eap := EAP
                     ,DefaultMethod => getNewMethodData()},
      %Offer our default auth method
      DMFun=discoverHandleMethod(DefaultMethod),
      handleOuterPacket(From, DMFun, [Msg, NewState]);
    _ ->
      lager:info("EAP Got a ~p packet in conversation start. Ignoring", [EapType]),
      {reply, {discard, spurious_non_ident}, starting, State}
  end.

running(Msg={handle, EAP=#eradius_eap{code=response, type=nak, id=Id, typedata=BinMethods},
             Rad=#eradius_rad{ip=Ip, state=RadState}},
          From,
          State=#{supported_methods := SupportedMethods, current_method := OldCurrentMethod
                  ,tx_credits := Credits})
  when Credits == 0 ->
  ok=radius_server:updateWorkEntry(?MODULE, {Id, RadState, Ip}, working, self()),
  lager:info("EAP Negotiating alternate EAP method"),
  %FIXME: This only works for methods with non-expanded types.
  SuggestedMethods =
    case decodeEapAuthType(BinMethods) of
      M when is_list(M) -> M;
      R -> [R]
    end,
  lager:debug("EAP Peer suggested methods ~p", [SuggestedMethods]),
  NS=maps:remove(OldCurrentMethod, State),
  NewState=NS#{last_rad := Rad, last_eap := EAP},
  case findFirstCompatible(SuggestedMethods, SupportedMethods) of
    {error, none_compatible} ->
      lager:info("EAP No compatible methods"),
      {ok, NextState}=enqueueAndMaybeTransmit(access_reject, failure, <<>>, NewState#{tx_credits := Credits+1}),
      gen_fsm:reply(From, ok),
      {stop, normal, NextState};
    {ok, Method} ->
      lager:info("EAP Negotiated method ~p", [Method]),
      NextState=NewState#{current_method := Method, Method => getNewMethodData()},
      handleOuterPacket(From, fun handleMethod/3, [Method, Msg, NextState])
  end;
running(Msg={handle,
             EAP=#eradius_eap{code=response, id=Id, type=EapType},
             Rad=#eradius_rad{ip=Ip, state=RadState}},
          From, State=#{current_method := EapType, tx_credits := Credits})
  when Credits == 0 ->
  ok=radius_server:updateWorkEntry(?MODULE, {Id, RadState, Ip}, working, self()),
  NewState=State#{last_rad := Rad, last_eap := EAP},
  handleOuterPacket(From, fun handleMethod/2, [Msg, NewState]).

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
      case enqueueAndMaybeTransmit(RType, EType, Packets, NS) of
        {ok, FS} ->
          {reply, ok, running, FS}
      end;
    {auth_ok, {RType, EType, Packets, SuccessAttrs}, S=#{tx_credits := Credits}} ->
      NS=S#{tx_credits := Credits+1},
      case enqueueAndMaybeTransmit(RType, EType, Packets, SuccessAttrs, NS) of
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

running(rehandle_last_eap_packet, State=#{tx_credits := Credits
                                                  ,last_rad := LastRad
                                                  ,last_eap := LastEap})
  when Credits == 1 ->
  case running({handle, LastEap, LastRad}, undefined, State#{tx_credits := 0}) of
    {reply, _, StateName, NS} ->
      {next_state, StateName, NS};
    Other -> Other
  end;
running(Msg={tls_up, _}, State=#{current_method := CurrMethod})
  when CurrMethod /= undefined ->
  Fun=discoverHandleMethod(CurrMethod),
  {ok, NS}=Fun(Msg, State),
  {next_state, running, NS};
running(Msg={eradius_send_cyphertext, _}, State=#{current_method := CurrMethod})
  when CurrMethod /= undefined ->
  Fun=discoverHandleMethod(CurrMethod),
  {ok, NS}=Fun(Msg, State),
  {next_state, running, NS};
running(Msg={ssl, _, _}, State=#{current_method := CurrMethod})
  when CurrMethod /= undefined ->
  Fun=discoverHandleMethod(CurrMethod),
  {ok, NS}=Fun(Msg, State),
  {next_state, running, NS};
running(Msg={tls_udp_server_start_error, _}, State) ->
  {stop, {error, Msg}, State}.

%%Rad's type in both clauses is #eradius_rad
handleMethod(TypeOverride, {Task, EAP, Rad}, State) ->
  handleMethod({Task, EAP#eradius_eap{type=TypeOverride}, Rad}, State).
handleMethod(Msg={_Task, Eap=#eradius_eap{type=Type}, Rad=#eradius_rad{}}, State) ->
  NewState=State#{last_rad := Rad, last_eap := Eap},
  case Type of
    identity ->
      Method=maps:get(default_method, NewState),
      lager:info("EAP Offering default method ~p", [Method]);
    _ ->
      Method=Type
  end,
  Fun=discoverHandleMethod(Method),
  Fun(Msg, NewState).

%@returns (just like all other method handlers)
% {ignore, State} | {ignore, bad_packet, State} | {send_queued, State}
% | {send_handled, State}
% | {enqueue_and_send, {Radius_type, EapType, PacketList}, State}
% | {auth_okay, {Radius_type, EapType, PacketList}, State}
% | {auth_fail, {Radius_type, EapType, PacketList}, State}
md5({handle, Eap=#eradius_eap{id=Id, typedata=TypeData},
    Rad=#eradius_rad{}},
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
      Challenge=crypto:strong_rand_bytes(16),
      ChallengeLen=binary:encode_unsigned(byte_size(Challenge)),
      Data= <<4,ChallengeLen/binary,Challenge/binary>>,
      Pkt={access_challenge, request, Data},
      NewState=State#{md5 := MethodData#{state => {challenge_sent, Challenge}}},
      {enqueue_and_send, Pkt, NewState};
    {challenge_sent, Challenge} ->
      Pass=maps:get(user_pass, State),
      CalculatedChallenge=crypto:hash(md5, <<Id, Pass/binary, Challenge/binary>>),
      <<_:1/bytes, ReceivedChallenge/binary>> = TypeData,
      case CalculatedChallenge == ReceivedChallenge of
        true -> {auth_ok, {access_accept, success, <<>>}, State};
        false -> {auth_fail, {access_reject, failure, <<>>}, State}
      end
  end.

sendEapMessage(RadType, Type, EapMessageList, AddlAttrs, Id
               ,#eradius_rad{ip=Ip, port=Port, auth=RadAuth, id=RadId
                             ,originalPacket=RadData, state=RadState}
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
  Attrs=#{message_authenticator => binary:copy(<<0>>, 16)
          ,state => RadState
          ,eap_message => EapMessageList
         },

  TheAttrs=maps:merge(Attrs, AddlAttrs),
  Pkt=eradius_decode:encodeRadius(Ip, RadType, RadId, RadAuth, TheAttrs),
  lager:info("EAP Tx ~p bytes to ~p:~p", [erlang:iolist_size(EapMessageList), Ip, Port]),
  %NOTE: We might get the reply packet before we update our work entry...
  %      So, when we go to insert the new work entry, there might already be an
  %      EAP FSM working on it. So, update work entry data before transmitting.
  case NID of
    Id ->
      ok=radius_server:updateWorkEntry(?MODULE, {Id, RadState, Ip}, waiting, self());
    NID ->
      ok=radius_server:insertWorkEntry(?MODULE, {NID, RadState, Ip}, waiting, self()),
      ok=radius_server:deleteWorkEntry(?MODULE, {Id, RadState, Ip})
  end,
  eradius_tx:send(Ip, Port, Pkt, RadData),
  {ok, State#{work_key => {NID, RadState, Ip}, tx_credits := Credits-1}}.

incrementId(255) -> 0;
incrementId(Id) -> Id+1.

txQueueIsEmpty(#{tx_queue := Q}) -> queue:is_empty(Q).

%FIXME: Or should we convert from separate Data and Attributes lists
%       to a {Data, Attrs} structure, and maybe a list of those?
enqueueAndMaybeTransmit(RadType, EapCode, Data, State) ->
  enqueueAndMaybeTransmit(RadType, EapCode, Data, #{}, State).
enqueueAndMaybeTransmit(RadType, EapCode, Data, AddlAttrs, State) ->
  {ok, NewState}=enqueueWork(RadType, EapCode, Data, AddlAttrs, State),
  transmitIfPossible(NewState).

transmitIfPossible(State=#{tx_credits := 0}) ->
  {ok, no_credits, State};
transmitIfPossible(State=#{tx_credits := Credits}) when Credits > 1 ->
  {error, {too_many_credits, Credits}, State};
transmitIfPossible(State=#{tx_queue := Queue
                           ,last_rad := Rad
                           ,last_eap := #eradius_eap{id=Id}}) ->
  case queue:is_empty(Queue) of
    true ->
      {ok, no_work, State};
    false ->
      {RadType, EapCode, Data, StoredAddlAttrs}=queue:get(Queue),
      NewQueue=queue:drop(Queue),
      {EapMessages, AddlAttrs, NewState}=
        case prepareWork(EapCode, Id, Data) of
          {ok, Messages} ->
            {Messages, StoredAddlAttrs, State#{tx_queue := NewQueue}};
          %%FIXME: The following clause might not ever be executed.
          %%       The args to queue:in_r/2 were reversed, but I have
          %%       _never_ seen a crash because of the error.
          %%       If this code is never executed, then what is providing
          %%       the size limiting???
          %%
          %%       ...I _guess_ the only current source of packets larger than
          %%       the EAP MTU is our PEAP handler... and it _already_ chunks
          %%       packets up to fit within the MTU + some header info.
          {data_too_large, Messages, Rest} ->
            lager:debug("EAP Tx ~p bytes. ~p bytes in queue", [byte_size(Data), byte_size(Rest)]),
            NQ=queue:in_r({RadType, EapCode, Rest, StoredAddlAttrs}, NewQueue),
            WNS=State#{tx_queue := NQ},
            %Don't Tx addl RADIUS attrs until we're transmitting the last
            %packet in this chain.
            %FIXME: Should it be an error to add addl attrs along with data
            %       that's larger than the EAP MTU?
            {Messages, #{}, WNS}
        end,
      sendEapMessage(RadType, EapCode, EapMessages, AddlAttrs, Id, Rad, NewState)
  end.

enqueueWork(_, _, [], State) ->
  {ok, State};
enqueueWork(RadType, EapCode, [DH|DT], State) ->
  {ok, NS} = enqueueWork(RadType, EapCode, DH, State),
  enqueueWork(RadType, EapCode, DT, NS);
enqueueWork(RadType, EapCode, Data, State=#{tx_queue := _}) ->
  enqueueWork(RadType, EapCode, Data, #{}, State).

enqueueWork(_, _, [], [], State) ->
  {ok, State};
enqueueWork(RadType, EapCode, [DH|DT], [AH|AT], State) ->
  {ok, NS} = enqueueWork(RadType, EapCode, DH, AH, State),
  enqueueWork(RadType, EapCode, DT, AT, NS);
enqueueWork(RadType, EapCode, Data, AddlRadAttrs, State=#{tx_queue := Queue}) ->
  lager:debug("EAP Enqueuing ~p bytes. QueueLen ~p", [byte_size(Data), queue:len(Queue)]),
  NewQueue=queue:in({RadType, EapCode, Data, AddlRadAttrs}, Queue),
  {ok, State#{tx_queue := NewQueue}}.

%FIXME: Pass in an actual EAP MTU, rather than doing this ad-hoc.
prepareWork(Code, Id, Data) when byte_size(Data) =< 1024 ->
  EapMessages=encodeEapMessage(Code, Id, Data),
  {ok, EapMessages};
%FIXME: Pass in an actual EAP MTU, rather than doing this ad-hoc.
prepareWork(Code, Id, <<Data:1024/bytes, Rest/binary>>) ->
  EapMessages=encodeEapMessage(Code, Id, Data),
  {data_too_large, EapMessages, Rest}.

%NOTE: There's no need to put any code _here_ that handles a MTU because
%that is handled further up the stack.
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
    %FIXME: There's a fair bit of code lying around that uses the fact that a
    %       one-item list returned from eap:prepareWork means that the EAP
    %       message will fit into a single packet. So, before we turn the
    %       one-packet version of this into just a binary, we need to track
    %       down all the places where that sort of thing happens and fix em.
    false -> [<<C/binary, Id, Length:16, Data/binary>>];
    true ->
      Sz=ChunkSize-4,
      <<D:Sz/bytes, Rest/binary>> = Data,
      A=[<<C/binary, Id, Length:16, D/binary>>],
      doEncodeEapMessage('FRAGGING', Rest, A)
  end.

concatMessage(M) ->
  concatMessage(M, <<>>).
concatMessage([], B) -> B;
concatMessage([H|T], B) ->
  concatMessage(T, <<B/binary, H/binary>>);
concatMessage(M, <<>>) -> M.

findFirstCompatible([], _) -> {error, none_compatible};
findFirstCompatible([Suggested|Rest], Valid) ->
  case lists:member(Suggested, Valid) of
    false -> findFirstCompatible(Rest, Valid);
    true -> {ok, Suggested}
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
    %FIXME: handle expanded_types correctly.
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
  lager:debug("EAP Terminating because ~p, then deleting work record.", [Reason]),
  case Key of
    undefined -> ok;
    _ -> radius_server:deleteWorkEntry(?MODULE, Key)
  end;
terminate(Reason={shutdown, _}, _, #{work_key := Key}) ->
  lager:debug("EAP Terminating because ~p, then deleting work record.", [Reason]),
  case Key of
    undefined -> ok;
    _ -> radius_server:deleteWorkEntry(?MODULE, Key)
  end;
terminate(Reason, _, #{work_key := Key}) ->
  lager:debug("EAP Terminating because ~p, then indicating crash in work record.", [Reason]),
  case Key of
    undefined -> ok;
    _ -> radius_server:updateWorkEntry(?MODULE, Key, crashed, self())
  end.

%If our TLS helper dies or exits, we should terminate, too.
handle_info({'EXIT', Pid, Reason}, _, State=#{tls_srv_pid := Pid}) ->
  {stop, Reason, State};
handle_info(_, StateName, State) -> {next_state, StateName, State}.

handle_event(_, StateName,State) -> {next_state, StateName, State}.
handle_sync_event(_, _, StateName,State) -> {reply, {error, unexpected}, StateName, State}.
code_change(_, StateName, State, _) -> {ok, StateName, State}.
