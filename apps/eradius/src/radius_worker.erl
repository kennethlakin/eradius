-module(radius_worker).
-compile([{parse_transform, lager_transform}]).
-export([start/2, start_link/1, start_worker/1]).
-export([init/1]).
-export([handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include_lib("eradius/include/common.hrl").

-behavior(gen_server).

start(Mod, Args) ->
  supervisor:start_child(radius_worker_sup:getName(), [{Mod, Args}]).

start_link({Mod, Args}) ->
  Mod:start_worker(Args).

start_worker(Args={_,_,_,_}) ->
  gen_server:start_link(?MODULE, Args, []).

init(S={Addr, Port, Data, _Sock}) ->
  radius_server:insertWorkEntry(?MODULE, {Addr, Port, Data}, working, self()),
  eradius_stats:worker_start(self()),
  lager:debug("RADIUS Worker started with args ~p", [S]),
  self() ! start_work,
  {ok, S}.

handle_info(start_work, State={Addr, Port, Data, Sock}) ->
  case eradius_auth:lookup_nas(Addr) of
    {error, not_found} ->
      %FIXME: Add statistics?
      lager:notice("RADIUS Dropping packet from unrecognized NAS"),
      lager:debug("RADIUS NAS ~p", [Addr]);
    {ok, NASSecret} ->
      case eradius_tx:findCachedEntry(Addr, Port, Data) of
        {ok, {_, Pkt}} ->
          lager:info("RADIUS Packet is retransmission. Using cache"),
          eradius_tx:resend(Addr, Port, Pkt, Sock);
        none ->
          case eradius_decode:decodeRadius(Data) of
            {ok, Rad=#eradius_rad_raw{attrs=Rest, auth=Auth, id=RadId}} ->
              case eradius_decode:decodeAttributes(Rest, Addr, Auth) of
                {ok, RadAttrs} ->
                  lager:debug("RADIUS Attrs decoded ~p", [RadAttrs]),
                  {ok, Attrs}=eradius_preprocess:preprocess(Addr, RadAttrs),
                  lager:debug("RADIUS Attrs preprocessed ~p", [Attrs]),
                  case handlePacket(NASSecret, Addr, Port, Rad, Attrs, Data, Sock) of
                    {ok, #eradius_rad_handler_ret{code=RadType, attrs=TheAttrs}} ->
                      TxPkt=eradius_decode:encodeRadius(Addr, RadType, RadId, Auth, TheAttrs),
                      eradius_tx:send(Addr, Port, TxPkt, Data, Sock);
                    {drop, Reason} ->
                      lager:debug("RADIUS Packet dropped. Reason ~w", [Reason]); %FIXME: Add statistics?
                    Ret ->
                      lager:notice("RADIUS Handler failed. Reason ~p. Sending Access-Reject", [Ret]),
                      sendAccessReject(Addr, Port, RadId, Auth, Data, Sock)
                  end;
                {error, R} ->
                  lager:notice("RADIUS Attr decode error ~p Sending Access-Reject", [R]),
                  sendAccessReject(Addr, Port, RadId, Auth, Data, Sock, <<"Attribute decode error">>)
              end;
            {discard, _} ->
              %FIXME: Increment a discard counter. Discriminate between the various
              %       reasons why we might discard a packet.
              ok
          end
      end
  end,
  eradius_stats:worker_stop(self()),
  {stop, normal, State}.

%See RFC5997.
handlePacket(NASSecret, _, _, #eradius_rad_raw{type=status_server, auth=Auth}, Attrs, RadPacket, _) ->
  %FIXME: Consider rate-limiting these.
  case eradius_decode:verifyPacket(NASSecret, Auth, Attrs, RadPacket) of
    error ->
      lager:notice("RADIUS Packet verification failed"),
      {drop, verify_failed};
    ok ->
      {ok, #eradius_rad_handler_ret{code=access_accept}}
  end;
%See RFC2866
handlePacket(NASSecret, Addr, _, #eradius_rad_raw{type=accounting_request, auth=Auth}, Attrs, RadPacket, _) ->
  case eradius_decode:verifyPacket(NASSecret, Auth, Attrs, RadPacket) of
    error ->
      lager:notice("RADIUS Packet verification failed"),
      {drop, verify_failed};
    ok ->
      eradius_stats:accounting_request(Addr, Attrs),
      {ok, #eradius_rad_handler_ret{code=accounting_response}}
  end;
handlePacket(NASSecret, Addr, Port, #eradius_rad_raw{id=Id, auth=Auth}, Attrs, RadPacket, Sock) ->
  %%FIXME: Notice that we never even inspect the radius type
  %%       (in #eradius_rad_raw.type) to determine what to
  %%       do... we just assume that it is an access_challenge
  %%       and proceed.
  NextStep=radius_server:determineWhatToDo(Attrs),
  lager:debug("RADIUS We got a ~p request", [NextStep]),
  %%FIXME: Need to add in NAS quirk processing here.
  %%       for the attrs in the packet.

  %FIXME: The checking done in verifyAuthPlausibility only makes sense
  %       for an Access-Request packet!
  case eradius_decode:verifyAuthPlausibility(Attrs) of
    error ->
      lager:notice("RADIUS Dropping packet because illegal auth attr combination");
    ok ->
      case eradius_decode:verifyPacket(NASSecret, Auth, Attrs, RadPacket) of
        error ->
          lager:notice("RADIUS Packet verification failed"),
          {drop, verify_failed};
        ok ->
          case Attrs of
            #{state := StateAttr} ->
              lager:debug("RADIUS Ongoing conversation");
            _ ->
              lager:debug("RADIUS New conversation"),
              StateAttr=radius_server:getNewStateData()
          end,
          try
            NextStep:handle_rad_packet(#eradius_rad{ip=Addr, port=Port, auth=Auth, id=Id, originalPacket=RadPacket
                                                    ,state=StateAttr, attrs=Attrs})
          catch
            Class:Reason ->
              Stacktrace=erlang:get_stacktrace(),
              lager:warning("RADIUS RADIUS handler threw exception. Sending Access-Reject."),
              sendAccessReject(Addr, Port, Id, Auth, RadPacket, Sock),
              erlang:raise(Class, Reason, Stacktrace)
          end
      end
  end.

%Convenience function to send an Access-Reject when we encounter an unexpected
%error.
sendAccessReject(Addr, Port, Id, Auth, RadPacket, Sock) ->
  sendAccessReject(Addr, Port, Id, Auth, RadPacket, Sock, <<"Internal server error">>).
sendAccessReject(Addr, Port, Id, Auth, RadPacket, Sock, Message) when is_binary(Message) ->
  TxPkt=eradius_decode:encodeRadius(Addr, access_reject, Id, Auth, #{reply_message => Message}),
  eradius_tx:send(Addr, Port, TxPkt, RadPacket, Sock).

terminate(_, {Addr, Port, Data, _}) ->
  ok=radius_server:deleteWorkEntry(?MODULE, {Addr, Port, Data}).

handle_call(_, _, State) -> {reply, {error, unexpected}, State}.
handle_cast(_, State) -> {noreply, State}.
code_change(_, State, _) -> {ok, State}.
