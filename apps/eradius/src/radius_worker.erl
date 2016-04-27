-module(radius_worker).
-compile([{parse_transform, lager_transform}]).
-export([start/2, start_link/1, start_worker/1]).
-export([init/1]).
-export([handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-behavior(gen_server).

start(Mod, Args) ->
  supervisor:start_child(radius_worker_sup:getName(), [{Mod, Args}]).

start_link({Mod, Args}) ->
  Mod:start_worker(Args).

start_worker(Args={_,_,_,_}) ->
  gen_server:start_link(?MODULE, Args, []).

init(S={_,_,_,_}) ->
  lager:debug("RADIUS Worker started with args ~p", [S]),
  {ok, S, 0}.

handle_info(timeout, State={Addr, Port, Data, _}) ->
  radius_server:insertWorkEntry(?MODULE, {Addr, Port, Data}, working, self()),
  case eradius_auth:lookup_nas(Addr) of
    {error, not_found} ->
      %FIXME: Add statistics?
      lager:notice("RADIUS Dropping packet because from unrecognized NAS"),
      lager:debug("RADIUS NAS ~p", [Addr]);
    {ok, NASSecret} ->
      case radius_tx:findCachedEntry(Addr, Port, Data) of
        {ok, {_, Pkt}} ->
          lager:info("RADIUS Packet is retransmission. Using cache"),
          radius_tx:resend(Addr, Port, Pkt);
        none ->
          DecRet=decode:decodeRadius(Data),
          case DecRet of
            {ok, Rad={_,_,_,_,_,Rest}} ->
              case decode:decodeAttributes(Rest) of
                {ok, Attrs} ->
                  lager:debug("RADIUS Attrs decoded ~p", [Attrs]),
                  handlePacket(NASSecret, Addr, Port, Rad, Attrs, Data);
                {error, R} ->
                  lager:notice("RADIUS Attr decode error ~p", [R])
              end;
            {discard, _} ->
              %FIXME: Increment a discard counter. Discriminate between the various
              %       reasons why we might discard a packet.
              ok
          end
      end
  end,
  {stop, normal, State}.

handlePacket(NASSecret, Addr, Port, {_, _, Id, _, Auth, _}, Attrs, Data) ->
  NextStep=radius_server:determineWhatToDo(Attrs),
  lager:debug("RADIUS We got a ~p request", [NextStep]),
  %FIXME: The checking done in verifyAuthPlausibility only makes sense
  %       for an Access-Request packet!
  case decode:verifyAuthPlausibility(Attrs) of
    error ->
      lager:notice("RADIUS Dropping packet because illegal auth attr combination");
    ok ->
      case decode:verifyPacket(NASSecret, Auth, Attrs, Data) of
        error ->
          lager:notice("RADIUS Packet verification failed");
        ok ->
          case Attrs of
            #{state := {[_], SA}} ->
              lager:debug("RADIUS Ongoing conversation"),
              <<_:2/bytes, StateAttr/binary>> = SA;
            _ ->
              lager:debug("RADIUS New conversation"),
              StateAttr=radius_server:getNewStateData()
          end,
          case NextStep:handlePacket({Addr, Port, Auth, Id, Data, StateAttr}, Attrs) of
            ok -> ok;
            {drop, _} -> ok; %FIXME: Add statistics?
            ErrorRet -> lager:notice("RADIUS Handler failed. Reason ~p", [ErrorRet])
          end
      end
  end.

terminate(_, {Addr, Port, Data, StartTime}) ->
  ok=radius_server:deleteWorkEntry(?MODULE, {Addr, Port, Data}),
  EndTime=erlang:monotonic_time(),
  radius_server:signalDone(EndTime-StartTime).

handle_call(_, _, State) -> {reply, ok, State, 0}.
handle_cast(_, State) -> {noreply, State, 0}.
code_change(_, State, _) -> {ok, State}.
