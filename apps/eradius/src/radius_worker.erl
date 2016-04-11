-module(radius_worker).
-compile([{parse_transform, lager_transform}]).
-export([start/2, start_link/1, start_worker/1]).
-export([init/1]).
-export([handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-behavior(gen_server).

start(Mod, Args) ->
  supervisor:start_child(radius_worker_sup:getName(), [{Mod, Args}]).

%radius_worker_sup calls this when it is asked to start a child.
start_link({Mod, Args}) ->
  %We expect that start_worker will call start_link or equivalent.
  Mod:start_worker(Args).

start_worker(Args={_,_,_,_}) ->
  gen_server:start_link(?MODULE, Args, []).

init(S={_,_,_,_}) ->
  {ok, S, 0}.

%So, here's the flow for child handlers:
%% * Get passed the addr, port, RADIUS ID, and original packet
%% * Work on the packet
%% * Return ignore | reject (with optional Attributes) | accept (w/ attrs)
%%    | challenge (w/ attrs) along with the original packet to the parent
%%    (the radius_server module).
%% * Now... the radius_server module will -in the case of reject/accept/challenge- save
%%   both the original packet, *and* the response packet that it sends. If it
%%   gets the *same* packet back from the NAS on the same addr and port, then
%%   it will send the packet it sent previously in response to that request.
%% ****** Actually... if at all possible, the child handler should send the
%%        first reply. This lets the radius_server module just handle packet
%%        dispatch and initial recording of addr/port/RADIUS_ID/packet info.
%%      * ACTUALLY, the above intuition is not the best, I think. Might be best
%%        to interleave Rx and Tx in this case. Or -fuck, IDK- have an Rx and a
%%        separate Tx process? Surely they won't have to own their own UDP
%%        socket... surely they can share one. (Made a separate Tx process and
%%        a socket server that gives you Rx access to the socket, and allows
%%        you to take and release ownership of the socket to perform Rx on the
%%        socket.
%%      * I suppose that the initial recording would set a flag that says that
%%        packet is "being worked on", and maybe mention the PID that is
%%        handling it. For protos like EAP that have conversations across
%%        multiple packets, after the initial recording by the radius_server
%%        module, the child handles status recording. It also records NAS-sent
%%        packet and response packet. This scheme should let us avoid
%%        bottlenecking in radius_server.
%% * After a while (30 seconds??) this entry in the response packet cache will
%%   be purged.
handle_info(timeout, State={Addr, Port, Data, _}) ->
  radius_server:insertWorkEntry(?MODULE, {Addr, Port, Data}, working, self()),
  case radius_tx:findCachedEntry(Addr, Port, Data) of
    {ok, {_, Pkt}} ->
      radius_tx:resend(Addr, Port, Pkt),
      lager:info("Cached entry used!");
    none ->
      DecRet=decode:decodeRadius(Data),
      lager:info("Got packet."),
      case DecRet of
        {ok, _Code, _RequestType, Id, _Length, Auth, Rest} ->
          Attrs=case decode:decodeAttributes(Rest) of
                  {ok, A} -> A;
                  {error, R} -> lager:info("Error: ~p", [R]), []
                end,
          NextStep=radius_server:determineWhatToDo(Attrs),
          lager:info("We are going to do ~p next.", [NextStep]),
          %FIXME: The checking done in verifyAuthPlausibility only makes sense
          %       for an Access-Request packet!
          case decode:verifyAuthPlausibility(Attrs) of
            error ->
              lager:warning("Dropping packet because illegal auth attr combination.");
            ok ->
              lager:info("Packet is plausible."),
              Verify=decode:verifyPacket(Addr, Auth, Attrs, Data),
              lager:info("verifyPacket returned ~p", [Verify]),
              lager:info("Handing off packet"),
              case Attrs of
                #{state := {[_], SA}} ->
                  lager:info("State attr found."),
                  <<_:2/bytes, StateAttr/binary>> = SA;
                _ ->
                  lager:info("Creating new state attr."),
                  StateAttr=radius_server:getNewStateData()
              end,
              Ret=NextStep:handlePacket({Addr, Port, Auth, Id, Data, StateAttr}, Attrs),
              lager:info("handlePacket returned ~p", [Ret])
          end;
        {discard, _} ->
          %FIXME: Increment a discard counter. Discriminate between the various
          %       reasons why we might discard a packet.
          ok
      end
  end,
  {stop, normal, State}.

terminate(_, {Addr, Port, Data, StartTime}) ->
  ok=radius_server:deleteWorkEntry(?MODULE, {Addr, Port, Data}),
  EndTime=erlang:monotonic_time(),
  radius_server:signalDone(EndTime-StartTime).

handle_call(_, _, State) -> {reply, ok, State, 0}.
handle_cast(_, State) -> {noreply, State, 0}.
code_change(_, State, _) -> {ok, State}.
