-module(radius_server).
-compile([{parse_transform, lager_transform}]).

-include_lib("eradius/include/common.hrl").

-behavior(gen_server).

%gen_server stuff:
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
%Work table management API
-export([getWorkEntry/2, insertWorkEntry/4, updateWorkEntry/4, deleteWorkEntry/2]).
%Used by radius_worker:
-export([getNewStateData/0, determineWhatToDo/1]).
%Housekeeping:
-export([start_link/0, getName/0]).
%Work table management housekeeping API
-export([txTableName/0, workTableName/0]).
%Utility stuff that should maybe be elsewhere:
-export([bin_to_hex/1]).

getName() ->
  eradius_radius_server.

workTableName() ->
  eradius_work_table.

txTableName() ->
  eradius_tx_table.

start_link() ->
  gen_server:start_link({local, getName()}, ?MODULE, [], []).

init(_) ->
  Multiplier=2,
  Workers=erlang:system_info(schedulers)*Multiplier,
  createTables(),
  UdpSock=radius_sock:get_sock(),
  AccSock=radius_sock:get_accounting_sock(),
  ok=radius_sock:take_ownership(UdpSock),
  ok=radius_sock:take_ownership(AccSock),
  %First switch to passive mode so that in case of starting back up after a
  %crash we're sure that we have at most a queue of length Workers.
  %FIXME: Consider looking at the read_packets option.
  inet:setopts(UdpSock, [{active, false}]),
  inet:setopts(AccSock, [{active, false}]),
  inet:setopts(UdpSock, [{active, Workers}]),
  inet:setopts(AccSock, [{active, Workers}]),
  lager:info("RADIUS Initialized with ~p workers", [Workers]),
  {ok, #{udp_sock => UdpSock, acc_sock => AccSock, num_schedulers => Workers, monitor_list => #{}}}.

%FIXME: Useful RFCS:
%       2865 5080 (RADIUS and RADIUS implementation lessons.)
%       2866 (RADIUS Accounting)
%       3579 3748 (EAP and EAP-RADIUS)
%       2433 (MSCHAPv1)
%       2759 draft-kamath-pppext-eap-mschapv2-02 (MSCHAPv2)
%             (NOTE: SHAInit/Update/Final are crypto:hash_init/update/final)
%       1994 (for PPP-CHAP, which is required to understand EAP-MD5 as well as
%             MSCHAP and MSCHAPv2)
%       5216 (EAP-TLS)
%       5281 (TTLSv0)
%       7170 (TEAPv1) [Not gonna get to this any time soon. It uses TLS SessionTicket]
%       draft-kamath-pppext-peapv0-00 (PEAPv0)
%       draft-josefsson-pppext-eap-tls-eap-05 (PEAPv1)
%       draft-josefsson-pppext-eap-tls-eap-10 (PEAPv2)
%         NOTE: For the TLS-based EAP methods (like PEAP) it might be worth
%               either figuring out if there's a way to remove entries from the
%               SSL session cache, and -if there's not- writing our own SSL
%               session cache code. (see ssl_session_cache_api dox). Also, if
%               we can remove sessions from the cache, being able to increase
%               the time before expiry of entires might be good.
%               Why do all this? PEAP (and maybe others) can use the presence
%               of a matching entry in the TLS session cache as a signal that
%               the requesting peer was previously authorized, so there's no
%               need to redo all the auth/authz stuff again.


handle_info({udp, Sock, Addr, Port, Data}, State=#{udp_sock := USock, acc_sock := ASock, monitor_list := MonList}) ->
  case Sock of
    Sock when Sock == USock orelse Sock == ASock ->
      case isWorkEntry(radius_worker, {Addr, Port, Data}) of
        true ->
          lager:info("RADIUS Worker already working on packet. Dropping."),
          inet:setopts(Sock, [{active, 1}]),
          {noreply, State};
        false ->
          lager:info("RADIUS Starting worker"),
          {ok, Pid}=radius_worker:start(radius_worker, {Addr, Port, Data, Sock}),
          case is_pid(Pid) of
            false -> NewState=State;
            true ->
              MonRef=monitor(process, Pid),
              NewML=MonList#{MonRef => {Pid, Sock}},
              NewState=State#{monitor_list := NewML}
          end,
          {noreply, NewState}
      end;
    _ ->
      lager:info("RADIUS Packet from unknown socket. Ignoring."),
      {noreply, State}
  end;

handle_info({'DOWN', _, process, Pid, noconnection}, State) ->
  %FIXME: Remove the monitored process from our list?
  lager:debug("RADIUS Connection to node with process ~w dropped", [Pid]),
  {noreply, State};
handle_info({'DOWN', MonRef, process, Pid, Reason}, State=#{monitor_list := MonList}) ->
  case maps:get(MonRef, MonList, undefined) of
    undefined ->
      lager:debug("RADIUS Got DOWN ~w for pid ~w that we have no record of.", [MonRef, Pid]),
      NewState=State;
    {Pid, Sock} ->
      inet:setopts(Sock, [{active, 1}]),
      case Reason of
        normal -> ok;
        shutdown -> ok;
        {shutdown, _} -> ok;
        %The noproc "reason" is for workers that terminate before we get to
        %monitor them.
        noproc -> ok;
        _ -> eradius_stats:worker_crashed(Pid)
      end,
      NewState=State#{monitor_list := maps:remove(MonRef, MonList)}
  end,
  {noreply, NewState};
%We can safely ignore this.
handle_info({udp_passive, Sock}, State=#{udp_sock := Sock}) ->
  {noreply, State};
handle_info({udp_passive, Sock}, State=#{acc_sock := Sock}) ->
  {noreply, State}.

insertWorkEntry(Mod, Key, Status, Pid) ->
  Now=erlang:monotonic_time(),
  WK={Mod, Key},
  WV={Pid, Status, Now},
  case ets:insert_new(workTableName(), {WK, WV}) of
    true -> ok;
    false -> {error, duplicate_key}
  end.

getWorkEntry(Mod, Key) ->
  WK={Mod, Key},
  case ets:lookup(workTableName(), WK) of
    [{_, {Pid, Status, _}}] -> {ok, {Pid, Status}};
    [] -> {error, work_entry_not_found};
    [_|_] -> {error, many_entries_found}
  end.

isWorkEntry(Mod, Key) ->
  WK={Mod, Key},
  ets:member(workTableName(), WK).

%Used to update the timestamp and/or status for a work entry.
updateWorkEntry(Mod, Key, Status, Pid) ->
  Now=erlang:monotonic_time(),
  WK={Mod, Key},
  WV={Pid, Status, Now},
  case ets:update_element(workTableName(), WK, {2, WV}) of
    true -> ok;
    false -> {error, work_entry_not_found}
  end.

deleteWorkEntry(Mod, Key) ->
  WK={Mod, Key},
  case ets:lookup(workTableName(), WK) of
    [{_, {_, _, _}}] ->
      ets:delete(workTableName(), WK),
      ok;
    [] -> {error, work_entry_not_found};
    [_|_] -> {error, many_entries_found}
  end.
%End work table management.

%FIXME: Might we want to check to see if the State value that we cook up
%       corresponds to any of the State values that we already know about, to
%       ward against the case where our node fell over, but we have a NAS out
%       there that was in the middle of a conversation with us?
getNewStateData() ->
  %About unique_integer and Erlang External Term Format:
  %For numbers whose absolute value is larger than 2^31, one byte is used for sign
  %storage. On 64-bit systems, we seem to start with eight-byte signed numbers.
  %So, the size of State will be no larger than nine bytes for (best case)
  %2^48 RADIUS conversations. When we hit that limit one byte will be added and
  %we'll get (best case) 2^New-2^(New-1) more RADIUS conversations before we
  %resize State.
  %
  %However, the documentation for unique_integer talks about there being
  %NUM_SCHEDULERS+1 pools, each pool containing (2^64)-1 unique integers.
  %So, while I can put a lower bound on the size of State, I can't really
  %put a good upper bound on it.
  %However, it seems likely that State will be no larger than nine bytes for
  %a _very_ long time.
  Int=erlang:unique_integer(),
  Raw=erlang:term_to_binary(Int),
  trimErlangTags(Raw).

%This scrapes off tags and size info from external term format integers:
trimErlangTags(<<131, 97, Num/binary>>) -> Num;
trimErlangTags(<<131, 98, Num/binary>>) -> Num;
trimErlangTags(<<131, 110, _:1/bytes, Num/binary>>) -> Num;
trimErlangTags(<<131, 111, _:4/bytes, Num/binary>>) -> Num.

%FIXME: This belongs in a utility module.
bin_to_hex(Bin) when is_binary(Bin) ->
  lists:flatten(
    [io_lib:format("~2.16.0B", [X]) || X <- binary_to_list(Bin)]).

determineWhatToDo(#{eap_message := _}) -> eradius_eap;
determineWhatToDo(#{}) -> unknown.

createTables() ->
  %work_table is a set because its keys should never collide.
  ets:new(workTableName(), [named_table, public, set]),
  %FIXME: Determine what the tx_table key should be and its storage type.
  ets:new(txTableName(), [named_table, public, duplicate_bag]).

terminate(_, #{udp_sock := Sock}) ->
  radius_sock:release_ownership(Sock);
terminate(_,_) -> ok.

handle_call(_, _, State) -> {noreply, State}.
handle_cast(_, State) -> {noreply, State}.

code_change(_, State, _) -> {ok, State}.

