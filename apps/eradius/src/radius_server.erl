-module(radius_server).

-compile([{parse_transform, lager_transform}]).
-compile(export_all).

-behavior(gen_server).

getName() ->
  eradius_radius_server.

workTableName() ->
  eradius_work_table.

workTableTimeName() ->
  eradius_work_table_time.

txTableName() ->
  eradius_tx_table.

txTableTimeName() ->
  eradius_tx_table_time.

start_link() ->
  gen_server:start_link({local, getName()}, ?MODULE, [], []).

init(_) ->
  process_flag(trap_exit, true),
  Schedulers=erlang:system_info(schedulers),
  createTables(),
  UdpSock=radius_sock:get_sock(),
  ok=radius_sock:take_ownership(UdpSock),
  %First switch to passive mode so that in case of starting back up after a
  %crash we're sure that we have at most a queue of length Schedulers.
  %FIXME: Consider looking at the read_packets option.
  inet:setopts(UdpSock, [{active, false}]),
  inet:setopts(UdpSock, [{active, Schedulers}]),
  lager:info("RADIUS Initialized with ~p workers", [Schedulers]),
  {ok, #{udp_sock => UdpSock, num_schedulers => Schedulers}}.

%FIXME: Useful RFCS:
%       2865 5080 (RADIUS and RADIUS implementation lessons.)
%       3579 3748 (EAP and EAP-RADIUS)
%       2433 (MSCHAPv1)
%       2759 draft-kamath-pppext-eap-mschapv2-02 (MSCHAPv2)
%             (NOTE: SHAInit/Update/Final are crypto:hash_init/update/final)
%       1994 (for PPP-CHAP, which is required to understand EAP-MD5 as well as
%             MSCHAP and MSCHAPv2)
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

handle_cast({done, ElapsedTime}, State=#{udp_sock := Sock}) ->
  inet:setopts(Sock, [{active, 1}]),
  lager:info("RADIUS Worker done. total time taken ~pus",
             [erlang:convert_time_unit(ElapsedTime, native, micro_seconds)]),
  {noreply, State}.

handle_info({udp, Sock, Addr, Port, Data}, State=#{udp_sock := Sock}) ->
  T1=erlang:monotonic_time(),
  case isWorkEntry(radius_worker, {Addr, Port, Data}) of
    true ->
      lager:info("RADIUS Worker already working on packet. Dropping."),
      inet:setopts(Sock, [{active, 1}]),
      {noreply, State};
    false ->
      lager:info("RADIUS Starting worker"),
      {ok, _}=radius_worker:start(radius_worker, {Addr, Port, Data, T1}),
      {noreply, State}
  end;
%If all of our workers are busy, our socket falls into passive mode, and we get
%this message. It can be safely ignored.
handle_info({udp_passive, Sock}, State=#{udp_sock := Sock}) ->
  lager:debug("RADIUS All workers busy"),
  {noreply, State}.

%FIXME: Make these configurable.
nas_secret(_) ->
  <<"password">>.
user_password(_) ->
  <<"pass">>.

%Work table management:
insertWorkEntry(Mod, Key, Status, Pid) ->
  Now=erlang:monotonic_time(),
  WK={Mod, Key},
  WV={Pid, Status, Now},
  TK=Now,
  TV=WK,
  case ets:insert_new(workTableName(), {WK, WV}) of
    true ->
      ets:insert(workTableTimeName(), {TK, TV}),
      ok;
    false ->
      {error, duplicate_key}
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
  TK=Now,
  TV=WK,
  %Get the TS so that we can remove the old time entry.
  case ets:lookup(workTableName(), WK) of
    [{_, {_, _, TS}}] ->
      %Remove the old entry from the timestamp table.
      ets:delete_object(workTableTimeName(), {TS, WK}),
      ets:insert(workTableName(), {WK, WV}),
      ets:insert(workTableTimeName(), {TK, TV}),
      ok;
    [] -> {error, work_entry_not_found};
    [_|_] -> {error, many_entries_found}
  end.

deleteWorkEntry(Mod, Key) ->
  WK={Mod, Key},
  case ets:lookup(workTableName(), WK) of
    [{_, {_, _, TS}}] ->
      ets:delete(workTableName(), WK),
      ets:delete_object(workTableTimeName(), {TS, WK}),
      ok;
    [] -> {error, work_entry_not_found};
    [_|_] -> {error, many_entries_found}
  end.
%End work table management.


newStateAttr() ->
  Data=getNewStateData(),
  Len=byte_size(Data)+2,
  <<24, Len/integer, Data/binary>>.

%FIXME: Might we want to check to see if the State value that we cook up
%       corresponds to any of the State values that we already know about, to
%       ward against the case where our node fell over, but we have a NAS out
%       there that was in the middle of a conversation with us?
getNewStateData() ->
  Int=erlang:unique_integer(),
  Raw=erlang:term_to_binary(Int),
  trimErlangTags(Raw).

%This scrapes off tags and size info from external term format integers:
trimErlangTags(<<131, 97, Num/binary>>) -> Num;
trimErlangTags(<<131, 98, Num/binary>>) -> Num;
trimErlangTags(<<131, 110, _:1/bytes, Num/binary>>) -> Num;
trimErlangTags(<<131, 111, _:4/bytes, Num/binary>>) -> Num.

%Called to turn a EAP-TLS-derived Master Key into an MS-MPPE-*-Key payload.
%From RFC 2548 sec 2.4.2
scramble_mppe_key(<<Key:32/bytes>>, {Ip,_,RadAuth,_,_,_}) ->
  NasSecret=radius_server:nas_secret(Ip),
  <<_:1, BaseSalt:15>> =crypto:rand_bytes(2),
  Salt= <<1:1,BaseSalt:15>>,
  Padding=binary:copy(<<0>>, 15),
  <<Plain:48/bytes>> = <<32, Key/binary, Padding/binary>>,
  <<Scrambled:48/bytes>> =startScramble(Plain, NasSecret, RadAuth, Salt),
  <<Salt/binary, Scrambled/binary>>.

startScramble(<<Plain:16/bytes, Rest/binary>>, Secret, RadAuth, Salt) ->
  B=crypto:hash(md5, <<Secret/binary, RadAuth/binary, Salt/binary>>),
  C=crypto:exor(Plain, B),
  doScramble(Rest, Secret, C, C).
doScramble(<<>>, _, _, Acc) -> Acc;
doScramble(<<Plain:16/bytes, Rest/binary>>, Secret, PrevChunk, Acc) ->
  B=crypto:hash(md5, <<Secret/binary, PrevChunk/binary>>),
  C=crypto:exor(Plain, B),
  doScramble(Rest, Secret, C, <<Acc/binary, C/binary>>).

%FIXME: This belongs in a utility module.
bin_to_hex(Bin) when is_binary(Bin) ->
  lists:flatten(
    [io_lib:format("~2.16.0B", [X]) || X <- binary_to_list(Bin)]).

determineWhatToDo(#{eap_message := _}) -> eap;
determineWhatToDo(#{}) -> unknown.

signalDone(ElapsedTime) when is_integer(ElapsedTime) ->
  gen_server:cast(getName(), {done, ElapsedTime}).

createTables() ->
  %work_table is a set because its keys should never collide.
  ets:new(workTableName(), [named_table, public, set]),
  %work_table_time is a dup_bag because its keys might collide. It's dup_bag
  %rather than bag so that we don't have the miniscule overhead of determining
  %if an object to be inserted already exists for the key. Because we're
  %storing work_table keys, we shouldn't have duplicate objects.
  ets:new(workTableTimeName(), [named_table, public, duplicate_bag]),
  %FIXME: Determine what the tx_table key should be and its storage type.
  ets:new(txTableName(), [named_table, public, duplicate_bag]),
  ets:new(txTableTimeName(), [named_table, public, duplicate_bag]).

terminate(_, #{udp_sock := Sock}) ->
  radius_sock:release_ownership(Sock);
terminate(_,_) -> ok.

handle_call(_, _, State) -> {noreply, State}.

code_change(_, State, _) -> {ok, State}.

