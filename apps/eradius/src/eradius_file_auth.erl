-module(eradius_file_auth).
-behavior(eradius_auth).
-behavior(gen_server).

-compile([{parse_transform, lager_transform}]).

%eradius_auth stuff:
-export([start_module/0, getName/0, lookup_nas/1, lookup_nas/2
         ,lookup_user/1, lookup_user/2, reload/0]).
%gen_server stuff:
-export([init/1, handle_call/3, handle_cast/2, handle_info/2
         ,terminate/2, code_change/3]).

start_module() ->
  gen_server:start_link({local, getName()}, ?MODULE, [], []).

%@Returns {ok, NasSecret} | {error, not_found}
lookup_nas(Nas) ->
  lookup_nas(Nas, #{}).
lookup_nas(Nas, Attrs) ->
  gen_server:call(getName(), {lookup, nas, Nas, Attrs}).

%@Returns {ok, Credential, SuccessAttrs} | {ok, [Credentials], SuccessAttrs} |
%         {error, not_found}
lookup_user(User) ->
  lookup_user(User, #{}).
lookup_user(User, Attrs) ->
  gen_server:call(getName(), {lookup, user, User, Attrs}).

reload() ->
  gen_server:call(getName(), reload).

getName() ->
  ?MODULE.

init([]) ->
  try
    case loadCredentials() of
      R={ok, _} -> R;
      Err -> {stop, {credential_file_load_fail, Err}}
    end
  catch
    E -> {stop, {credential_file_load_fail, E}};
    X:Y -> {stop, {credential_file_load_fail, X, Y}}
  end.

handle_call({lookup, nas, Key, _Attrs}, _, State) ->
  #{nas := List}=State,
  case lists:keyfind(Key, 1, List) of
    false ->
      {reply, {error, not_found}, State};
    {Key, Credential} ->
      {reply, {ok, Credential}, State}
  end;
handle_call({lookup, user, Key, Attrs}, _, State) ->
  %FIXME: Move default attrs into auth server state.
  DefaultAttrs=#{idle_timeout => [10]},
  #{user := List}=State,
  case lists:keyfind(Key, 1, List) of
    false ->
      {reply, {error, not_found}, State};
    {Key, Credential, RestrictAttrs, SuccessAttrs} ->
      case passesRestrictions(RestrictAttrs, Attrs) of
        %FIXME: This should be {error, not_authorized}, maybe.
        false -> {reply, {error, not_found}, State};
        true ->
          %FIXME: Need to add optional failure attrs, which also get merged in with
          %       the default attrs.
          RetAttrs=maps:merge(DefaultAttrs, SuccessAttrs),
          {reply, {ok, Credential, RetAttrs}, State}
      end
  end;

handle_call(reload, _, State) ->
  try
    case loadCredentials() of
      {ok, NewState} ->
        {reply, ok, NewState};
      Err ->
        lager:error("ERADIUS_FILE_AUTH error while reloading credentials ~p", [Err]),
        {reply, Err, State}
    end
  catch
    E ->
      lager:error("ERADIUS_FILE_AUTH Critical error while reloading credentials ~p", [E]),
      {reply, {error, E}, State};
    X:Y ->
      lager:error("ERADIUS_FILE_AUTH Critical error while reloading credentials ~p:~p", [X,Y]),
      {reply, {error, {X,Y}}, State}
  end.

passesRestrictions(RestrictAttrs, Attrs) when is_map(Attrs) ->
  passesRestrictions(RestrictAttrs, maps:to_list(Attrs));
passesRestrictions({L, a, R}, Attrs) ->
  passesRestrictions(L, Attrs) == true andalso
  passesRestrictions(R, Attrs) == true;
passesRestrictions({L, o, R}, Attrs) ->
  passesRestrictions(L, Attrs) == true orelse
  passesRestrictions(R, Attrs) == true;
passesRestrictions(Ref, Attrs) ->
  areAttrsASuperset(Ref, Attrs).

%NOTE:
%This will be fine if there are not many attributes. Given that -in the
%overwhelmingly common case- MTU is 1500 bytes, there can be (at most)
%500 attributes. 250k compares is probably hefty, but we're never gonna
%see that in practice. The _absolute_ worst case is 4096 byte packets, with
%~1.86m comparisons, but that would require jumbo frames, a NAS that actually
%makes use of them, and a packet entirely full of attributes.
areAttrsASuperset(Reference, Attrs) ->
  lists:subtract(Reference, Attrs) == [].

loadCredentials() ->
  %FIXME: Make this configurable and such.
  FileName="credentials",
  lager:info("ERADIUS_FILE_AUTH Attempting load of file ~p", [FileName]),
  case file:consult(FileName) of
    {ok, Result} ->
      case lists:keyfind(user, 1, Result) of
        {user, UserList} ->
          case lists:keyfind(nas, 1, Result) of
            {nas, NasList} ->
              ConvU=lists:map(fun convertUser/1, UserList),
              ConvN=lists:map(fun convertNas/1, NasList),
              lager:info("ERADIUS_FILE_AUTH Load of file ~p successful", [FileName]),
              {ok, #{user => ConvU, nas => ConvN}};
            false ->
              {error, nas_list_not_present}
          end;
        false ->
          {error, user_list_not_present}
      end;
    {error, E} ->
      {error, file:format_error(E)}
  end.

convertUser({U, P}) ->
  convertUser({U, P, {}, #{}});
convertUser({U, P, SuccessAttrs}) when is_map(SuccessAttrs) ->
  convertUser({U, P, {}, SuccessAttrs});
convertUser({U, P, RestrictAttrs}) when is_tuple(RestrictAttrs) ->
  convertUser({U,P, RestrictAttrs, #{}});
%Flip position of last two args if they were mispositioned:
convertUser({U, P, SuccessAttrs, RestrictAttrs}) when
    is_map(SuccessAttrs), is_tuple(RestrictAttrs) ->
  convertUser({U, P, RestrictAttrs, SuccessAttrs});
convertUser({U, P, RestrictAttrs, SuccessAttrs}) ->
  {erlang:iolist_to_binary(U), erlang:iolist_to_binary(P)
   ,convertRestrictAttrs(RestrictAttrs), SuccessAttrs}.

%A restriction can take the form:
% {} | map() | {(map()|restriction()), (a|o), (map()|restriction())}
convertRestrictAttrs({}) -> maps:to_list(#{});
%For the case where we only want to compare against a single
%set of attributes:
convertRestrictAttrs({V}) ->
  convertRestrictAttrs(V);
convertRestrictAttrs({L, Op, R}) ->
  {convertRestrictAttrs(L), Op, convertRestrictAttrs(R)};
convertRestrictAttrs(V) ->
  NewV=normalizeMacAddrs(V),
  maps:to_list(NewV).

convertNas({N, S}) ->
  {ok, A}=inet:parse_address(N),
  {A, erlang:iolist_to_binary(S)}.

%% RFC3580 (3.20 and 3.21) says that
%% "Supplicant MAC address [are stored] in ASCII format
%% (upper case only), with octet values separated by a "-""
%% for attributes Called-Station-Id Calling-Station-Id.
%FIXME: Normalize Called-Station-Id MAC address as well.
normalizeMacAddrs(RestrictAttrs=#{calling_station_id := CSI}) ->
  NewCSI=eradius_utils:normalizeMacAddr(CSI),
  RestrictAttrs#{calling_station_id := NewCSI};
normalizeMacAddrs(RestrictAttrs) -> RestrictAttrs.

handle_info(_,State) -> {noreply, State}.
handle_cast(_, State) -> {noreply, State}.
terminate(_,_) -> ok.
code_change(_,State,_) -> {ok, State}.
