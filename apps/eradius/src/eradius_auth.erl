-module(eradius_auth).

-behavior(gen_server).

%Public interface:
-export([lookup_nas/1, lookup_user/1, reload/0]).

-export([getName/0, start_link/0, init/1, handle_call/3
         ,handle_cast/2, handle_info/2, terminate/2
         ,code_change/3]).

-compile([{parse_transform, lager_transform}]).

lookup_nas(Nas) ->
  gen_server:call(getName(), {lookup, nas, Nas}).

lookup_user(User) ->
  gen_server:call(getName(), {lookup, user, User}).

reload() ->
  gen_server:call(getName(), reload).

getName() ->
  eradius_auth_srv.

start_link() ->
  gen_server:start_link({local, getName()}, ?MODULE, [], []).

init([]) ->
  case loadCredentials() of
    {ok, State} ->
      {ok, State};
    Err ->
      {stop, {credential_file_load_fail, Err}}
  end.

handle_call({lookup, Type, Key}, _, State) ->
  case Type of
    nas ->
      #{nas := List} = State;
    user ->
      #{user := List} = State
  end,
  case lists:keyfind(Key, 1, List) of
    false ->
      {reply, {error, not_found}, State};
    {Key, Credential} ->
      {reply, {ok, Credential}, State}
  end;

handle_call(reload, _, State) ->
  try
    case loadCredentials() of
      {ok, NewState} ->
        {reply, ok, NewState};
      Err ->
        {reply, Err, State}
    end
  catch
    E -> 
      lager:error("ERADIUS_AUTH Critical error while reloading credentials ~p", [E]),
      {reply, {error, E}, State};
    X:Y -> 
      lager:error("ERADIUS_AUTH Critical error while reloading credentials ~p:~p", [X,Y]),
      {reply, {error, {X,Y}}, State}
  end.

loadCredentials() ->
  %FIXME: Make this configurable and such.
  FileName="credentials",
  lager:info("ERADIUS_AUTH Attempting load of file ~p", [FileName]),
  case file:consult(FileName) of
    {ok, Result} ->
      case lists:keyfind(user, 1, Result) of
        {user, UserList} ->
          case lists:keyfind(nas, 1, Result) of
            {nas, NasList} ->
              ConvU=lists:map(fun convertUser/1, UserList),
              ConvN=lists:map(fun convertNas/1, NasList),
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
  {erlang:iolist_to_binary(U), erlang:iolist_to_binary(P)}.

convertNas({N, S}) ->
  {ok, A}=inet:parse_address(N),
  {A, erlang:iolist_to_binary(S)}.

handle_cast(_, State) -> {noreply, State}.
terminate(_,_) -> ok.
handle_info(_,_) -> ok.
code_change(_,State,_) -> {ok, State}.
