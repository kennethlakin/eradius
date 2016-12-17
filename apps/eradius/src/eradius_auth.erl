-module(eradius_auth).

-behavior(gen_server).

-type nas_lookup_ret() :: {ok, NasSecret :: term()} | {error, not_found}.
-type user_lookup_ret() ::
  {ok, Credential :: term(), SuccessAttrs :: map()}
  | {ok, Credentials :: list(), SuccessAttrs :: map()}
  | {error, not_found}.

-callback lookup_nas(Nas :: term())                  -> nas_lookup_ret().
-callback lookup_nas(Nas :: term(), Attrs :: map())  -> nas_lookup_ret().
-callback lookup_user(User:: term())                 -> user_lookup_ret().
-callback lookup_user(User:: term(), Attrs :: map()) -> user_lookup_ret().

%It is expected that clients will call some variant of start_link unless there
%is no state to be maintained, in which case 'ignore' is returned.
-callback start_module() -> {ok, Pid :: pid()} | {ok, Pid :: pid(), Info :: term()}
                            | {error, Err :: term()} | ignore.
-callback reload() -> ok | {error, Err :: term()}.
-callback getName() -> term().

%Public interface:
-export([lookup_nas/1, lookup_nas/2, lookup_user/1, lookup_user/2, start_module/0, reload/0]).
%Housekeeping interface:
-export([getName/0, start_link/0]).
%gen_server stuff:
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-compile([{parse_transform, lager_transform}]).

-define(mod_table, eradius_auth_modules).

lookup_nas(Nas) ->
  lookup_nas(Nas, #{}).
lookup_nas(Nas, Attrs) ->
  [{_, NasMods}]=ets:lookup(?mod_table, nas_mods),
  doNasLookup(Nas, Attrs, NasMods).

lookup_user(User) ->
  lookup_user(User, #{}).
lookup_user(User, Attrs) ->
  [{_, UserMods}]=ets:lookup(?mod_table, user_mods),
  doUserLookup(User, Attrs, UserMods).

%This isn't actually an auth module, so...
start_module() -> {error, not_an_auth_module}.

reload() ->
  gen_server:call(getName(), reload, infinity).

getName() ->
  eradius_auth_srv.

start_link() ->
  gen_server:start_link({local, getName()}, ?MODULE, [], []).

init([]) ->
  {ok, App}=application:get_application(),
  NasMods=application:get_env(App, nas_lookup_mods, []),
  UserMods=application:get_env(App, user_lookup_mods, []),
  N=lists:usort(NasMods),
  U=lists:usort(UserMods),
  MergedMods=lists:umerge(N, U),
  ets:new(?mod_table, [named_table, {read_concurrency, true}]),
  ets:insert(?mod_table, {nas_mods, NasMods}),
  ets:insert(?mod_table, {user_mods, UserMods}),

  self() ! start_children,
  {ok, #{merged_mods => MergedMods}}.

handle_info(start_children, State=#{merged_mods := Mods}) ->
  lists:foreach(fun(M) ->
                    case eradius_auth_sup:start_mod(M) of
                      {error, Err} ->
                        lager:warning("ERADIUS_AUTH Error starting mod ~p: '~p'", [M, {error, Err}]);
                      _ -> ok
                    end
                end, Mods),
  {noreply, State};
handle_info(_,State) -> {noreply, State}.

%%FIXME: Find a better way to signal when a module's reload fails.
handle_call(reload, _, State=#{merged_mods := Mods}) ->
  lists:foreach(
    fun(Mod) ->
        case Mod:reload() of
          ok -> ok;
          R -> lager:warning("ERADIUS_AUTH Module ~p returned '~p' during reload", [Mod, R])
        end
    end, Mods),
  {reply, ok, State}.

doNasLookup(_, _, []) ->
  {error, not_found};
doNasLookup(Key, Attrs, [Mod|Rest]) ->
  case Mod:lookup_nas(Key, Attrs) of
    {error, not_found} -> doNasLookup(Key, Attrs, Rest);
    Ret -> Ret
  end.

doUserLookup(_, _, []) ->
  {error, not_found};
doUserLookup(Key, Attrs, [Mod|Rest]) ->
  case Mod:lookup_user(Key, Attrs) of
    {error, not_found} -> doUserLookup(Key, Attrs, Rest);
    Ret -> Ret
  end.


handle_cast(_, State) -> {noreply, State}.
terminate(_,_) -> ok.
code_change(_,State,_) -> {ok, State}.

