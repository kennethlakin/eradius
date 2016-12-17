-module(eradius_preprocess).

-behavior(gen_server).

-callback preprocess(NasIp :: inet:ip_address(), Attrs :: map()) -> {ok, map()} | {error, term()}.
%It is expected that clients will call some variant of start_link unless there
%is no state to be maintained, in which case 'ignore' is returned.
-callback start_module() -> {ok, Pid :: pid()} | {ok, Pid :: pid(), Info :: term()}
                            | {error, Err :: term()} | ignore.
-callback reload() -> ok | {error, Err :: term()}.
-callback getName() -> term().

-export([preprocess/2, start_module/0, reload/0]).
%Housekeeping interface:
-export([getName/0, start_link/0]).
%gen_server stuff:
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-compile([{parse_transform, lager_transform}]).

-define(mod_table, eradius_preprocess_modules).

start_module() -> {error, not_a_preprocess_module}.

reload() -> gen_server:call(getName(), reload, infinity).

getName() ->
  eradius_preprocess_srv.

start_link() ->
  gen_server:start_link({local, getName()}, ?MODULE, [], []).

init([]) ->
  {ok, App}=application:get_application(),
  PreprocessMods=application:get_env(App, preprocess_mods, []),
  ets:new(?mod_table, [named_table, {read_concurrency, true}]),
  ets:insert(?mod_table, {mods, PreprocessMods}),

  self() ! start_children,
  {ok, #{mods => PreprocessMods}}.

handle_info(start_children, State=#{mods := Mods}) ->
  lists:foreach(fun(M) ->
                    case eradius_preprocess_sup:start_mod(M) of
                      {error, Err} ->
                        lager:warning("ERADIUS_PREPROCESS Error starting mod ~w: '~p'", [M, {error, Err}]);
                      _ -> ok
                    end
                end, Mods),
  {noreply, State};
handle_info(_, State) -> {noreply, State}.

preprocess(NasIp, Attrs) ->
  [{_, Mods}]=ets:lookup(?mod_table, mods),
  Ret=
    lists:foldl(fun(M, A) ->
                    case M:preprocess(NasIp, A) of
                      {ok, NewAttrs} -> NewAttrs;
                      R ->
                        lager:warning("ERADIUS_PREPROCESS Module ~w returned '~w' during preprocess", [M, R]),
                        A
                    end
                end, Attrs, Mods),
  {ok, Ret}.

handle_call(reload, _, State=#{mods := Mods}) ->
  lists:foreach(
    fun(Mod) ->
        case Mod:reload() of
          ok -> ok;
          R -> lager:warning("ERADIUS_PREPROCESS Module ~p returned '~p' during reload", [Mod, R])
        end
    end, Mods),
  {reply, ok, State}.

handle_cast(_, State) -> {noreply, State}.
terminate(_,_) -> ok.
code_change(_,State,_) -> {ok, State}.
