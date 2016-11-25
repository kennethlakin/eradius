-module(eradius_auth_sup).

-behavior(supervisor).

-export([start_auth_mod/1]).
%supervisor exports
-export([init/1]).
%Internal API
-export([getName/0, start_link/0]).


start_auth_mod(Mod) ->
  supervisor:start_child(getName(),
                         #{id => Mod:getName()
                           ,start => {Mod, start_module, []}
                           ,restart => permanent}).
getName() ->
  ?MODULE.

start_link() ->
  supervisor:start_link({local, getName()}, ?MODULE, []).

init(Args) ->
  {ok, {{one_for_one, 5, 10}, [
                               #{id => eradius_auth:getName()
                                 ,start => {eradius_auth, start_link, Args}}
                              ]}}.
