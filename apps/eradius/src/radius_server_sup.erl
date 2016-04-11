-module(radius_server_sup).

-export([getName/0, start_link/0, init/1]).
-behavior(supervisor).

getName() ->
  eradius_radius_server_sup.

start_link() ->
  supervisor:start_link({local, getName()}, ?MODULE, []).

init([]) ->
  %FIXME: Tune the strat/intensity values.
  {ok, {{one_for_all, 5, 10}, [
                               #{id => radius_server:getName()
                                 ,start => {radius_server, start_link, []}
                                }
                               ,#{id => radius_worker_sup:getName()
                                  ,type => supervisor
                                  ,shutdown => infinity
                                  ,start => {radius_worker_sup, start_link, []} 
                                 }
                              ]}}.
