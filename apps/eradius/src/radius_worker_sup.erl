-module(radius_worker_sup).

-export([getName/0, init/1, start_link/0]).

-behavior(supervisor).

start_link() ->
  supervisor:start_link({local, getName()}, ?MODULE, []).
  
getName() ->
  eradius_radius_worker_sup.

init([]) ->
  {ok, {{simple_one_for_one, 1000, 1}, [#{ id => radius_worker
                                         ,start => {radius_worker, start_link, []}
                                         ,restart => temporary}
                                     ]}}.
