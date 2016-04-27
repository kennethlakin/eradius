-module(eradius_sup).

-export([init/1]).

-behavior(supervisor).

init([]) ->
  %FIXME: Make this configurable!!
  CacheCleanerTimeout=30000,
  {ok, {{one_for_one, 5, 10}, [
                               #{id => tls_udp:getName()
                                  ,start => {tls_udp, start_link, []}}
                               ,#{id => radius_tx:getName()
                                  ,start => {radius_tx, start_link, []}}
                               ,#{id => eradius_auth:getName()
                                  ,start => {eradius_auth, start_link, []}}
                               ,#{id => cache_cleaner:getName()
                                  ,start => {eradius_app, createChild, [{cache_cleaner, loop, [CacheCleanerTimeout]}]}}
                               ,#{id => radius_server_sup:getName()
                                  ,start => {radius_server_sup, start_link, []}
                                  ,type => supervisor
                                  ,shutdown => infinity}
                              ]}}.
