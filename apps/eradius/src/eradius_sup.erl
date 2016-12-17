-module(eradius_sup).

-export([init/1]).

-behavior(supervisor).

init([]) ->
  %FIXME: Make this configurable!!
  CleanerTimeout=30000,
  {ok, {{one_for_one, 5, 10}, [
                               #{id => tls_udp:getName()
                                  ,start => {tls_udp, start_link, []}}
                               ,#{id => eradius_tx:getName()
                                  ,start => {eradius_tx, start_link, []}}
                               ,#{id => eradius_auth_sup:getName()
                                  ,start => {eradius_auth_sup, start_link, []}}
                               ,#{id => eradius_preprocess_sup:getName()
                                  ,start => {eradius_preprocess_sup, start_link, []}}
                               ,#{id => eradius_stats:getName()
                                  ,start => {eradius_stats, start_link, []}}
                               ,#{id => eradius_cleaner:getName()
                                  ,start => {eradius_app, createChild, [{eradius_cleaner, loop, [CleanerTimeout]}]}}
                               ,#{id => radius_server_sup:getName()
                                  ,start => {radius_server_sup, start_link, []}
                                  ,type => supervisor
                                  ,shutdown => infinity}
                              ]}}.
