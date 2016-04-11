-module(eradius_app).
-behavior(application).
-behavior(supervisor).

-export([startOneshot/1, startOneshot/3]).
-export([getName/0]).
-export([start/0, stop/0, restart/0]).
%Housekeeping stuff.
-export([createChild/1]).
-export([init/1]).
-export([start/2, stop/1]).
-export([startRest/0]).

startOneshot(M, F, A) ->
  startOneshot({M, F, A}).
startOneshot(MFA={_,_,_}) ->
  supervisor:start_child(getName(),
                         #{id => make_ref()
                           ,start => {?MODULE, createChild, [MFA]}
                           ,restart => temporary}).

createChild({M, F, A}) ->
  Pid=spawn_link(M, F, A),
  {ok, Pid}.

getName() ->
  eradius_app.

start() ->
  application:ensure_all_started(eradius).

stop() ->
  application:stop(eradius).

start(_, _) ->
  supervisor:start_link({local, getName()}, ?MODULE, []).

stop(_) ->
  ok.

restart() ->
  application:stop(eradius),
  application:ensure_all_started(eradius).

%This starts the RADIUS server and friends.
startRest() ->
  supervisor:start_link({local, eradius_sup}, eradius_sup, []).

init([]) ->
  {ok, {{rest_for_one, 5, 10}, [
                                %We do this because if the radius_sock server
                                %crashes, our UDP socket gets recreated.
                               #{id => radius_sock:getName()
                                 ,start => {radius_sock, start_link, []}}
                               ,#{id => eradius_sup
                                  ,type => supervisor
                                  ,shutdown => infinity
                                  ,start => {?MODULE, startRest, []}}
                              ]}}.
