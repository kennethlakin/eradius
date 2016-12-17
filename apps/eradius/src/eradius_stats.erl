-module(eradius_stats).

-behavior(gen_server).

-compile([{parse_transform, lager_transform}]).

%Public API
-export([worker_start/1, worker_stop/1, worker_crashed/1, accounting_request/2, start_link/0]).
%gen_server stuff:
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
%Housekeeping
-export([getName/0]).

worker_start(Pid) ->
  Now=erlang:monotonic_time(),
  gen_server:cast(getName(), {worker_start, Pid, Now}).

worker_stop(Pid) ->
  Now=erlang:monotonic_time(),
  gen_server:cast(getName(), {worker_stop, Pid, Now}).

worker_crashed(Pid) ->
  gen_server:cast(getName(), {worker_crashed, Pid}).

accounting_request(Addr, Attrs) ->
  gen_server:cast(getName(), {accounting_request, Addr, Attrs}).

start_link() ->
  gen_server:start_link({local, getName()}, ?MODULE, [], []).

getName() -> ?MODULE.

init(_) ->
  {ok, #{job_duration => #{}}}.

handle_cast({worker_start, Pid, Time}, State=#{job_duration := JobMap}) ->
  {noreply, State#{job_duration := JobMap#{Pid => Time}}};
handle_cast({worker_stop, Pid, Stop}, State=#{job_duration := JobMap}) ->
  case maps:get(Pid, JobMap, 'NOTTHERE') of
    'NOTTHERE' ->
      lager:debug("ERADIUS_STATS Stop called for unknown pid ~w", [Pid]);
    Start ->
      Elapsed=erlang:convert_time_unit(Stop-Start, native, microsecond),
      %FIXME: Record stats or whatever.
      lager:debug("RADIUS Worker ~w done. Total time taken ~wus", [Pid, Elapsed])
  end,
  NewJM=maps:remove(Pid, JobMap),
  {noreply, State#{job_duration := NewJM}};
handle_cast({worker_crashed, Pid}, State=#{job_duration := JobMap}) ->
  NewJM=maps:remove(Pid, JobMap),
  {noreply, State#{job_duration := NewJM}};
handle_cast({accounting_request, Addr, Attrs}, State) ->
  lager:info("ERADIUS_STATS Accounting-Request recieved from NAS ~w. Attrs ~p", [Addr, Attrs]),
  {noreply, State}.

handle_call(Msg, _, State) ->
  {reply, {error, {unexpected, Msg}}, State}.
handle_info(_, State) -> {noreply, State}.

terminate(_,_) -> ok.
code_change(_, State, _) -> {ok, State}.
