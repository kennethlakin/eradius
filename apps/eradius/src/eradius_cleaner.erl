-module(eradius_cleaner).

-include_lib("stdlib/include/ms_transform.hrl").
-include_lib("eradius/include/common.hrl").

-export([loop/1, loop/2]).
-export([getName/0]).

getName() ->
  eradius_cleaner.

loop(Timeout) ->
  loop(Timeout, Timeout).
loop(Timeout, Target) ->
  timer:sleep(Timeout),
  Start=erlang:monotonic_time(millisecond),
  cleanTables(Target),
  clearQueue(),
  Stop=erlang:monotonic_time(millisecond),
  SleepTime=max(Target-(Stop-Start), 0),
  ?MODULE:loop(SleepTime, Target).

clearQueue() ->
  receive _ -> clearQueue()
  after 0 -> ok
  end.

cleanTables(TargetTime) ->
  ThresholdTime=erlang:monotonic_time()-erlang:convert_time_unit(TargetTime, millisecond, native),
  TxSelect=ets:fun2ms(fun({_, {_, Time}}) when Time < ThresholdTime -> true end),
  DoneWorkerSelect=ets:fun2ms(
                     fun({_, {_, Status, Time}}) when
                           (Status == done orelse Status == crashed)
                           andalso Time < ThresholdTime -> true end),
  StaleWorkerPidSelect=ets:fun2ms(
                         fun({_, {Pid, waiting, Time}}) when
                               Time < ThresholdTime -> Pid end),
  StaleWorkerDeleteSelect=ets:fun2ms(
                            fun({_, {_, waiting, Time}}) when
                                  Time < ThresholdTime -> true end),

  ets:select_delete(radius_server:txTableName(), TxSelect),
  ets:select_delete(radius_server:workTableName(), DoneWorkerSelect),
  StaleWorkers=ets:select(radius_server:workTableName(), StaleWorkerPidSelect),
  ets:select_delete(radius_server:workTableName(), StaleWorkerDeleteSelect),

  lists:foreach(fun(Pid) ->
                    monitor(process, Pid),
                    exit(Pid, ?ERADIUS_CLEANER_EXIT)
                end, StaleWorkers),
  StuckWorkers=waitPids(StaleWorkers),
  lists:foreach(fun(Pid) ->
                    exit(Pid, kill)
                end, StuckWorkers),
  ok.

waitPids([]) -> [];
waitPids(PidList) ->
  receive
    {'DOWN', _, process, Pid, _} ->
      waitPids(lists:delete(Pid, PidList))
  after 5000 -> PidList
  end.
