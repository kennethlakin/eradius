-module(cache_cleaner).

-include_lib("stdlib/include/ms_transform.hrl").

-export([loop/1]).
-export([getName/0]).

getName() ->
  eradius_cache_cleaner.

loop(Timeout) ->
  timer:sleep(Timeout),
  cleanTables(),
  clearQueue(),
  ?MODULE:loop(Timeout).

clearQueue() ->
  receive _ -> clearQueue()
  after 0 -> ok
  end.

cleanTables() ->
  %Only clean out old cached transmitted data for now.
  ThresholdTime=erlang:monotonic_time()-erlang:convert_time_unit(30, seconds, native),
  TimeSelect=ets:fun2ms(fun({Time, _}) when Time < ThresholdTime -> true end),
  TxSelect=ets:fun2ms(fun({_, {_, Time}}) when Time < ThresholdTime -> true end),

  ets:select_delete(radius_server:txTableTimeName(), TimeSelect),
  ets:select_delete(radius_server:txTableName(), TxSelect),
  ok.
