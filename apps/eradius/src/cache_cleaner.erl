-module(cache_cleaner).

-compile([{parse_transform, lager_transform}]).

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
  %FIXME: Actually clean.
  ok.
