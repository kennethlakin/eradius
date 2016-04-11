EPMD_ADDRESS=ERL_EPMD_ADDRESS=""
NODE_NAME=eradius
MONITOR_NODE_NAME=eradius-observer
ERL_BASE=$(EPMD_ADDRESS) erl
BASE_ARGS=+C multi_time_warp +K true -name $(NODE_NAME) -mnesia dir "'db-$(NODE_NAME)'" -mnesia dump_log_write_threshold 1000

all:
	rebar3 compile

tags:
	ctags -R --languages=erlang .

start:
	ERL_FLAGS="$(BASE_ARGS)" rebar3 shell --apps eradius --config app.config

justload:
	ERL_FLAGS="$(BASE_ARGS)" rebar3 shell

monitor:
	$(ERL_BASE) -name $(MONITOR_NODE_NAME) -hidden -eval 'observer:start()'

distclean: clean

clean:
	rebar3 clean -a

#Because rebar3 auto doesn't yet take --apps args, we use the sync project.
#Major disadvantage of using sync is it doesn't understand rebar3 profiles,
#so its build location is hard-coded to _build/default/lib/eradius/ebin/
watch:
	ERL_FLAGS="$(BASE_ARGS)" rebar3 shell --apps eradius,sync --config app.config
