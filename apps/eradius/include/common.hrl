%%NOTE: rustyio/sync won't pick up changes to .hrl files (2016-10-03)
%%      so if you change this file you have to bounce the server.

-type eradius_auth() :: binary().
-type eradius_id() :: pos_integer().
-type eradius_state() :: binary().
-type eradius_attrs() :: map().

-record(eradius_rad, {ip :: inet:ip_address(), port :: inet:port_number()
                      ,auth :: eradius_auth(), id :: eradius_id()
                      ,originalPacket :: binary(), state :: eradius_state()
                      ,attrs=#{} :: eradius_attrs()}).

-type eradius_raw_code() :: pos_integer().
%%FIXME: We might just want this type to be atom()
-type eradius_raw_requestType() :: 'access_request' | 'access_accept' |
        'access_reject' | 'accounting_request' | 'accounting_response' |
        'access_challenge' | 'status_server' | 'unrecognized'.
-type eradius_raw_length() :: pos_integer().
-type eradius_raw_attrs() :: binary().

-record(eradius_rad_raw, {code :: eradius_raw_code()
                          ,type :: eradius_raw_requestType()
                          ,id :: eradius_id(), length :: eradius_raw_length()
                          ,auth :: eradius_auth(), attrs :: eradius_raw_attrs()}).

-type eradius_eap_code() :: 'request' | 'response' | 'success' | 'failure'.
-type eradius_eap_id() :: pos_integer().
-type eradius_eap_length() :: pos_integer().
%%FIXME: This might need to change once we start handling expanded types.
-type eradius_eap_auth_type() :: atom().
-type eradius_eap_typedata() :: binary().

-record(eradius_eap, {code :: eradius_eap_code(), id :: eradius_eap_id()
                     ,length :: eradius_eap_length(), type :: eradius_eap_auth_type()
                     ,typedata :: eradius_eap_typedata()}).

-record(eradius_rad_handler_ret, {code :: eradius_raw_requestType(), attrs=#{} :: eradius_attrs()}).

%Used by the eradius_cleaner to politely shutdown a stale worker
-define(ERADIUS_CLEANER_EXIT, {shutdown, eradius_cleaner_reap}).
