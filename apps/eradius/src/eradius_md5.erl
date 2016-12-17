-module(eradius_md5).

-export([handle/2]).

-compile([{parse_transform, lager_transform}]).
-include_lib("eradius/include/common.hrl").

handle({handle, Eap=#eradius_eap{id=Id, typedata=TypeData}
        ,Rad=#eradius_rad{}}
       ,PassedState=#{tx_credits := Credits
                      ,rad_attrs := RadAttrs
                      ,md5 := MethodData=#{ state := MethodState }})
  when Credits == 0 ->
  State=PassedState#{last_rad := Rad, last_eap := Eap},
  case MethodState of
    undefined ->
      Challenge=crypto:strong_rand_bytes(16),
      ChallengeLen=binary:encode_unsigned(byte_size(Challenge)),
      Data= <<4,ChallengeLen/binary,Challenge/binary>>,
      Pkt={access_challenge, request, Data},
      NewState=State#{md5 := MethodData#{state => {challenge_sent, Challenge}}},
      {enqueue_and_send, Pkt, NewState};
    {challenge_sent, Challenge} ->
      UserName=maps:get(username, PassedState),
      case eradius_auth:lookup_user(UserName, RadAttrs) of
        {error, not_found} ->
          {auth_fail, {access_reject, failure, <<>>}, State};
        {ok, Passwords, SuccessAttrs} ->
          case validateAuth(Passwords, Id, Challenge, TypeData) of
            invalid ->
              {auth_fail, {access_reject, failure, <<>>}, State};
            valid ->
              {auth_ok, {access_accept, success, <<>>, SuccessAttrs}, State}
          end
      end
  end.

validateAuth(Pass, Id, Challenge, TypeData) when is_binary(Pass) ->
  validateAuth([Pass], Id, Challenge, TypeData);
validateAuth([], _, _, _) -> invalid;
validateAuth([Pass|Rest], Id, Challenge, TypeData) ->
  CalculatedChallenge=crypto:hash(md5, <<Id, Pass/binary, Challenge/binary>>),
  <<_:1/bytes, ReceivedChallenge/binary>> = TypeData,
  case CalculatedChallenge == ReceivedChallenge of
    true -> valid;
    false -> validateAuth(Rest, Id, Challenge, TypeData)
  end.

