-module(eradius_mschap).
-compile([{parse_transform, lager_transform}]).

%FIXME: Reduce the surface area here.
-compile(export_all).

handle({handle, {_, Id, _, _Type, TypeData},
    {_, _, _, _, _, _}},
    State=#{mschapv2 := MethodData=#{state := MethodState}}) ->
  case MethodState of
    undefined ->
      MSCHAPv2Bytes=crypto:strong_rand_bytes(16),
      %It is not at all required to put a name in the challenge packet.
      Name= <<"erlang.eap.server">>,
      NewState=State#{mschapv2 := MethodData#{state := {challenge_sent, MSCHAPv2Bytes, Name}}},
      NextId=eap:incrementId(Id),
      BytesLen=byte_size(MSCHAPv2Bytes),
      Data=eradius_mschap:create_packet(challenge, NextId, <<BytesLen, MSCHAPv2Bytes/binary, Name/binary>>),
      {enqueue_and_send, {access_challenge, request, Data}, NewState};
    %NOTE: This message might be useful if the Mac machine continues to be dumb
    %when the RADIUS credentials have changed out from under it:
    %http://lists.freeradius.org/pipermail/freeradius-users/2011-April/053010.html
    {challenge_sent, AuthChallenge, _Name} ->
      %Reserved and Flags both must be zero-filled. (RFC2759)
      Reserved=binary:copy(<<0>>, 8),
      Flags= <<0>>,
      case TypeData of
        %Response packet.
        %FIXME: Use ChapLen and ValueSize to verify the packet!
        <<2, Id:1/bytes, _ChapLen:2/bytes, _ValueSize:1/bytes,
          PeerChallenge:16/bytes, Reserved:8/bytes, NtResponse:24/bytes, Flags:1/bytes,
          %FIXME: This username might have a WinNT domain part. Ignore up to and
          %including the first "\", and then the rest is the username.
          ChapUserName/binary>> ->
          Password=maps:get(user_pass, State),
          %Convert password from UTF8 to UTF16-LE:
          ConvertedPass=unicode:characters_to_binary(Password,
                                                     utf8, {utf16, little}),
          CalculatedReponse=eradius_mschap:generateNtResponse(AuthChallenge, PeerChallenge,
                                                              ChapUserName, ConvertedPass),
          case CalculatedReponse == NtResponse of
            true ->
              lager:info("Authenticator response valid."),
              AuthResp=eradius_mschap:generateAuthenticatorResponse(ConvertedPass, NtResponse, PeerChallenge,
                                                                    AuthChallenge, ChapUserName),
              NextId=eap:incrementId(Id),
              Message= <<>>,
              Data=eradius_mschap:create_packet(success, NextId, AuthResp, Message),
              NewState=State#{mschapv2 := MethodData#{state => {mschap_success_sent, AuthChallenge, _Name}}},
              {enqueue_and_send, {access_challenge, request, Data}, NewState};
            false ->
              %FIXME: If the username is correct, then the password is invalid.
              %       Send a retryable error with code 691 and wait for another message.
              %       If the username is incorrect, then all auth here is
              %       invalid. MAYBE send a non-retryable error with code 691
              %       and PROBABLY END the session.
              lager:info("Authenticator response invalid."),
              %FIXME: See above. This data should be sensible!
              %       Also, we shouldn't reject outright!
              {enqueue_and_send, {access_reject, failure, <<>>}, State}
          end;
        _ ->
          lager:warning("Malformed MSCHAPv2 packet."),
          {stay, State}
      end;
    {mschap_success_sent, _AuthChallenge, _Name} ->
      case TypeData of
        <<3>> ->
          {auth_ok, {access_accept, success, <<>>}, State}
      end
  end.

%TODO: Note: Everything in this module only handles MSCHAPv2, despite the
%      module name. Adding support for older versions of MSCHAP is on the TODO
%      list.

create_packet(success, Id, AuthBin, Message) when is_binary(Message) ->
  create_packet(success, Id, <<AuthBin/binary, " M=", Message/binary>>).

create_packet(failure, Id, ErrorCode, Retryable, <<Challenge:16/bytes>>, Message)
  when is_binary(Message) ->
  C=binary:list_to_bin(radius_server:bin_to_hex(Challenge)),
  EC=erlang:integer_to_binary(ErrorCode),
  true=byte_size(EC)<11,
  R=
    case Retryable of
      true -> <<"1">>;
      false -> <<"0">>
    end,
  create_packet(failure, Id, <<"E=", EC/binary, " R=", R/binary,
                               " C=", C/binary, " V=3 M=", Message/binary>>).

create_packet(Type, Id, Data) ->
  Code=
    case Type of
      challenge -> <<1>>;
      success -> <<3>>;
      failure -> <<4>>
    end,
  MSLen=byte_size(Data)+4,
  <<26, Code/binary, Id/binary, MSLen:16, Data/binary>>.

%Support functions:
%FIXME: Note all of the ones that are present in MSCHAPv2 but not MSCHAPv1
generateNtResponse(<<AuthChallenge:16/bytes>>, <<PeerChallenge:16/bytes>>,
                   UserName, Password) when
    byte_size(Password) =< 256*2 andalso byte_size(UserName) =< 256 ->
  <<Challenge:8/bytes>> = challengeHash(PeerChallenge, AuthChallenge, UserName),
  <<PwHash:16/bytes>> = ntPasswordHash(Password),
  <<Response:24/bytes>> = challengeResponse(Challenge, PwHash),
  Response.

challengeHash(<<PeerChallenge:16/bytes>>, <<AuthChallenge:16/bytes>>,
              UserName) when byte_size(UserName) =< 256 ->
  C1=crypto:hash_init(sha),
  C2=crypto:hash_update(C1, PeerChallenge),
  C3=crypto:hash_update(C2, AuthChallenge),
  C4=crypto:hash_update(C3, UserName),
  <<Challenge:8/bytes, _:12/bytes>> = crypto:hash_final(C4),
  Challenge.

ntPasswordHash(Password) when byte_size(Password) =< 256*2 ->
  <<PwHash:16/bytes>> = crypto:hash(md4, Password),
  PwHash.

hashNtPasswordHash(<<PwHash:16/bytes>>) ->
  <<PwHashHash:16/bytes>> = crypto:hash(md4, PwHash),
  PwHashHash.

challengeResponse(<<Challenge:8/bytes>>, <<PwHash:16/bytes>>) ->
  Zeroes=binary:copy(<<0>>, 21-16),
  <<ZPasswordHash:21/bytes>> = <<PwHash/binary, Zeroes/binary>>,
  <<R1:8/bytes>> = desEncrypt(Challenge, binary:part(ZPasswordHash, 0, 7)),
  <<R2:8/bytes>> = desEncrypt(Challenge, binary:part(ZPasswordHash, 7, 7)),
  <<R3:8/bytes>> = desEncrypt(Challenge, binary:part(ZPasswordHash, 14, 7)),
  <<R1/binary, R2/binary, R3/binary>>.

desEncrypt(<<Clear:8/bytes>>, <<A:7,B:7,C:7,D:7,E:7,F:7,G:7,H:7>>) ->
  %Add fake parity bits (that are ignored by this DES implementation).
  <<Key:8/bytes>> = <<A:7, 1:1, B:7, 1:1, C:7, 1:1, D:7, 1:1,
                      E:7, 1:1, F:7, 1:1, G:7, 1:1, H:7, 1:1>>,
  <<Cypher:8/bytes>> = crypto:block_encrypt(des_ecb, <<Key/binary>>, Clear),
  Cypher.

generateAuthenticatorResponse(Password, <<NtResponse:24/bytes>>, <<PeerChallenge:16/bytes>>,
                              <<AuthChallenge:16/bytes>>, UserName) when 
    byte_size(Password) =< 256*2 andalso byte_size(UserName) =< 256 ->
  %Magic server to client signing constant"
  Magic1= <<16#4D, 16#61, 16#67, 16#69, 16#63, 16#20, 16#73, 16#65, 16#72, 16#76,
             16#65, 16#72, 16#20, 16#74, 16#6F, 16#20, 16#63, 16#6C, 16#69, 16#65,
             16#6E, 16#74, 16#20, 16#73, 16#69, 16#67, 16#6E, 16#69, 16#6E, 16#67,
             16#20, 16#63, 16#6F, 16#6E, 16#73, 16#74, 16#61, 16#6E, 16#74>>,
  %"Pad to make it do more than one iteration"
  Magic2= <<16#50, 16#61, 16#64, 16#20, 16#74, 16#6F, 16#20, 16#6D, 16#61, 16#6B,
             16#65, 16#20, 16#69, 16#74, 16#20, 16#64, 16#6F, 16#20, 16#6D, 16#6F,
             16#72, 16#65, 16#20, 16#74, 16#68, 16#61, 16#6E, 16#20, 16#6F, 16#6E,
             16#65, 16#20, 16#69, 16#74, 16#65, 16#72, 16#61, 16#74, 16#69, 16#6F,
             16#6E>>,
  <<PwHash:16/bytes>> = ntPasswordHash(Password),
  <<PwHashHash:16/bytes>> = hashNtPasswordHash(PwHash),
  C1=crypto:hash_init(sha),
  C2=crypto:hash_update(C1, PwHashHash),
  C3=crypto:hash_update(C2, NtResponse),
  C4=crypto:hash_update(C3, Magic1),
  <<Digest:20/bytes>> = crypto:hash_final(C4),
  <<Challenge:8/bytes>> = challengeHash(PeerChallenge, AuthChallenge, UserName),

  C5=crypto:hash_init(sha),
  C6=crypto:hash_update(C5, Digest),
  C7=crypto:hash_update(C6, Challenge),
  C8=crypto:hash_update(C7, Magic2),
  <<DigestLast:20/bytes>> = crypto:hash_final(C8),

  <<AuthReponse:42/bytes>> = binary:list_to_bin("S=" ++ radius_server:bin_to_hex(DigestLast)),
  AuthReponse.

checkAuthenticatorResponse(Password, <<NtResponse:24/bytes>>, <<PeerChallenge:16/bytes>>,
                          <<AuthChallenge:16/bytes>>, UserName, <<ReceivedResponse:42/bytes>>)
  when byte_size(Password) =< 256*2 ->
  <<MyResponse:42/bytes>> = generateAuthenticatorResponse(Password, NtResponse, PeerChallenge,
                                                          AuthChallenge, UserName),
  MyResponse == ReceivedResponse.

newPasswordEncryptedWithOldNtPasswordHash(NewPassword, OldPassword)
  when byte_size(NewPassword) =< 256*2 andalso byte_size(OldPassword) =< 256*2 ->
  <<PasswordHash:16/bytes>> = ntPasswordHash(OldPassword),
  EncPwBlock = <<_:(256*2)/bytes, _:4/bytes>> = 
    encryptPwBlockWithPasswordHash(NewPassword, PasswordHash),
  EncPwBlock.

encryptPwBlockWithPasswordHash(Password, <<PasswordHash:16/bytes>>)
  when byte_size(Password) =< 256*2 ->
  PwSize=byte_size(Password),

  ClearPassword=crypto:rand_bytes(256*2),
  ClearPasswordLen= <<PwSize:32>>,
  PwOffset=byte_size(ClearPassword)-PwSize,

  ClearHead=binary:part(ClearPassword, 0, PwOffset),
  MixedPassword = <<ClearHead/binary, Password/binary>>,
  ClearLen=byte_size(ClearPassword) + byte_size(ClearPasswordLen),
  PwHashLen=byte_size(PasswordHash),

  <<Cypher:ClearLen/bytes>> = 
    rc4Encrypt(<<MixedPassword/binary, ClearPasswordLen/binary>>, ClearLen,
               PasswordHash, PwHashLen),
  Cypher.

rc4Encrypt(Clear, ClearLen, Key, KeyLen) when
    byte_size(Clear) == ClearLen andalso byte_size(Key) == KeyLen ->
  S1=crypto:stream_init(rc4, Key),
  {_, <<Cypher:ClearLen/bytes>>}=crypto:stream_encrypt(S1, Clear),
  Cypher.

oldNtPasswordHashEncryptedWithNewNtPasswordHash(NewPassword, OldPassword)
  when byte_size(NewPassword) =< 256*2 andalso byte_size(OldPassword) =< 256*2 ->
  <<OldPasswordHash:16/bytes>> = ntPasswordHash(OldPassword),
  <<NewPasswordHash:16/bytes>> = ntPasswordHash(NewPassword),
  <<EncryptedPwHash:16/bytes>> = ntPasswordHashEncryptedWithBlock(OldPasswordHash,
                                                                 NewPasswordHash),
  EncryptedPwHash.

ntPasswordHashEncryptedWithBlock(<<PwHashFront:8/bytes, PwHashBack:8/bytes>>, <<Block:16/bytes>>) ->
  <<R1:8/bytes>> = desEncrypt(PwHashFront, binary:part(Block, 0, 7)),
  <<R2:8/bytes>> = desEncrypt(PwHashBack,  binary:part(Block, 7, 7)),
  <<R1/binary, R2/binary>>.

%MSCHAPv2 test: (taken from RFC 2759, sec 9.2)
run_test() ->
  %0-to-256-char UserName:
  UserName= <<16#55,16#73,16#65,16#72>>,
  %0-to-256-unicode-char, Password:
  Pass= <<16#63,16#00,16#6C,16#00,16#69,16#00,16#65,16#00,16#6E,16#00,16#74,16#00,16#50,16#00,16#61,16#00,16#73,16#00,16#73,16#00>>,
  %16-octet, AuthenticatorChallenge:
  AuthChallenge= <<16#5B,16#5D,16#7C,16#7D,16#7B,16#3F,16#2F,16#3E,16#3C,16#2C,16#60,16#21,16#32,16#26,16#26,16#28>>,
  %16-octet, PeerChallenge:
  PeerChallenge= <<16#21,16#40,16#23,16#24,16#25,16#5E,16#26,16#2A,16#28,16#29,16#5F,16#2B,16#3A,16#33,16#7C,16#7E>>,
  %8-octet, Challenge:
  _Challenge= <<16#D0,16#2E,16#43,16#86,16#BC,16#E9,16#12,16#26>>,
  %16-octet,PasswordHash:
  PwHash= <<16#44,16#EB,16#BA,16#8D,16#53,16#12,16#B8,16#D6,16#11,16#47,16#44,16#11,16#F5,16#69,16#89,16#AE>>,
  %24octet, NT-Response:
  NtResp= <<16#82,16#30,16#9E,16#CD,16#8D,16#70,16#8B,16#5E,16#A0,16#8F,16#AA,16#39,16#81,16#CD,16#83,16#54,16#42,16#33,16#11,16#4A,16#3D,16#85,16#D6,16#DF>>,
  %16-octet PasswordHashHash:
  PwHashHash= <<16#41,16#C0,16#0C,16#58,16#4B,16#D2,16#D9,16#1C,16#40,16#17,16#A2,16#A1,16#2F,16#A5,16#9F,16#3F>>,
  %42-octet AuthenticatorResponse:
  AuthResp= <<"S=407A5589115FD0D6209F510FE9C04566932CDA56">>,

  <<"User">> = UserName,
  <<"clientPass">> = unicode:characters_to_binary(Pass, {utf16, little}, utf8),
  PwHash=ntPasswordHash(Pass),
  PwHashHash=hashNtPasswordHash(PwHash),
  AuthResp=generateAuthenticatorResponse(Pass, NtResp, PeerChallenge, AuthChallenge, UserName),
  NtResp=generateNtResponse(AuthChallenge, PeerChallenge, UserName, Pass),
  true=checkAuthenticatorResponse(Pass, NtResp, PeerChallenge, AuthChallenge, UserName, AuthResp).
