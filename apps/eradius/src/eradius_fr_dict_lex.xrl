Definitions.

ALPHA = [a-zA-Z]
WS = [\t\s]
NL = [\r\n]
NUM = [0-9]+
HEX = [0-9a-fA-F]+
%FIXME: Should I exclude the trailing NL?
COMMENT = #.*
%There are a few crazy chars in attr names.
NAMECHARS = [a-zA-z0-9\./\+,=]

%The basic datatypes
%The single stray leading-capital spelling I've located is
%included. I don't know how to do a case-insensitive search, so...
TYPE = (integer|octets|string|String|ipaddr|date|ipv6addr|ipv6prefix|ifid|integer64|ether|abinary|byte|short|signed|tlv|ipv4prefix|combo-ip|evs|vsa|extended|long-extended)
%The basic -er- "line types"
BASICHEADING = ATTRIBUTE|VALUE|VENDOR|BEGIN-VENDOR|END-VENDOR|BEGIN-TLV|END-TLV
%Often something like "Calling-Station-Id"
%But sometimes something like "Calling-Station_Id" because typos.
NAME = {NAMECHARS}+([-_]{NAMECHARS}+)*

Rules.

{TYPE} : {token, {list_to_atom(normalize_name(TokenChars)), TokenLine}}.
{BASICHEADING} :
  {token, {list_to_atom(normalize_name(TokenChars)), TokenLine}}.
%%We need these greedy matches for the tags, along with the pushback,
%%as "," is a valid character in NAMEs.
has_tag,?.* :
  {token, {rfc_2868_tag_flag, TokenLine}, determine_pushback_chars(TokenChars)}.
encrypt={NUM},?.* :
  {token, {encrypt_flag, TokenLine, get_crypt_type(TokenChars)}, determine_pushback_chars(TokenChars)}.
array,?.* :
  {token, {array_flag, TokenLine}, determine_pushback_chars(TokenChars)}.
virtual,?.* :
  {token, {virtual_flag, TokenLine}, determine_pushback_chars(TokenChars)}.
concat,?.* :
  {token, {concat_flag, TokenLine}, determine_pushback_chars(TokenChars)}.
%Often comes in two parts, but sometimes in three.
%The three-part formulation indicates the use of WiMAX VSA continuation bit
format=.,.(,.)? :
  {token, {vendor_type_length_size, TokenLine, get_vsa_typelen(TokenChars)}}.
%Blow up the parser if we find a format flag paired with another flag.
%The flag and the flag combiner both use "," as an item separator
%and I don't want to work out the right thing to do for that right now.
format=.,.(,.)?, :
  {token, {unexpected_format_flag_paired_with_another_flag_please_update_lexer, TokenLine}}.
octets\[{NUM}\] :
  {token, {octets_len_restricted, TokenLine, get_declared_length(TokenChars)}}.
\$INCLUDE{WS}+.* : {token, {include, TokenLine, get_include_file(TokenChars)}}.

{NUM} : {token, {number, TokenLine, list_to_integer(TokenChars)}}.
0x{HEX} : {token, {number, TokenLine, hex_to_integer(TokenChars)}}.
%A line containing at least one of these appears to come after a "tlv" line.
%There can be multiple levels of dots. (See WiMAX-Source-IPAddressMask for instance).
%
%The dotted notation is used in lieu of BEGIN-TLV END-TLV pairs. You can also
%get "nested" TLVs by adding more dots. The docs call this the "oid" format.
{NUM}(\.{NUM})+ : {token, {number, TokenLine, explode_oid_number(TokenChars)}}.
{WS} : skip_token.
{NL} : skip_token.
{COMMENT} : skip_token.
%NAME matching is very greedy, so it should be the last thing we consider.
{NAME} : {token, {name, TokenLine, list_to_atom(normalize_name(TokenChars))}}.
, : skip_token.

Erlang code.

%Convert to lowercase and replace "-" with "_"
normalize_name(Chars) ->
  Lowered=string:to_lower(Chars),
  lists:flatten(
    lists:join("_",
      string:tokens(Lowered, "-"))).

%Get length from things of the form "octet[12]"
get_declared_length(Chars) ->
  [_, Len]=string:tokens(Chars, "[]"),
  list_to_integer(Len).

%Extract the number from "encrypt=1" and similar.
get_crypt_type(TokenChars) ->
  ["encrypt", Rest]=string:tokens(TokenChars, "="),
  %For the case where the rhs of the "=" is more flags:
  Num=lists:nth(1, string:tokens(Rest, ",")),
  list_to_integer(Num).

%Get the parts from "format=4,0" or "format=1,1,c"
get_vsa_typelen(TokenChars) ->
  ["format", Str]=string:tokens(TokenChars, "="),
  case string:tokens(Str, ",") of
    [A, B] ->
      [list_to_integer(A), list_to_integer(B)];
    [A, B, C] ->
      [list_to_integer(A), list_to_integer(B), C]
  end.

explode_oid_number(TokenChars) ->
  lists:foldl(fun(Tok, Acc) ->
                Acc ++ [list_to_integer(Tok)]
              end, [], string:tokens(TokenChars, ".")).

%Get the argument to an include directive.
get_include_file(Chars) ->
  %length of "$INCLUDE " is 9
  lists:sublist(Chars, 10, length(Chars)).

hex_to_integer(Chars) ->
  %Trim off the leading "0x"
  {ok, [Ret], _}=io_lib:fread("~16u", string:substr(Chars, 3)),
  Ret.

determine_pushback_chars([])-> [];
determine_pushback_chars(Chars) ->
  case string:str(Chars, ",") of
    0 -> "";
    Idx -> string:substr(Chars, Idx+1)
  end.
