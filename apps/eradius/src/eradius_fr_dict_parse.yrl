Nonterminals
  attribute_mapping attr_or_value declaration declarations dictionary flag flag_list flags
  id include_directive sname snumber soctets_len_restricted tlv_block tlv_block_end
  tlv_block_item tlv_block_items tlv_block_start type value_mapping valsname_or_snumber vendor_line
  vsa_block vsa_block_end vsa_block_item vsa_block_items vsa_block_start.
Terminals
  abinary array_flag attribute begin_tlv begin_vendor byte combo_ip concat_flag date encrypt_flag end_tlv
  end_vendor ether evs extended ifid include integer integer64 ipaddr ipv4prefix ipv6addr ipv6prefix
  long_extended name number octets octets_len_restricted rfc_2868_tag_flag short signed string
  tlv value vendor vendor_type_length_size virtual_flag vsa.

Rootsymbol dictionary.

dictionary -> declarations : '$1'.
declarations -> declaration : [ '$1' ].
declarations -> declaration declarations : [ '$1' | '$2' ].

declaration -> attr_or_value : '$1'.
declaration -> vendor_line : '$1'.
declaration -> vsa_block : '$1'.
declaration -> tlv_block : '$1'.
declaration -> include_directive : '$1'.

attr_or_value -> attribute_mapping : '$1'.
attr_or_value -> value_mapping : '$1'.

attribute_mapping -> attribute sname id type flags : {attribute, '$2', '$3', '$4', '$5'}.
attribute_mapping -> attribute sname id soctets_len_restricted flags : {attribute, '$2', '$3',  octets, '$4', '$5'}.

value_mapping -> value sname valsname_or_snumber snumber : {value, '$2', '$3', '$4'}.

vendor_line -> vendor sname snumber flags : {vendor, '$2', '$3', '$4'}.

vsa_block -> vsa_block_start vsa_block_items vsa_block_end : {vsa_block, {'$1', '$2', '$3'}}.
vsa_block -> vsa_block_start vsa_block_end : {vsa_block, {'$1', '$2'}}.
vsa_block_start -> begin_vendor sname : {begin_vendor, '$2'}.
vsa_block_end -> end_vendor sname : {end_vendor, '$2'}.
vsa_block_items -> vsa_block_item : [ '$1' ].
vsa_block_items -> vsa_block_item vsa_block_items : [ '$1' | '$2' ].
vsa_block_item -> attr_or_value : '$1'.
vsa_block_item -> tlv_block : '$1'.

tlv_block -> tlv_block_start tlv_block_items tlv_block_end : {tlv_block, {'$1', '$2', '$3'}}.
tlv_block -> tlv_block_start tlv_block_end : {tlv_block, {'$1', '$2'}}.
tlv_block_start -> begin_tlv sname : {begin_tlv, '$2'}.
tlv_block_end -> end_tlv sname : {end_tlv, '$2'}.
tlv_block_items -> tlv_block_item : [ '$1' ].
tlv_block_items -> tlv_block_item tlv_block_items : [ '$1' | '$2' ].
tlv_block_item -> attr_or_value : '$1'.

flags -> flag_list : merge_flags('$1').
flags -> '$empty' : #{}.
flag_list -> flag : ['$1'].
flag_list -> flag flag_list : [ '$1' | '$2' ].
%Defines how many octets to use to encode the VSA type and length fields.
%Default is 1,1
%Offically supported values for Type   are 1,2,4.
%Offically supported values for Length are 0,1,2.
%The secret third value (which should always be "c") indicates the use of the
%WiMAX VSA continuation bit.
flag -> vendor_type_length_size : #{vendor_type_len => strip('$1')}.
%encrypt=1 : RFC2865 User-Password scramble method
%encrypt=2 : RFC2868 Tunnel-Password scramble method
%encrypt=3 : Ascend-Send-Secret scramble method (whatever that means)
flag -> encrypt_flag : #{encrypt_flag => strip('$1')}.
%has_tag flag is for RFC2868 tagged data. Operationally, I'm
%not sure we care about this.
flag -> rfc_2868_tag_flag : #{tag_flag => true}.
%concat flag is for attrs like EAP-Message that spread
%large contents across multiple multiple attrs
flag -> concat_flag : #{concat_flag => true}.
%array flag is for FreeRADIUS DHCP server attributes.
%(yes, FR can be a DHCP server)
flag -> array_flag : #{array_flag => true}.
%virtual flag appears to only be for FR internal attributes.
flag -> virtual_flag : #{virtual_flag => true}.

id -> number : strip('$1').

include_directive -> include : {include_directive, strip('$1')}.

valsname_or_snumber -> sname : '$1'.
valsname_or_snumber -> snumber : list_to_atom(integer_to_list('$1')).
sname -> name : strip('$1').
snumber -> number : strip('$1').
soctets_len_restricted -> octets_len_restricted : strip('$1').

type -> integer : strip('$1').
type -> octets : strip('$1').
type -> string : strip('$1').
type -> ipaddr : strip('$1').
type -> date : strip('$1').
type -> ipv6addr : strip('$1').
type -> ipv6prefix : strip('$1').
type -> ifid : strip('$1').
type -> integer64 : strip('$1').
type -> ether : strip('$1').
type -> abinary : strip('$1').
type -> byte : strip('$1').
type -> short : strip('$1').
type -> signed : strip('$1').
type -> tlv : strip('$1').
type -> ipv4prefix : strip('$1').
type -> combo_ip : strip('$1').
type -> evs : strip('$1').
type -> vsa : strip('$1').
type -> extended : strip('$1').
type -> long_extended : strip('$1').

Erlang code.

strip({_, _, A}) -> A;
strip({A, _}) -> A.

merge_flags(FlagList) ->
  lists:foldl(fun(F, Acc) -> maps:merge(Acc, F) end, #{}, FlagList).
