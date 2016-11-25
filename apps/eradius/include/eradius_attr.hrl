-record(eradius_attr,
        {name :: atom()
         ,type :: atom() %string, octet, or whatever.
         ,id :: undefined | pos_integer()
         %Stores predefined value name => value value map.
         %eg: #{vlan => 13} for the Tunnel-Type attr
         ,val_name_map = #{} :: #{atom() => term()}
         %Stores predefined value value => value name map.
         %eg: #{13 => vlan} for the Tunnel-Type attr
         ,val_val_map = #{} :: #{term() => atom()}
         ,value_data = <<>> :: term()
         %Some vendors alter the width of the Length and Value (AKA Type) "bytes"
         ,len_width = 1 :: integer()
         ,val_width = 1 :: integer()
         %Set to a value if the attribute specifies an appropriate length
         %Have only seen it (so far) with octet types.
         ,declared_length :: undefined | integer()
         %Currently observered encrypt values are 1, 2, 3
         %encrypt=1 : RFC2865 User-Password scramble method
         %encrypt=2 : RFC2868 Tunnel-Password scramble method
         %encrypt=3 : Ascend-Send-Secret scramble method (whatever that means)
         %See also http://freeradius.org/radiusd/man/dictionary.html
         ,encrypt_flag :: undefined | integer()
         %RFC2868 tagged data
         %FIXME: Update our encode/decode code to carve out the tag from the
         % first byte of data. NOTE: A tag reduces the available space
         % for our data by one byte.
         % However, the tag must be added _after_ we've done data
         % processing... things like Tunnel-Password are scrambled
         % _without_ the tag... the tag gets prepended to the result of
         % the scramble.
         ,tag_flag = false :: boolean()
         %Used on attributes like EAPMessage where adjacent attributes should
         %be concatenated together, rather than put into a list.
         ,concat_flag = false ::boolean()
         %FIXME: Not sure what this is for. It is present on FreeRADIUS DHCP
         %       server attributes.
         ,array_flag = false :: boolean()
         %FIXME: This is present on FreeRADIUS internal attributes. Maybe we
         %       should just refuse to process attributes with this flag set?
         ,virtual_flag = false :: boolean()
         %Should the first TLV in a set have the WiMAX continuation bit?
         %FIXME: Actually fragment and reassemble toolarge TLVs
         ,wimax_continuation = false :: boolean()
}).

