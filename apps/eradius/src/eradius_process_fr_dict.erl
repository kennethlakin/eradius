-module(eradius_process_fr_dict).

-export([process_dict/1]).
-compile([{parse_transform, lager_transform}]).

-include_lib("eradius/include/eradius_attr.hrl").

%This code processes FreeRADIUS-format dictionary files.
%NOTE: It converts most names in the files into atoms... malicious (or simply 
%      absurdly large) dictionaries can crash your VM.
%FIXME: It ignores $INCLUDE directives... the dictionaries of interest
%       must be concatentated before pointing this code at it.
process_dict(DictFile) ->
  {ok, FileBin}=file:read_file(DictFile),
  FileStr = binary_to_list(FileBin),
  {ok, Lex, _}=eradius_fr_dict_lex:string(FileStr),
  {ok, Tree}=eradius_fr_dict_parse:parse(Lex),
  {IdMap, NameMap}=process_parse(Tree),
  IdString=create_id_lookup(IdMap),
  NameString=create_name_lookup(NameMap),
  Header=
"-module(eradius_dict).
-export([id_lookup/1, name_lookup/1]).
-include_lib(\"eradius/include/eradius_attr.hrl\").
",
  OutFile=code:lib_dir(eradius) ++ "/src/eradius_dict.erl",
  lager:info("PROCESS_FR_DICT Writing compiled dictionary to ~p", [OutFile]),
  file:write_file(OutFile, Header ++ IdString ++ NameString).

create_name_lookup(NameMap) when is_map(NameMap) ->
  create_name_lookup(maps:to_list(NameMap));
create_name_lookup([]) ->
"name_lookup(_) -> [].
";
create_name_lookup([{Name, {Id, _}}| Rest]) ->
  TEMPLATE="name_lookup(~w) -> ~w;~n",
  Ret=io_lib:fwrite(TEMPLATE, [Name, Id]),
  Ret ++ create_name_lookup(Rest).

create_id_lookup(IdMap) when is_map(IdMap) ->
  create_id_lookup(maps:to_list(IdMap));
create_id_lookup([]) ->
"id_lookup([]) -> #eradius_attr{}.
";
create_id_lookup([{Id, Rec} | Rest]) ->
  %FIXME: Figure out how to use something like io_lib_pretty:print to print
  %       out the record as a record definition, rather than a tuple.
  TEMPLATE="id_lookup(~w) -> ~w;~n",
  Ret=io_lib:fwrite(TEMPLATE, [Id, Rec]),
  Ret ++ create_id_lookup(Rest).

process_parse(ParseTree) ->
  ParseConfiguration=
              #{
                %The idea with the Attr Name lookup is that all spellings of a
                %given attr will be accepted. They might even map to the same ID.
                attr_name_lookup => #{} %#{ atom() => {path_id(), #eradius_attr{}} }
                %The way the ID lookup will work is that -in the event that
                %multiple attrs map to the same ID, the _last_ attr in will be
                %the one that gets to be the default.
                %It is primed with the empty list to make writing the
                %processing code easier.
                ,id_lookup => #{[] => #eradius_attr{}} %#{list(pos_integer()) => #eradius_attr{}}
                %The VNL and the TNL should contain a _single_ id, not the entire
                %path.
                ,vendor_name_lookup => #{} %#{atom() => pos_integer()}
                ,tlv_name_lookup => #{}    %#{atom() => pos_integer()}
                %Make sure that we don't end up in deferral loops.
                ,defer_counts => #{} %{term() => pos_integer()}
                %Process attributes first.
                ,attribute_mode => true
   },
  case doProcess(ParseTree, ParseConfiguration) of
    {ok, State} ->
      case doProcess(ParseTree, State#{attribute_mode := false}) of
        {ok, #{id_lookup := ILookup, attr_name_lookup := NameLookup}} ->
          %Remove the lookup for the empty ID. It's not a real ID.
          IdLookup=maps:remove([], ILookup),
          {IdLookup, NameLookup};
        Other -> Other
      end;
    Other -> Other
  end.

%Processes the flags attached to an attribute (if any) and sets the appropriate
%values in the eradius_attr record.
-spec processFlags(#eradius_attr{}, list({atom(), term()})) -> #eradius_attr{};
                  (#eradius_attr{}, map()) -> #eradius_attr{}.
processFlags(Attr=#eradius_attr{}, Flags) when is_map(Flags) ->
  processFlags(Attr, maps:to_list(Flags));
processFlags(Attr=#eradius_attr{}, []) -> Attr;
processFlags(Attr=#eradius_attr{}, [{vendor_type_len, LenList} | Rest]) ->
  case LenList of
    [] ->
      processFlags(Attr, Rest);
    [V, L] ->
      processFlags(Attr#eradius_attr{val_width=V, len_width=L}, Rest);
    [V, L, "c"] ->
      processFlags(Attr#eradius_attr{val_width=V, len_width=L, wimax_continuation=true}, Rest)
  end;
processFlags(Attr=#eradius_attr{}, [{encrypt_flag, Val} | Rest]) ->
  processFlags(Attr#eradius_attr{encrypt_flag=Val}, Rest);
processFlags(Attr=#eradius_attr{}, [{tag_flag, true} | Rest]) ->
  processFlags(Attr#eradius_attr{tag_flag=true}, Rest);
processFlags(Attr=#eradius_attr{}, [{concat_flag, true} | Rest]) ->
  processFlags(Attr#eradius_attr{concat_flag=true}, Rest);
processFlags(Attr=#eradius_attr{}, [{array_flag, true} | Rest]) ->
  processFlags(Attr#eradius_attr{array_flag=true}, Rest);
processFlags(Attr=#eradius_attr{}, [{virtual_flag, true} | Rest]) ->
  processFlags(Attr#eradius_attr{virtual_flag=true}, Rest).

doProcess([], State) ->
  {ok, State};
doProcess([Item|Rest], State=#{defer_counts := DeferCounts}) ->
  case doProcess(Item, [], [], State) of
    defer ->
      case maps:get(Item, DeferCounts, undefined) of
        10 ->
          lager:error("PROCESS_FR_DICT Defered ~p 10 times. Dropping", [Item]),
          doProcess(Rest, State);
        Count ->
          case Count of
            undefined ->
              NewDeferCounts=DeferCounts#{Item => 1};
            Count ->
              NewDeferCounts=DeferCounts#{Item := Count+1}
          end,
          doProcess(Rest ++ [Item], State#{defer_counts:=NewDeferCounts})
      end;
    {ok, NewState} ->
      doProcess(Rest, NewState)
  end;
%FIXME: This is _ugly_
doProcess(Item, State) ->
  doProcess([Item], State).

doProcess([], _, _, State) -> {ok, State};
doProcess([Item|Rest], IdStack, TypelenFormat, State) ->
  case doProcess(Item, IdStack, TypelenFormat, State) of
    {ok, NewState} ->
      doProcess(Rest, IdStack, TypelenFormat, NewState);
    defer ->
      defer
  end;
%If we're running in value mode, don't process attributes.
doProcess({attribute, _, _, _, _}, _, _, State=#{attribute_mode := false}) ->
  {ok, State};
doProcess({attribute, _, _, _, _, _}, _, _, State=#{attribute_mode := false}) ->
  {ok, State};
doProcess({attribute, Name, IdList, Type, Flags}, IdStack, TypelenFormat, State)
  when is_list(IdList) ->
  {Path, [Id]}=lists:split(length(IdList)-1, IdList),
  doProcess({attribute, Name, Id, Type, Flags}, IdStack ++ Path, TypelenFormat, State);
doProcess({attribute, Name, IdList, Type, Length, Flags}, IdStack, TypelenFormat, State)
  when is_list(IdList) ->
  {Path, [Id]}=lists:split(length(IdList)-1, IdList),
  doProcess({attribute, Name, Id, Type, Length, Flags}, IdStack ++ Path, TypelenFormat, State);
doProcess({attribute, Name, Id, Type, F}, IdStack, TLFormat
          ,State=#{attr_name_lookup := ANL, id_lookup := IDL, tlv_name_lookup := TNL}) ->
  case maps:is_key(IdStack, IDL) of
    false ->
      lager:warning("PROCESS_FR_DICT Deferring ~p because Stack ~p wasn't found", [Name, IdStack]),
      defer;
    true ->
      case Type == tlv andalso length(IdStack) == 2 of
        false ->
          %The WiMAX continuation bit is only set on the outermost TLV
          TypelenFormat=lists:sublist(TLFormat, 2);
        true ->
          TypelenFormat=TLFormat
      end,
      Flags=maps:merge(F, #{vendor_type_len => TypelenFormat}),
      A=#eradius_attr{name=Name, id=Id, type=Type},
      Attr=processFlags(A, Flags),
      NewANL=ANL#{Name => {IdStack ++ [Id], Attr}},
      NewIDL=IDL#{IdStack ++ [Id] => Attr},
      case Type of
        tlv ->
          NewTNL=TNL#{Name => Id},
          NewState=State#{attr_name_lookup := NewANL, id_lookup := NewIDL, tlv_name_lookup := NewTNL};
        _ ->
          NewState=State#{attr_name_lookup := NewANL, id_lookup := NewIDL}
      end,
      {ok, NewState}
  end;
doProcess({attribute, Name, Id, Type, Length, F}, IdStack, TLFormat
          ,State=#{attr_name_lookup := ANL, id_lookup := IDL}) ->
  case maps:is_key(IdStack, IDL) of
    false ->
      lager:warning("PROCESS_FR_DICT Deferring Attribute ~p because Stack ~p wasn't found", [Name, IdStack]),
      defer;
    true ->
      %TLVs should never have a specified length, but we do this check anyway.
      case Type == tlv andalso length(IdStack) == 2 of
        false ->
          %The WiMAX continuation bit is only set on the outermost TLV
          TypelenFormat=lists:sublist(TLFormat, 2);
        true ->
          TypelenFormat=TLFormat
      end,
      Flags=maps:merge(F, #{vendor_type_len => TypelenFormat}),
      A=#eradius_attr{name=Name, id=Id, type=Type, declared_length=Length},
      Attr=processFlags(A, Flags),
      NewANL=ANL#{Name => {IdStack ++ [Id], Attr}},
      NewIDL=IDL#{IdStack ++ [Id] => Attr},
      NewState=State#{attr_name_lookup := NewANL, id_lookup := NewIDL},
      {ok, NewState}
  end;
doProcess({value, _, _, _}, _, _, State=#{attribute_mode := true}) ->
  %If we're running in attribute-only mode, don't process values.
  {ok, State};
doProcess({value, AttrName, ValName, ValValue}, _, _, State=#{attr_name_lookup := ANL, id_lookup := IDL}) when is_atom(ValName) ->
  case maps:get(AttrName, ANL, undefined) of
    undefined ->
      lager:warning("PROCESS_FR_DICT Deferring Value ~p because Attribute ~p wasn't found", [ValName, AttrName]),
      defer;
    {PathId, Attr} ->
      #eradius_attr{val_name_map=ValNameMap, val_val_map=ValValMap}=Attr,
      NewAttr=Attr#eradius_attr{val_name_map=ValNameMap#{ValName => ValValue}
                               ,val_val_map=ValValMap#{ValValue => ValName}},
      NewANL=ANL#{AttrName := {PathId, NewAttr}},
      NewIDL=IDL#{PathId := NewAttr},
      {ok, State#{attr_name_lookup := NewANL, id_lookup := NewIDL}}
  end;
doProcess({vendor, VendorName, Id, Flags}
          ,[] %IdStack
          ,[] %TypelenFormat
          ,State=#{attr_name_lookup:=ANL, vendor_name_lookup:=VNL, id_lookup:=IDL}) ->
  %Our standard vendor specific attribute is named 'vendor_specific'
  case maps:get(vendor_specific, ANL, undefined) of
    undefined ->
      lager:warning("PROCESS_FR_DICT Deferring ~p because vendor_specific Attribute wasn't found", [VendorName]),
      defer;
    {[VSId], #eradius_attr{id=VSId}} ->
      case maps:get(vendor_type_len, Flags, undefined) of
        undefined -> VendorTypeLen=[];
        VendorTypeLen -> VendorTypeLen
      end,
      VA=#eradius_attr{type=vendor, id=Id, name=VendorName},
      VendorAttr=processFlags(VA, Flags),
      VendorPathId=[VSId, Id],
      NewANL=ANL#{VendorName => {VendorPathId, VendorAttr}},
      NewVNL=VNL#{VendorName => {Id, VendorTypeLen}},
      NewIDL=IDL#{VendorPathId => VendorAttr},
      {ok, State#{attr_name_lookup := NewANL, vendor_name_lookup := NewVNL, id_lookup := NewIDL}}
  end;
%Blocks with no contents need no work.
doProcess({vsa_block, {{begin_vendor, VendorName}, {end_vendor, VendorName}}}, _, _, State) ->
  {ok, State};
doProcess({vsa_block,
           {{begin_vendor, VendorName}, Block, {end_vendor, VendorName}}}, IdStack, [] %TypelenFormat
          ,State=#{vendor_name_lookup := VNL, attr_name_lookup := ANL}) ->
  case maps:get(VendorName, VNL, undefined) of
    undefined ->
      lager:warning("PROCESS_FR_DICT Deferring vsa_block for Vendor ~p because its VendorName wasn't found", [VendorName]),
      defer;
    {VendorId, VendorFormat} ->
      case maps:get(vendor_specific, ANL, undefined) of
        undefined ->
          defer;
        {[VSId], #eradius_attr{id=VSId}} ->
          doProcess(Block, IdStack ++ [VSId] ++ [VendorId], VendorFormat, State)
      end
  end;
doProcess({vsa_block, {{begin_vendor, NameOne}, {end_vendor, NameTwo}}}, IdStack, _, _) ->
  {error, {vsa_block, mismatched_vendor_pairs, [NameOne, NameTwo], at, IdStack}};
doProcess({vsa_block, {{begin_vendor, NameOne}, _, {end_vendor, NameTwo}}}, IdStack, _, _) ->
  {error, {vsa_block, mismatched_vendor_pairs, [NameOne, NameTwo], at, IdStack}};
%Blocks with no contents need no work.
doProcess({tlv_block, {{begin_tlv, TlvName}, {end_tlv, TlvName}}}, _, _, State) ->
  {ok, State};
doProcess({tlv_block, {{begin_tlv, TlvName}, Block, {end_tlv, TlvName}}}, IdStack, TypelenFormat
          ,State=#{tlv_name_lookup := TNL}) ->
  case maps:get(TlvName, TNL, undefined) of
    undefined ->
      lager:warning("PROCESS_FR_DICT Deferring tlv_block ~p because its tlv decl wasn't found", [TlvName]),
      defer;
    TlvId ->
      doProcess(Block, IdStack ++ [TlvId], TypelenFormat, State)
  end;
doProcess({tlv_block, {{begin_tlv, NameOne}, {end_tlv, NameTwo}}}, IdStack, _, _) ->
  {error, {tlv_block, mismatched_tlv_pairs, [NameOne, NameTwo], at, IdStack}};
doProcess({tlv_block, {{begin_tlv, NameOne}, _, {end_tlv, NameTwo}}}, IdStack, _, _) ->
  {error, {tlv_block, mismatched_tlv_pairs, [NameOne, NameTwo], at, IdStack}};
doProcess({include_directive, _File}, _, _, State) ->
  {ok, State};
doProcess(Unknown_Item, IdStack, TypelenFormat, State) ->
  lager:error("PROCESS_FR_DICT Unhandled Item ~p ~p ~p", [Unknown_Item, IdStack, TypelenFormat]),
  {ok, State}.

