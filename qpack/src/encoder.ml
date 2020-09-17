(*----------------------------------------------------------------------------
 *  Copyright (c) 2020 António Nuno Monteiro
 *
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 *
 *  3. Neither the name of the copyright holder nor the names of its
 *  contributors may be used to endorse or promote products derived from this
 *  software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *---------------------------------------------------------------------------*)

open Types

module HeaderFieldsTbl = struct
  include Hashtbl.Make (struct
    type t = string

    let equal = String.equal

    let hash s = Hashtbl.hash s
  end)

  let[@inline] find_opt h key = try Some (find h key) with Not_found -> None
end

module ValueMap = struct
  include Map.Make (String)

  let[@inline] find_opt k m = try Some (find k m) with Not_found -> None
end

type t =
  { (* We maintain a lookup table of header fields to their indexes in the
     * dynamic table. The format is name -> (value -> index) *)
    table : Dynamic_table.t
  ; (* -1 signals no change, and avoids allocating option in the hot path *)
    mutable dyn_table_capacity_change : int
  ; lookup_table : int ValueMap.t HeaderFieldsTbl.t
  ; mutable next_seq : int
  ; (* From RFC<QPACK-RFC>§2.1.1:
     *   [...] an encoder that uses the dynamic table has to keep track of each
     *   dynamic table entry referenced by each field section until those
     *   representations are acknowledged by the decoder; see Section 4.4.1. *)
    stream_references : (int64, IntSet.t list) Hashtbl.t
  }

let not_found = Static_table.not_found

type table =
  | Static
  | Dynamic

let on_evict lookup_table (name, value) =
  let map = HeaderFieldsTbl.find lookup_table name in
  if ValueMap.cardinal map = 1 then
    HeaderFieldsTbl.remove lookup_table name
  else
    let map = ValueMap.remove value map in
    HeaderFieldsTbl.replace lookup_table name map

let create capacity =
  let lookup_table = HeaderFieldsTbl.create capacity in
  { table = Dynamic_table.create ~on_evict:(on_evict lookup_table) capacity
  ; lookup_table
  ; next_seq = 0
  ; dyn_table_capacity_change = -1
  ; stream_references = Hashtbl.create ~random:true 100
  }

let track_table_reference t idx set =
  IntSet.add (Dynamic_table.offset_from_index t.table idx) set

let add
    ({ table; lookup_table; next_seq; _ } as t)
    ~cur_referenced_fields
    name
    value
  =
  if Dynamic_table.add table name value then (
    let map =
      match HeaderFieldsTbl.find_opt lookup_table name with
      | Some map ->
        ValueMap.add value next_seq map
      | None ->
        ValueMap.singleton value next_seq
    in
    t.next_seq <- next_seq + 1;
    HeaderFieldsTbl.replace lookup_table name map;
    assert (Dynamic_table.offset_from_index t.table next_seq = t.table.offset);
    cur_referenced_fields :=
      track_table_reference t next_seq !cur_referenced_fields;
    next_seq)
  else
    not_found

let all_referenced_indices ~cur_referenced_fields t =
  Hashtbl.fold
    (fun _ sets acc -> List.fold_left IntSet.union acc sets)
    t.stream_references
    cur_referenced_fields

let tokens_without_indexing =
  (* From RFC7541§6.2.2: Never-Indexed Literals
   *   Either form of header field name representation is followed by the
   *   header field value represented as a string literal (see Section 5.2).
   *
   * Note: we choose not to index the values of these fields as they would
   * vary immensely. This way, we save some additions / evictions from the
   * dynamic table. *)
  IntSet.of_list
    Static_table.TokenIndices.
      [ token__path
      ; token_age
      ; token_content_length
      ; token_etag
      ; token_if_modified_since
      ; token_if_none_match
      ; token_location
      ; token_set_cookie
      ]

let[@inline] is_without_indexing token =
  token <> -1 && IntSet.mem token tokens_without_indexing

let[@inline] is_sensitive token value =
  token <> -1
  && (* From RFC7541§7.1.3: Never-Indexed Literals
      *   An encoder might also choose not to index values for header fields
      *   that are considered to be highly valuable or sensitive to recovery,
      *   such as the Cookie or Authorization header fields. *)
  Static_table.TokenIndices.(
    token == token_authorization
    || (token == token_cookie && String.length value < 20))

let[@inline] relative_index ~base absolute_index =
  (* a relative index of "0" refers to the entry with absolute index equal to
     Base - 1. *)
  base - 1 - absolute_index

let[@inline] post_base_index ~base absolute_index = absolute_index - base

module Instruction = struct
  (** Instructions sent to a peer's decoder *)

  let encode_set_dynamic_table_capacity t capacity =
    (* From RFC<QPACK-RFC>§4.3.1:
     *   An encoder informs the decoder of a change to the dynamic table
     *   capacity using an instruction that begins with the '001' three-bit
     *   pattern. This is followed by the new dynamic table capacity
     *   represented as an integer with a 5-bit prefix. *)
    let prefix = 0b0010_0000 in
    Qint.encode t prefix 5 capacity

  let encode_insert_with_name_reference t ~table ~base index value =
    (* From RFC<QPACK-RFC>§4.3.2:
     *   An encoder adds an entry to the dynamic table where the field name
     *   matches the field name of an entry stored in the static or the dynamic
     *   table using an instruction that starts with the '1' one-bit pattern. The
     *   second ('T') bit indicates whether the reference is to the static or
     *   dynamic table. The 6-bit prefix integer (Section 4.1.1) that follows is
     *   used to locate the table entry for the field name. *)
    let prefix, index =
      match table with
      | Static ->
        (* When T=1, the number represents the static table index; *)
        0b1100_0000, index
      | Dynamic ->
        (* when T=0, the number is the relative index of the entry in the
           dynamic table. *)
        0b1000_0000, relative_index ~base index
    in
    Qint.encode t prefix 6 index;
    (* The field name reference is followed by the field value represented as a
     * string literal; see Section 4.1.2. *)
    Qstring.encode t 0 8 value

  let encode_insert_without_name_reference t name value =
    (* From RFC<QPACK-RFC>§4.3.3:
     *   An encoder adds an entry to the dynamic table where both the field name
     *   and the field value are represented as string literals using an
     *   instruction that starts with the '01' two-bit pattern.
     *
     *   This is followed by the name represented as a 6-bit prefix string
     *   literal, and the value represented as an 8-bit prefix string literal;
     *   see Section 4.1.2. *)
    let name_prefix = 0b0100_0000 in
    Qstring.encode t name_prefix 6 name;
    (* The field name reference is followed by the field value represented as a
     * string literal; see Section 4.1.2. *)
    Qstring.encode t 0 8 value

  let encode_insert t ~static_name_idx ~dynamic_name_idx ~base name value =
    if static_name_idx <> not_found then
      encode_insert_with_name_reference
        t
        ~table:Static
        ~base
        static_name_idx
        value
    else if dynamic_name_idx <> not_found then
      encode_insert_with_name_reference
        t
        ~table:Dynamic
        ~base
        dynamic_name_idx
        value
    else
      encode_insert_without_name_reference t name value

  let encode_duplicate t ~base absolute_index =
    (* From RFC<QPACK-RFC>§4.3.4:
     *   An encoder duplicates an existing entry in the dynamic table using an
     *   instruction that begins with the '000' three-bit pattern. This is
     *   followed by the relative index of the existing entry represented as an
     *   integer with a 5-bit prefix; see Section 4.1.1. *)
    let prefix = 0b0000_0000 in
    Qint.encode t prefix 5 (relative_index ~base absolute_index)

  (** Instructions read from a peer's decoder. *)

  type decoder_instruction =
    | Section_ack of int64
    | Stream_cancelation of int64
    | Insert_count_increment of int

  let rec remove_last = function
    | [] | [ _ ] ->
      []
    | x :: xs ->
      x :: remove_last xs

  let stop_tracking t ~stream_id =
    match Hashtbl.find_opt t.stream_references stream_id with
    | Some sets ->
      (match remove_last sets with
      | [] ->
        Hashtbl.remove t.stream_references stream_id
      | sets' ->
        Hashtbl.replace t.stream_references stream_id sets')
    | None ->
      assert false

  let parser t =
    let open Angstrom in
    any_uint8 >>= fun b ->
    if b land 0b1000_0000 = 0b1000_0000 then
      (* From RFC<QPACK-RFC>§4.4.1:
       *   The instruction begins with the '1' one-bit pattern, followed by the
       *   field section's associated stream ID encoded as a 7-bit prefix
       *   integer; see Section 4.1.1. *)
      lift
        (fun stream_id ->
          let stream_id = Int64.of_int stream_id in
          stop_tracking t ~stream_id;
          Section_ack stream_id)
        (Qint.decode b 7)
    else if b land 0b0100_0000 = 0b0100_0000 then
      (* From RFC<QPACK-RFC>§4.4.2:
       *   The instruction begins with the '01' two-bit pattern, followed by the
       *   stream ID of the affected stream encoded as a 6-bit prefix integer. *)
      lift
        (fun stream_id ->
          (* From RFC<QPACK-RFC>§2.2.2.2:
           *   This signals to the encoder that all references to the dynamic
           *   table on that stream are no longer outstanding. *)
          let stream_id = Int64.of_int stream_id in
          stop_tracking t ~stream_id;
          Stream_cancelation stream_id)
        (Qint.decode b 6)
    else (
      assert (b land 0b1100_0000 = 0b0000_0000);
      (* From RFC<QPACK-RFC>§4.4.3:
       *   The Insert Count Increment instruction begins with the '00' two-bit
       *   pattern, followed by the Increment encoded as a 6-bit prefix integer. *)
      lift (fun inc -> Insert_count_increment inc) (Qint.decode b 6))
end

let encode_index_reference t ~table ~base absolute_index =
  (* From RFC<QPACK-RFC>§4.5.2:
   *   This representation starts with the '1' 1-bit pattern, followed by the
   *   'T' bit indicating whether the reference is into the static or dynamic
   *   table. The 6-bit prefix integer (Section 4.1.1) that follows is used to
   *   locate the table entry for the field line. *)
  match table with
  | Static ->
    (* When T=1, the number represents the static table index; *)
    Qint.encode t 0b1100_0000 6 absolute_index
  | Dynamic ->
    (* when T=0, the number is the relative index of the entry in the dynamic
       table. *)
    if absolute_index >= base then
      (* From RFC<QPACK-RFC>§4.5.3:
       *   An indexed field line with post-base index representation identifies
       *   an entry in the dynamic table with an absolute index greater than or
       *   equal to the value of the Base. *)
      Qint.encode t 0b0001_0000 4 (post_base_index ~base absolute_index)
    else
      Qint.encode t 0b1000_0000 6 (relative_index ~base absolute_index)

let encode_literal_with_name_reference t ~table ~base name_idx value =
  (* From RFC<QPACK-RFC>§4.5.5:
   *   This representation starts with the '01' two-bit pattern. The following
   *   bit, 'N', indicates whether an intermediary is permitted to add this
   *   field line to the dynamic table on subsequent hops. *)
  (match table with
  | Static ->
    (* When T=1, the number represents the static table index *)
    Qint.encode t 0b0101_0000 4 name_idx
  | Dynamic ->
    if name_idx >= base then
      (* From RFC<QPACK-RFC>§4.5.5:
       *   A literal field line with post-base name reference representation
       *   encodes a field line where the field name matches the field name of
       *   a dynamic table entry with an absolute index greater than or equal
       *   to the value of the Base. *)
      (* This is followed by a post-base index of the dynamic table entry (Section
       * 3.2.6) encoded as an integer with a 3-bit prefix; see Section 4.1.1. *)
      Qint.encode t 0b0000_0000 3 (post_base_index ~base name_idx)
    else
      (* when T=0, the number is the relative index of the entry in the dynamic
       * table. *)
      Qint.encode t 0b0100_0000 4 (relative_index ~base name_idx));
  (* the field value is encoded as an 8-bit prefix string literal; see Section
     4.1.2. *)
  Qstring.encode t 0 8 value

let encode_literal_without_name_reference t name value =
  (* From RFC<QPACK-RFC>§4.5.6:
   *   This representation begins with the '001' three-bit pattern. *)
  let prefix = 0b0010_0000 in
  (* The name follows, represented as a 4-bit prefix string literal, *)
  Qstring.encode t prefix 4 name;
  (* then the value, represented as an 8-bit prefix string literal; see Section
   * 4.1.2. *)
  Qstring.encode t 0 8 value

let encode_literal t ~static_name_idx ~dynamic_name_idx ~base name value =
  if static_name_idx <> not_found then
    encode_literal_with_name_reference
      t
      ~table:Static
      ~base
      static_name_idx
      value
  else if dynamic_name_idx <> not_found then
    encode_literal_with_name_reference
      t
      ~table:Dynamic
      ~base
      dynamic_name_idx
      value
  else
    encode_literal_without_name_reference t name value

let encode_section_prefix t f ~required_insert_count ~base =
  if required_insert_count = 0 then (
    (* From RFC<QPACK-RFC>§4.5.1:
     *   The Required Insert Count is encoded as an integer with an 8-bit
     *   prefix using the encoding described in Section 4.5.1.1. The Base is
     *   encoded as a sign bit ('S') and a Delta Base value with a 7-bit
     *   prefix; see Section 4.5.1.2. *)
    Qint.encode f 0 8 0;
    Qint.encode f 0 7 0)
  else
    let wireRIC =
      (required_insert_count mod (2 * Dynamic_table.max_entries t.table)) + 1
    in
    Qint.encode f 0x00 8 wireRIC;
    if base >= required_insert_count then
      Qint.encode f 0 7 (base - required_insert_count)
    else
      Qint.encode f 0b1000_0000 7 (required_insert_count - base - 1)

let req_insert_count_from_index ~required_insert_count absolute_index =
  (* From RFC<QPACK-RFC>§2.1.2:
   *   For a field section encoded using references to the dynamic table, the
   *   Required Insert Count is one larger than the largest absolute index of
   *   all referenced dynamic table entries. *)
  max required_insert_count (absolute_index + 1)

let encode_headers t ~stream_id ~encoder_buffer f headers =
  let cur_referenced_fields = ref IntSet.empty in
  let blockf = Faraday.create 0x200 in
  let base = t.next_seq in
  let required_insert_count =
    List.fold_left
      (fun required_insert_count { name; value; sensitive = _ } ->
        let name_idx, header_idx = Static_table.lookup name value in
        if header_idx <> Static_table.not_found then (
          (* static name + value -> static index reference *)
          encode_index_reference blockf ~table:Static ~base header_idx;
          required_insert_count)
        else
          let dynamic_name_index, dynamic_index =
            match HeaderFieldsTbl.find t.lookup_table name with
            | map ->
              (match ValueMap.find value map with
              | idx ->
                (* Header value is indexed in the dynamic table. *)
                idx, idx
              | exception Not_found ->
                let _, any_entry = ValueMap.choose map in
                any_entry, not_found)
            | exception Not_found ->
              not_found, not_found
          in
          let dynamic_index =
            if dynamic_index = not_found then
              (* Not found in the dynamic table, try to index. *)
              if
                (* TODO: should_index with never_indexed fields *)
                true
                && Dynamic_table.can_index
                     t.table
                     ~referenced_indices:
                       (all_referenced_indices
                          ~cur_referenced_fields:!cur_referenced_fields
                          t)
                     ~name
                     ~value
              then (
                (* save base before adding to the dynamic table. *)
                let base_for_encoder = t.next_seq in
                (* add to the dynamic table *)
                let maybe_added = add t ~cur_referenced_fields name value in
                (* From RFC<QPACK-RFC>§3.2.5:
                 *   In encoder instructions (Section 4.3), a relative index of
                 *   "0" refers to the most recently inserted value in the
                 *   dynamic table. Note that this means the entry referenced by
                 *   a given relative index will change while interpreting
                 *   instructions on the encoder stream. *)
                if maybe_added <> not_found then
                  Instruction.encode_insert
                    encoder_buffer
                    ~static_name_idx:name_idx
                    ~dynamic_name_idx:dynamic_name_index
                    ~base:base_for_encoder
                    name
                    value;
                (* with or without name reference based on dynamic_name_index
                   and static_name_index *)
                maybe_added)
              else
                dynamic_index
            else
              dynamic_index
          in
          (* Could not index, literal *)
          if dynamic_index = not_found then
            if dynamic_name_index <> not_found then (
              encode_literal
                blockf
                ~static_name_idx:name_idx
                ~dynamic_name_idx:dynamic_name_index
                ~base
                name
                value;
              cur_referenced_fields :=
                track_table_reference
                  t
                  dynamic_name_index
                  !cur_referenced_fields;
              req_insert_count_from_index
                ~required_insert_count
                dynamic_name_index)
            else (
              assert (dynamic_name_index = not_found);
              encode_literal
                blockf
                ~static_name_idx:name_idx
                ~dynamic_name_idx:dynamic_name_index
                ~base
                name
                value;
              required_insert_count)
          else (
            (* Dynamic Index reference *)
            assert (dynamic_index <> not_found);
            encode_index_reference blockf ~table:Dynamic ~base dynamic_index;
            cur_referenced_fields :=
              track_table_reference t dynamic_name_index !cur_referenced_fields;
            req_insert_count_from_index ~required_insert_count dynamic_index))
      (* From RFC<QPACK-RFC>§4.3.1:
       * For a field section encoded with no references to the dynamic table,
       * the Required Insert Count is zero. *)
      0
      headers
  in
  (match Hashtbl.find_opt t.stream_references stream_id with
  | Some sets ->
    Hashtbl.replace
      t.stream_references
      stream_id
      (!cur_referenced_fields :: sets)
  | None ->
    Hashtbl.add t.stream_references stream_id [ !cur_referenced_fields ]);
  let bs = Faraday.serialize_to_bigstring blockf in
  encode_section_prefix t f ~required_insert_count ~base;
  Faraday.schedule_bigstring f bs

let encode_header encoder t _headers =
  match encoder.dyn_table_capacity_change with
  | -1 ->
    ()
  | min_max_size ->
    encoder.dyn_table_capacity_change <- -1;
    (* From RFC<QPACK-RFC>§3.2.1:
     *   An encoder informs the decoder of a change to the dynamic table
     *   capacity using an instruction that begins with the '001' three-bit
     *   pattern. This is followed by the new dynamic table capacity
     *   represented as an integer with a 5-bit prefix. *)
    Qint.encode t 32 5 min_max_size

(* wtf is this doing anyway? *)
(* if encoder.table.max_size > min_max_size then *)
(* Qint.encode t 32 5 encoder.table.max_size *)

let set_capacity ({ table; _ } as t) new_capacity =
  Dynamic_table.set_capacity table new_capacity;
  match t.dyn_table_capacity_change with
  | -1 ->
    t.dyn_table_capacity_change <- new_capacity
  | lower_min_capacity when lower_min_capacity < new_capacity ->
    ()
  | _other ->
    t.dyn_table_capacity_change <- new_capacity
