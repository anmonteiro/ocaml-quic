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
open Angstrom

type t =
  { table : Dynamic_table.t
  ; max_capacity : int
  ; mutable next_seq : int
  }

let create max_capacity =
  { table = Dynamic_table.create max_capacity; max_capacity; next_seq = 0 }

let set_capacity { table; max_capacity; _ } capacity =
  if capacity > max_capacity then
    (* From RFC7541§6.3:
     *   The new maximum size MUST be lower than or equal to the limit
     *   determined by the protocol using HPACK. A value that exceeds this
     *   limit MUST be treated as a decoding error. *)
    Error Decoding_error
  else (
    Dynamic_table.set_capacity table capacity;
    Ok ())

let[@inline] ok x = return (Ok x)

let[@inline] error x = return (Error x)

let add t name value =
  let ret = Dynamic_table.add t.table (name, value) in
  if ret then t.next_seq <- t.next_seq + 1;
  ret

let[@inline] absolute_of_relative ~base relative = base - 1 - relative

let[@inline] absolute_of_post_base ~base post_base = base + post_base

module Instruction = struct
  let encode_section_acknowledgement t ~stream_id =
    (* From RFC<QPACK-RFC>§4.4.1:
     *   The instruction begins with the '1' one-bit pattern, followed by the
     *   field section's associated stream ID encoded as a 7-bit prefix
     *   integer; see Section 4.1.1. *)
    let prefix = 0b1000_0000 in
    Qint.encode t prefix 7 stream_id

  let encode_stream_cancelation t ~stream_id =
    (* From RFC<QPACK-RFC>§4.4.2:
     *   The instruction begins with the '01' two-bit pattern, followed by the
     *   stream ID of the affected stream encoded as a 6-bit prefix integer. *)
    let prefix = 0b0100_0000 in
    Qint.encode t prefix 6 stream_id

  let encode_insert_count_increment t increment =
    (* From RFC<QPACK-RFC>§4.4.3:
     *   The Insert Count Increment instruction begins with the '00' two-bit
     *   pattern, followed by the Increment encoded as a 6-bit prefix integer. *)
    let prefix = 0b0000_0000 in
    Qint.encode t prefix 6 increment

  (* Returns the insert count increment for the instruction processed *)
  let parser t =
    let open Angstrom in
    peek_char_fail >>= fun c ->
    let b = Char.code c in
    (* From RFC<QPACK-RFC>§4.3.2:
     *   An encoder adds an entry to the dynamic table where the field name
     *   matches the field name of an entry stored in the static or the dynamic
     *   table using an instruction that starts with the '1' one-bit pattern.
     *   The second ('T') bit indicates whether the reference is to the static
     *   or dynamic table. *)
    if b land 0b1100_0000 = 0b1100_0000 then
      lift2
        (fun idx value ->
          (* When T=1, the number represents the static table index *)
          let name, _ = Static_table.table.(idx) in
          if add t name (Result.get_ok value) then 1 else 0)
        (any_uint8 >>= fun b -> Qint.decode b 6)
        (Qstring.decode 8)
    else if b land 0b1000_0000 = 0b1000_0000 then
      (* when T=0,* the number is the relative index of the entry in the dynamic
         table. *)
      lift2
        (fun idx value ->
          let name, _ =
            Dynamic_table.get
              t.table
              (absolute_of_relative ~base:t.next_seq idx)
          in
          if add t name (Result.get_ok value) then 1 else 0)
        (any_uint8 >>= fun b -> Qint.decode b 6)
        (Qstring.decode 8)
    else if b land 0b0100_0000 = 0b0100_0000 then
      (* From RFC<QPACK-RFC>§4.3.1:
       *   An encoder adds an entry to the dynamic table where both the field
       *   name and the field value are represented as string literals using an
       *   instruction that starts with the '01' two-bit pattern. *)
      lift2
        (fun name value ->
          if add t (Result.get_ok name) (Result.get_ok value) then 1 else 0)
        (Qstring.decode 6)
        (Qstring.decode 8)
    else if b land 0b0010_0000 = 0b0010_0000 then
      lift
        (fun max ->
          Result.get_ok (set_capacity t max);
          0)
        (any_uint8 >>= fun b -> Qint.decode b 5)
    else (
      assert (b land 0b0001_0000 = 0);
      lift
        (fun idx ->
          let name, value =
            Dynamic_table.get
              t.table
              (absolute_of_relative ~base:t.next_seq idx)
          in
          if add t name value then 1 else 0)
        (any_uint8 >>= fun b -> Qint.decode b 5))

  let manyp ~f p = fix (fun m -> lift2 f p m <|> return 0)

  let many1p ~f p = lift2 f p (manyp ~f p)

  let parser t =
    let f = Faraday.create 0x100 in
    let p = many1p ~f:(fun i acc -> acc + i) (parser t) in
    lift
      (fun insert_count_increment ->
        if insert_count_increment > 0 then
          (* From RFC<QPACK-RFC>§4.4.3:
           *   An encoder that receives an Increment field equal to zero, or
           *   one that increases the Known Received Count beyond what the
           *   encoder has sent MUST treat this as a connection error of type
           *   QPACK_DECODER_STREAM_ERROR. *)
          encode_insert_count_increment f insert_count_increment;
        Faraday.serialize_to_string f)
      p
end

let reconstruct_required_insert_count t ~encoded_insert_count =
  let total_inserts = t.next_seq in
  let max_entries = t.table.max_size / 32 in
  let full_range = 2 * max_entries in
  if encoded_insert_count = 0 then
    0
  else if encoded_insert_count > full_range then
    failwith "error"
  else
    let max_value = total_inserts + max_entries in
    let max_wrapped = max_value / full_range * full_range in
    let req_insert_count = max_wrapped + encoded_insert_count - 1 in
    (* If ReqInsertCount exceeds MaxValue, the Encoder's value must have wrapped
     * one fewer time *)
    if req_insert_count > max_value then
      if req_insert_count <= full_range then
        failwith "error"
      else
        req_insert_count - full_range
    else if req_insert_count = 0 then
      failwith "error"
    else
      req_insert_count

let section_prefix t =
  let open Angstrom in
  any_uint8 >>= fun b ->
  Qint.decode b 8 >>= fun req_insert_count ->
  any_uint8 >>= fun b ->
  Qint.decode b 7 >>| fun delta_base ->
  let sign = b land 0b1000_0000 = 0b1000_0000 in
  let req_insert_count =
    reconstruct_required_insert_count t ~encoded_insert_count:req_insert_count
  in
  let base =
    if not sign then
      req_insert_count + delta_base
    else
      req_insert_count - delta_base - 1
  in
  req_insert_count, base

let parser { table; _ } ~base =
  let open Angstrom in
  peek_char_fail >>= fun c ->
  let b = Char.code c in
  if b land 0b1100_0000 = 0b1100_0000 then
    (* From RFC<QPACK-RFC>§4.5.1:
     *   This representation starts with the '1' 1-bit pattern, followed by the
     *   'T' bit indicating whether the reference is into the static or dynamic
     *   table. *)
    lift
      (* When T=1, the number represents the static table index; *)
        (fun index -> Static_table.table.(index))
      (any_uint8 >>= fun b -> Qint.decode b 6)
  else if b land 0b1000_0000 = 0b1000_0000 then
    lift
      (* when T=0, the number is the relative index of the entry in the dynamic
         table. *)
        (fun idx ->
        let index = absolute_of_relative ~base idx in
        Dynamic_table.get table index)
      (any_uint8 >>= fun b -> Qint.decode b 6)
  else if b land 0b0100_0000 = 0b0100_0000 then
    (* From RFC<QPACK-RFC>§4.5.4:
     *   This representation starts with the '01' two-bit pattern. [...] The
     *   fourth ('T') bit indicates whether the reference is to the static or
     *   dynamic table. *)
    lift2
      (fun index value ->
        (* When T=1, the number represents the static table index; when T=0, the
         * number is the relative index of the entry in the dynamic table. *)
        let is_static = b land 0b0001_0000 = 0b0001_0000 in
        let name, _ =
          if is_static then
            Static_table.table.(index)
          else
            Dynamic_table.get table (absolute_of_relative ~base index)
        in
        name, Result.get_ok value)
      (any_uint8 >>= fun b -> Qint.decode b 4)
      (Qstring.decode 8)
  else if b land 0b0010_0000 = 0b0010_0000 then
    (* From RFC<QPACK-RFC>§4.3.1:
     *   This representation begins with the '001' three-bit pattern. *)
    lift2
      (fun name value -> Result.get_ok name, Result.get_ok value)
      (Qstring.decode 4)
      (Qstring.decode 8)
  else if b land 0b0001_0000 = 0b0001_0000 then
    (* From RFC<QPACK-RFC>§4.5.3:
     *   This representation starts with the '0001' 4-bit pattern. *)
    lift
      (fun idx ->
        let index = absolute_of_post_base ~base idx in
        Dynamic_table.get table index)
      (any_uint8 >>= fun b -> Qint.decode b 4)
  else (
    assert (b land 0b1111_0000 = 0b0000_0000);
    lift2
      (fun idx value ->
        let index = absolute_of_post_base ~base idx in
        let name, _ = Dynamic_table.get table index in
        name, Result.get_ok value)
      (any_uint8 >>= fun b -> Qint.decode b 3)
      (Qstring.decode 8))

let parser t =
  section_prefix t >>= fun (_req_insert_count, base) ->
  Angstrom.many1 (parser t ~base)

let decode_block = parser
