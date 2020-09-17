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

module Helpers = struct
  let manyp ~init ~f p =
    fix (fun m ->
        lift2
          (fun x y ->
            match x, y with
            | Ok x, Ok y ->
              Ok (f x y)
            | (Error _ as e), _ | _, (Error _ as e) ->
              e)
          p
          m
        <|> return (Ok init))

  let cons x xs = x :: xs

  let many1p ~init ~f p =
    lift2
      (fun x y ->
        match x, y with
        | Ok x, Ok y ->
          Ok (f x y)
        | (Error _ as e), _ | _, (Error _ as e) ->
          e)
      p
      (manyp ~f ~init p)
end

type t =
  { table : Dynamic_table.t
  ; max_capacity : int
  ; mutable insertion_count : int
  }

let create max_capacity =
  { table = Dynamic_table.create max_capacity
  ; max_capacity
  ; insertion_count = 0
  }

let set_capacity { table; max_capacity; _ } capacity =
  if capacity > max_capacity then
    (* From RFC<QPACK-RFC>§4.3.1:
     *   The decoder MUST treat a new dynamic table capacity value that exceeds
     *   this limit as a connection error of type QPACK_ENCODER_STREAM_ERROR. *)
    encoder_stream_error
  else (
    Dynamic_table.set_capacity table capacity;
    ok)

let add t name value =
  (* From RFC<QPACK-RFC>§3.2.2:
   *   It is an error if the encoder attempts to add an entry that is larger
   *   than the dynamic table capacity; the decoder MUST treat this as a
   *   connection error of type QPACK_ENCODER_STREAM_ERROR. *)
  if Dynamic_table.entry_size name value > t.table.max_size then
    encoder_stream_error
  else
    let ret = Dynamic_table.add t.table name value in
    if ret then t.insertion_count <- t.insertion_count + 1;
    Ok ret

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

  let add_returning_insert_count_increment t name value =
    match add t name value with
    | Ok true ->
      Ok 1
    | Ok false ->
      Ok 0
    | Error _ as err ->
      err

  (* Reads encoder instructions, returns the insert count increment for the
   * instruction processed *)
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
          Result.bind value (add_returning_insert_count_increment t name))
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
              (absolute_of_relative ~base:t.insertion_count idx)
          in
          Result.bind value (add_returning_insert_count_increment t name))
        (any_uint8 >>= fun b -> Qint.decode b 6)
        (Qstring.decode 8)
    else if b land 0b0100_0000 = 0b0100_0000 then
      (* From RFC<QPACK-RFC>§4.3.3:
       *   An encoder adds an entry to the dynamic table where both the field
       *   name and the field value are represented as string literals using an
       *   instruction that starts with the '01' two-bit pattern. *)
      lift2
        (fun name value ->
          match name, value with
          | Ok name, Ok value ->
            add_returning_insert_count_increment t name value
          | (Error _ as err), _ | _, (Error _ as err) ->
            err)
        (Qstring.decode 6)
        (Qstring.decode 8)
    else if b land 0b0010_0000 = 0b0010_0000 then
      lift
        (fun max -> Result.map (fun () -> 0) (set_capacity t max))
        (any_uint8 >>= fun b -> Qint.decode b 5)
    else (
      assert (b land 0b1110_0000 = 0);
      lift
        (fun idx ->
          let name, value =
            Dynamic_table.get
              t.table
              (absolute_of_relative ~base:t.insertion_count idx)
          in
          add_returning_insert_count_increment t name value)
        (any_uint8 >>= fun b -> Qint.decode b 5))

  let parser t =
    let f = Faraday.create 0x100 in
    let p = Helpers.many1p ~f:( + ) ~init:0 (parser t) in
    lift
      (function
        | Ok insert_count_increment ->
          if insert_count_increment > 0 then
            (* From RFC<QPACK-RFC>§4.4.3:
             *   An encoder that receives an Increment field equal to zero, or
             *   one that increases the Known Received Count beyond what the
             *   encoder has sent MUST treat this as a connection error of type
             *   QPACK_DECODER_STREAM_ERROR. *)
            encode_insert_count_increment f insert_count_increment;
          Ok (Faraday.serialize_to_string f)
        | Error _ as e ->
          e)
      p
end

let reconstruct_required_insert_count t ~encoded_insert_count =
  let max_entries = t.table.max_size / 32 in
  let full_range = 2 * max_entries in
  if encoded_insert_count = 0 then
    Ok 0
  else if encoded_insert_count > full_range then
    decompression_failed
  else
    let max_value = t.insertion_count + max_entries in
    let max_wrapped = max_value / full_range * full_range in
    let req_insert_count = max_wrapped + encoded_insert_count - 1 in
    (* If ReqInsertCount exceeds MaxValue, the Encoder's value must have wrapped
     * one fewer time *)
    if req_insert_count > max_value then
      if req_insert_count <= full_range then
        decompression_failed
      else
        Ok (req_insert_count - full_range)
    else if req_insert_count = 0 then
      decompression_failed
    else
      Ok req_insert_count

let section_prefix t =
  let open Angstrom in
  any_uint8 >>= fun b ->
  Qint.decode b 8 >>= fun req_insert_count ->
  any_uint8 >>= fun b ->
  Qint.decode b 7 >>| fun delta_base ->
  let sign = b land 0b1000_0000 = 0b1000_0000 in
  match
    reconstruct_required_insert_count t ~encoded_insert_count:req_insert_count
  with
  | Ok req_insert_count ->
    let base =
      if not sign then
        req_insert_count + delta_base
      else
        req_insert_count - delta_base - 1
    in
    Ok (req_insert_count, base)
  | Error _ as e ->
    e

let decode_header_block { table; _ } ~base =
  let open Angstrom in
  peek_char_fail >>= fun c ->
  let b = Char.code c in
  if b land 0b1100_0000 = 0b1100_0000 then
    (* From RFC<QPACK-RFC>§4.5.2:
     *   This representation starts with the '1' 1-bit pattern, followed by the
     *   'T' bit indicating whether the reference is into the static or dynamic
     *   table. *)
    lift
      (* When T=1, the number represents the static table index; *)
        (fun index -> Ok Static_table.table.(index))
      (any_uint8 >>= fun b -> Qint.decode b 6)
  else if b land 0b1000_0000 = 0b1000_0000 then
    lift
      (* when T=0, the number is the relative index of the entry in the dynamic
         table. *)
        (fun idx ->
        let index = absolute_of_relative ~base idx in
        Ok (Dynamic_table.get table index))
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
        Result.map (fun value -> name, value) value)
      (any_uint8 >>= fun b -> Qint.decode b 4)
      (Qstring.decode 8)
  else if b land 0b0010_0000 = 0b0010_0000 then
    (* From RFC<QPACK-RFC>§4.5.6:
     *   This representation begins with the '001' three-bit pattern. *)
    lift2
      (fun name value ->
        match name, value with
        | Ok name, Ok value ->
          Ok (name, value)
        | (Error _ as e), _ | _, (Error _ as e) ->
          e)
      (Qstring.decode 4)
      (Qstring.decode 8)
  else if b land 0b0001_0000 = 0b0001_0000 then
    (* From RFC<QPACK-RFC>§4.5.3:
     *   This representation starts with the '0001' 4-bit pattern. *)
    lift
      (fun idx ->
        let index = absolute_of_post_base ~base idx in
        Ok (Dynamic_table.get table index))
      (any_uint8 >>= fun b -> Qint.decode b 4)
  else (
    (* From RFC<QPACK-RFC>§4.5.5:
     *   This representation starts with the '0000' four-bit pattern. *)
    assert (b land 0b1111_0000 = 0b0000_0000);
    lift2
      (fun idx value ->
        let index = absolute_of_post_base ~base idx in
        let name, _ = Dynamic_table.get table index in
        Result.map (fun value -> name, value) value)
      (any_uint8 >>= fun b -> Qint.decode b 3)
      (Qstring.decode 8))

let parser t ~stream_id =
  section_prefix t >>= function
  | Ok (_req_insert_count, base) ->
    lift
      (function
        | Ok headers ->
          let f = Faraday.create 0x100 in
          Instruction.encode_section_acknowledgement
            f
            ~stream_id:(Int64.to_int stream_id);
          Ok (headers, Faraday.serialize_to_string f)
        | Error _ as e ->
          e)
      (Helpers.many1p ~init:[] ~f:Helpers.cons (decode_header_block t ~base))
  | Error _ as e ->
    return e

module Buffered = struct
  module StreamIdSet = Set.Make (Int64)

  type blocked =
    { required_insertion_count : int
    ; blocks : Bigstringaf.t list
    ; callback : Bigstringaf.t -> unit
    }

  module Q : Psq.S with type k = int64 and type p = blocked =
    Psq.Make
      (Int64)
      (struct
        type t = blocked

        let compare
            { required_insertion_count = ric1; _ }
            { required_insertion_count = ric2; _ }
          =
          compare ric1 ric2
      end)

  module AB = Angstrom.Buffered

  type nonrec t =
    { decoder : t
    ; mutable blocked_blocks : Q.t
    ; mutable blocked_streams : StreamIdSet.t
    ; max_blocked_streams : int
    }

  let create ~max_size ~max_blocked_streams =
    { decoder = create max_size
    ; blocked_blocks = Q.empty
    ; blocked_streams = StreamIdSet.empty
    ; max_blocked_streams
    }

  let rec process_blocked_streams t =
    match Q.pop t.blocked_blocks with
    | Some
        ( (stream_id, { required_insertion_count = ric; blocks = bs; callback })
        , q' ) ->
      assert (List.length bs = 1);
      assert (stream_id > 0L);
      if ric <= t.decoder.insertion_count then (
        t.blocked_blocks <- q';
        if not (Q.mem stream_id q') then
          t.blocked_streams <- StreamIdSet.remove stream_id t.blocked_streams;
        let chunks = List.rev bs in
        List.iter callback chunks;
        process_blocked_streams t)
    | None ->
      ()

  let parse_instructions t bs =
    match
      Angstrom.parse_bigstring ~consume:All (Instruction.parser t.decoder) bs
    with
    | Ok received_count_increment ->
      process_blocked_streams t;
      Ok received_count_increment
    | Error _ as e ->
      e

  let parse_header_block t ~stream_id bs f =
    match
      Angstrom.parse_bigstring ~consume:Prefix (section_prefix t.decoder) bs
    with
    | Ok (Ok (required_insertion_count, _base)) ->
      if required_insertion_count > t.decoder.insertion_count then (
        (* From RFC<QPACK-RFC>§2.1.2: * When the decoder receives an encoded
           field section with a Required * Insert Count greater than its own
           Insert Count, the stream cannot * be processed immediately, and is
           considered "blocked"; see Section * 2.2.1. *)
        t.blocked_streams <- StreamIdSet.add stream_id t.blocked_streams;
        let q' =
          Q.update
            stream_id
            (function
              | None ->
                Some { required_insertion_count; blocks = [ bs ]; callback = f }
              | Some ({ required_insertion_count = ric; blocks; _ } as found) ->
                assert (ric >= required_insertion_count);
                Some { found with blocks = bs :: blocks })
            t.blocked_blocks
        in
        t.blocked_blocks <- q')
      else
        f bs;
      ok
    | Ok (Error _ as e) ->
      e
    | Error _ ->
      decompression_failed
end
