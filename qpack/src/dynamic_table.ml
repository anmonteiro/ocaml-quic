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

type t =
  { mutable entries : (string * string * int) array
  ; mutable length : int
  ; mutable offset : int
  ; mutable capacity : int
        (* `length` above is the number of entries in the dynamic table. We
         * track the HPACK size in `size`.
         *
         * From RFC7541§4.1:
         *   The size of the dynamic table is the sum of the size of its
         *   entries.
         *
         *   The size of an entry is the sum of its name's length in octets (as
         *   defined in Section 5.2), its value's length in octets, and 32. *)
  ; mutable size : int
        (* From RFC7541§4.2:
         *   Protocols that use HPACK determine the maximum size that the
         *   encoder is permitted to use for the dynamic table. In HTTP/2, this
         *   value is determined by the SETTINGS_HEADER_TABLE_SIZE setting (see
         *   Section 6.5.2 of [HTTP2]). *)
  ; mutable max_size : int
  ; on_evict : string * string -> unit
  }

(* From RFC7541§4.1:
 *   The size of an entry is the sum of its name's length in octets (as defined
 *   in Section 5.2), its value's length in octets, and 32. *)
let default_entry = "", "", 32

let default_evict = Sys.opaque_identity (fun _ -> ())

let create ?(on_evict = default_evict) max_size =
  let capacity = max 256 max_size in
  { entries = Array.make capacity default_entry
  ; length = 0
  ; offset = 0
  ; capacity
  ; size = 0
  ; max_size
  ; on_evict
  }

let max_entries t =
  (* From RFC<QPACK-RFC>§4.5.1:
   *   MaxEntries = floor( MaxTableCapacity / 32 ) *)
  t.max_size / 32

let ( mod ) x y = ((x mod y) + y) mod y

let[@inline] offset_from_index t i = (t.capacity - 1 - i) mod t.capacity

let[@inline] _get t i = t.entries.((offset_from_index [@inlined]) t i)

let[@inline] get table i =
  let name, value, _ = _get table i in
  name, value

let[@inline] entry_size name value =
  (* From RFC<QPACK-RFC>§3.2.1:
   *   The size of an entry is the sum of its name's length in bytes, its
   *   value's length in bytes, and 32. The size of an entry is calculated
   *   using the length of its name and value without Huffman encoding applied.
   *)
  String.length name + String.length value + 32

let[@inline] eviction_offset { offset; length; capacity; _ } =
  (offset + length - 1) mod capacity

(* Note: Assumes table.size is positive. Doesn't perform any checking. *)
let evict_one ({ entries; on_evict; _ } as table) =
  let i = eviction_offset table in
  table.length <- table.length - 1;
  let name, value, entry_size = entries.(i) in
  entries.(i) <- default_entry;
  table.size <- table.size - entry_size;
  (* Don't bother calling if the eviction callback is not meaningful. *)
  if on_evict != default_evict then
    on_evict (name, value)

let increase_capacity table =
  let new_capacity = 2 * table.capacity in
  let new_entries =
    Array.init new_capacity (fun i ->
        if i < table.length then
          _get table i
        else
          default_entry)
  in
  table.entries <- new_entries;
  table.offset <- 0;
  table.capacity <- new_capacity

exception Local

let can_index t ~referenced_indices ~name ~value =
  let entry_size = entry_size name value in
  let cur_size = ref t.size in
  let cur_length = ref t.length in
  let prev_offset = t.offset in
  try
    while !cur_size > 0 && !cur_size + entry_size > t.max_size do
      let eviction_offset = (t.offset + !cur_length - 1) mod t.capacity in
      if
        prev_offset = eviction_offset
        || IntSet.mem eviction_offset referenced_indices
      then
        (* From RFC<QPACK-RFC>§2.1.1:
         *   A dynamic table entry cannot be evicted immediately after
         *   insertion, even if it has never been referenced. [...] If the
         *   dynamic table does not contain enough room for a new entry without
         *   evicting other entries, and the entries that would be evicted are
         *   not evictable, the encoder MUST NOT insert that entry into the
         *   dynamic table (including duplicates of existing entries). *)
        raise Local
      else (
        decr cur_length;
        let _name, _value, entry_size = t.entries.(eviction_offset) in
        cur_size := !cur_size - entry_size)
    done;
    true
  with
  | Local ->
    false

let evict_if_needed t ~entry_size =
  (* From RFC<QPACK-RFC>§3.2.2:
   *   Before a new entry is added to the dynamic table, entries are evicted
   *   from the end of the dynamic table until the size of the dynamic table is
   *   less than or equal to (table capacity - size of new entry). *)
  while t.size > 0 && t.size + entry_size > t.max_size do
    evict_one t
  done

let add ({ max_size; _ } as table) name value =
  let entry_size = (entry_size [@inlined]) name value in
  evict_if_needed table ~entry_size;
  (* From RFC7541§4.4:
   *   If the size of the new entry is less than or equal to the maximum size,
   *   that entry is added to the table. *)
  if table.size + entry_size <= max_size then (
    if table.length = table.capacity then
      increase_capacity table;
    table.length <- table.length + 1;
    table.size <- table.size + entry_size;
    let new_offset = (table.offset + table.capacity - 1) mod table.capacity in
    table.entries.(new_offset) <- name, value, entry_size;
    table.offset <- new_offset;
    true)
  else
    false

let[@inline] table_size table = table.length

let set_capacity table max_size =
  table.max_size <- max_size;
  (* From RFC7541§4.3:
   *   Whenever the maximum size for the dynamic table is reduced, entries are
   *   evicted from the end of the dynamic table until the size of the dynamic
   *   table is less than or equal to the maximum size. *)
  while table.size > max_size do
    evict_one table
  done
