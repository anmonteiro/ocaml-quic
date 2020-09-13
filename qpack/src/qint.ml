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

let encode t prefix n i =
  let max_prefix = (1 lsl n) - 1 in
  if i < max_prefix then
    (* From RFC7541§5.1:
     *   If the integer value is small enough, i.e., strictly less than 2^N-1,
     *   it is encoded within the N-bit prefix. *)
    Faraday.write_uint8 t (prefix lor i)
  else
    (* From RFC7541§5.1:
     *   Otherwise, all the bits of the prefix are set to 1, and the value,
     *   decreased by 2^N-1, is encoded using a list of one or more octets. The
     *   most significant bit of each octet is used as a continuation flag: its
     *   value is set to 1 except for the last octet in the list. The remaining
     *   bits of the octets are used to encode the decreased value. *)
    let i = i - max_prefix in
    Faraday.write_uint8 t (prefix lor max_prefix);
    let rec loop i =
      if i >= 128 then (
        Faraday.write_uint8 t (i land 127 lor 128);
        loop (i lsr 7))
      else
        Faraday.write_uint8 t i
    in
    loop i

(* From RFC7541§5.1:
 *   decode I from the next N bits. *)
let decode prefix n =
  let open Angstrom in
  let max_prefix = (1 lsl n) - 1 in
  let i = prefix land max_prefix in
  if i < max_prefix then
    return i
  else
    let rec loop i m =
      any_uint8 >>= fun b ->
      let i = i + ((b land 127) lsl m) in
      if b land 0b1000_0000 == 0b1000_0000 then
        loop i (m + 7)
      else
        return i
    in
    loop i 0
