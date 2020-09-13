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

(* From RFC<QPACK-RFC>§4.5.2:
 *   This document expands the definition of string literals by permitting them
 *   to begin other than on a byte boundary. An "N-bit prefix string literal"
 *   begins with the same Huffman flag, followed by the length encoded as an
 *   (N-1)-bit prefix integer. The prefix size, N, can have a value between 2
 *  and 8 inclusive. The remainder of the string literal is unmodified. *)
let[@inline] encode t prefix n s =
  (* N-bit prefix means we reserve 1 bit for the Huffman bit, and N-1 for the
   * prefix length *)
  let string_length = String.length s in
  let huffman_length = Huffman.encoded_length s in
  if huffman_length > string_length then (
    (* From RFC7541§5.2:
     *   The number of octets used to encode the string literal, encoded as an
     *   integer with a 7-bit prefix (see Section 5.1). *)
    Qint.encode t prefix (n - 1) string_length;
    (* From RFC7541§5.2:
     *   The encoded data of the string literal. If H is '0', then the encoded
     *   data is the raw octets of the string literal. If H is '1', then the
     *   encoded data is the Huffman encoding of the string literal. *)
    Faraday.write_string t s)
  else (
    (* From RFC7541§5.2:
     *   The number of octets used to encode the string literal, encoded as an
     *   integer with a 7-bit prefix (see Section 5.1). *)
    Qint.encode t (prefix lor (1 lsl (n - 1))) (n - 1) huffman_length;
    (* From RFC7541§5.2:
     *   The encoded data of the string literal. If H is '0', then the encoded
     *   data is the raw octets of the string literal. If H is '1', then the
     *   encoded data is the Huffman encoding of the string literal. *)
    Huffman.encode t s)

let decode n =
  let open Angstrom in
  (* From RFC<QPACK-RFC>§4.1.2:
   *   This document expands the definition of string literals by permitting
   *   them to begin other than on a byte boundary. An "N-bit prefix string
   *   literal" begins with the same Huffman flag, followed by the length
   *   encoded as an (N-1)-bit prefix integer. *)
  any_uint8 >>= fun h ->
  Qint.decode h (n - 1) >>= fun string_length ->
  lift
    (fun string_data ->
      (* From RFC7541§5.2:
       *   A one-bit flag, H, indicating whether or not the octets of the
       *   string are Huffman encoded. *)
      if h land (1 lsl (n - 1)) == 0 then
        Ok string_data
      else
        Huffman.decode string_data)
    (take string_length)
