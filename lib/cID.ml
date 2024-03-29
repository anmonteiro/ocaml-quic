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

type t = string

let empty = Sys.opaque_identity ""
let[@inline] length t = String.length t
let src_length = 20
let is_empty t = t == empty
let is_unset t = t = empty

let parse =
  let open Angstrom in
  (* From RFC<QUIC-RFC>§17.2:
   *   This length is encoded as an 8-bit unsigned integer. In QUIC version 1,
   *   this value MUST NOT exceed 20. Endpoints that receive a version 1 long
   *   header with a value larger than 20 MUST drop the packet.  Servers SHOULD
   *   be able to read longer connection IDs from other QUIC versions in order
   *   to properly form a version negotiation packet. *)
  any_uint8 >>= take

let serialize f t =
  Faraday.write_uint8 f (length t);
  Faraday.write_string f t

let to_string t = t
let of_string t = t
let compare = String.compare
let equal = String.equal

let generate () =
  let random_bytes n = Mirage_crypto_rng.generate n |> Cstruct.to_string in
  random_bytes 20
