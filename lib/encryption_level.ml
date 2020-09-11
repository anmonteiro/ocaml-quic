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

(* From RFC<QUIC-TLS-RFC>§2.1:
 *   Data is protected using a number of encryption levels:
 *
 *   Initial Keys
 *   Early Data (0-RTT) Keys
 *   Handshake Keys
 *   Application Data (1-RTT) Keys *)
type level =
  | Initial
  | Zero_RTT
  | Handshake
  | Application_data

let all = [ Initial; Zero_RTT; Handshake; Application_data ]

(* From RFC<QUIC-TLS-RFC>§4:
 *
 *     +---------------------+-----------------+------------------+
 *     | Packet Type         | Encryption Keys | PN Space         |
 *     +=====================+=================+==================+
 *     | Initial             | Initial secrets | Initial          |
 *     +---------------------+-----------------+------------------+
 *     | 0-RTT Protected     | 0-RTT           | Application data |
 *     +---------------------+-----------------+------------------+
 *     | Handshake           | Handshake       | Handshake        |
 *     +---------------------+-----------------+------------------+
 *     | Retry               | Retry           | N/A              |
 *     +---------------------+-----------------+------------------+
 *     | Version Negotiation | N/A             | N/A              |
 *     +---------------------+-----------------+------------------+
 *     | Short Header        | 1-RTT           | Application data |
 *     +---------------------+-----------------+------------------+
 *
 *               Table 1: Encryption Keys by Packet Type
 *)
let of_header = function
  | Packet.Header.Initial _ ->
    Initial
  | Long { packet_type; _ } ->
    (match packet_type with
    | Packet.Type.Initial ->
      (* Shouldn't be possible. *)
      Initial
    | Zero_RTT ->
      Zero_RTT
    | Handshake ->
      Handshake
    | Retry ->
      (* not protected. *)
      assert false)
  | Short _ ->
    Application_data

let next = function
  | Initial ->
    Handshake
  | Handshake ->
    Application_data
  | Zero_RTT ->
    failwith "Encryption_level.next: 0-RTT not supported"
  | Application_data ->
    failwith "Encryption_level.next: no level after Application Data"

let to_string = function
  | Initial ->
    "Initial"
  | Zero_RTT ->
    "Zero_RTT"
  | Handshake ->
    "Handshake"
  | Application_data ->
    "Application_data"

let pp_hum fmt t = Format.fprintf fmt "%s" (to_string t)

module Ord = struct
  type t = level

  let to_int = function
    | Initial ->
      0
    | Zero_RTT ->
      1
    | Handshake ->
      2
    | Application_data ->
      3

  let compare t1 t2 = compare (to_int t1) (to_int t2)

  let equal t1 t2 = compare t1 t2 = 0
end

module LMap = Map.Make (Ord)

type 'a t =
  { mutable current : level
  ; mutable vals : 'a LMap.t
  }

let create ~current = { current; vals = LMap.empty }

let add k v t = t.vals <- LMap.add k v t.vals

let remove k t = t.vals <- LMap.remove k t.vals

let find k t = LMap.find_opt k t.vals

let find_exn k t = LMap.find k t.vals

let find_current t = LMap.find_opt t.current t.vals

let find_current_exn t = LMap.find t.current t.vals

let update level f t =
  let vals' = LMap.update level f t.vals in
  t.vals <- vals'

let update_exn level f t =
  update
    level
    (function
      | None ->
        failwith "Encryption_level.update_exn: expected binding to exist."
      | Some x ->
        f x)
    t

let update_current f t = update t.current f t

let update_current_exn f t = update_exn t.current f t

let ordered_iter f t =
  (* From RFC<QUIC-RFC>§12.2:
   *   Coalescing packets in order of increasing encryption levels (Initial,
   *   0-RTT, Handshake, 1-RTT; see Section 4.1.4 of [QUIC-TLS]) makes it more
   *   likely the receiver will be able to process all the packets in a single
   *   pass.
   *
   * NOTE: Map.iter guarantees increasing ordering over the type of the keys. *)
  LMap.iter f t.vals

let fold f t a = LMap.fold f t.vals a

let mem lvl t = LMap.mem lvl t.vals
