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

type t = int64

(* From RFC<QUIC-RFC>§2.1:
 *   Streams are identified within a connection by a numeric value, referred to
 *   as the stream ID. A stream ID is a 62-bit integer (0 to 2^62-1) that is
 *   unique for all streams on a connection.
 *
 * Streams are 62 bit integers, but the last 2 bits are reserved (to
 * distinguish uni vs bidirectional and client vs server initiated).
 *)
let max = 1 lsl 60

(* From RFC<QUIC-RFC>§2.1:
 *   The second least significant bit (0x2) of the stream ID distinguishes
 *   between bidirectional streams (with the bit set to 0) [...]. *)
let is_bidi t = Int64.equal (Int64.logand t 0b10L) 0L

(* From RFC<QUIC-RFC>§2.1:
 *   The second least significant bit (0x2) of the stream ID distinguishes
 *   between [...] unidirectional streams (with the bit set to 1). *)
let is_uni t = not (Int64.equal (Int64.logand t 0b10L) 0L)

(* From RFC<QUIC-RFC>§2.1:
 *   The least significant bit (0x1) of the stream ID identifies the initiator
 *   of the stream. Client-initiated streams have even-numbered stream IDs
 *   (with the bit set to 0) [...]. *)
let is_client_initiated t = Int64.equal (Int64.logand t 0b1L) 0L

(* From RFC<QUIC-RFC>§2.1:
 *   The least significant bit (0x1) of the stream ID identifies the initiator
 *   of the stream. [...] server-initiated streams have odd-numbered stream IDs
 *   (with the bit set to 1). *)
let is_server_initiated t = Int64.equal (Int64.logand t 0b1L) 1L

let classify t =
  if is_bidi t then
    Stream.Direction.Bidirectional
  else
    Unidirectional
