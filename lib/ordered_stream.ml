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

(* From RFC<QUIC-RFC>§2.2:
 *   Endpoints MUST be able to deliver stream data to an application as an
 *   ordered byte-stream. Delivering an ordered byte-stream requires that an
 *   endpoint buffer any data that is received out of order, up to the
 *   advertised flow control limit. *)

type fragment = Bigstringaf.t IOVec.t

module Q : Psq.S with type k = int and type p = fragment =
  Psq.Make
    (Int)
    (struct
      type t = fragment

      let compare { IOVec.off = off1; _ } { IOVec.off = off2; _ } =
        compare off1 off2
    end)

type t =
  { mutable q : Q.t
  ; mutable offset : int (* TODO: int64? *)
  }

let create () = { q = Q.empty; offset = 0 }

let add ({ IOVec.off; len; _ } as fragment) t =
  (* From RFC<QUIC-RFC>§2.2:
   *   An endpoint could receive data for a stream at the same stream offset
   *   multiple times. Data that has already been received can be discarded. *)
  if t.offset < off + len then
    let q' = Q.add off fragment t.q in
    t.q <- q'

let pop t =
  match Q.pop t.q with
  | Some ((off, fragment), q') ->
    if off = t.offset then (
      t.offset <- t.offset + fragment.len;
      t.q <- q';
      Some fragment)
    else
      None
  | None ->
    None
