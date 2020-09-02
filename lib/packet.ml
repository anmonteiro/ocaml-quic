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

module CID = struct
  type t =
    { length : int
    ; id : string
    }

  let length = 8
end

module Version = struct
  type t =
    | Negotiation
    | Number of (* really an unsigned 32-bit int *)
                int32

  let parse = function
    | 0l ->
      (* From RFC<QUIC-RFC>§17.2.1:
       *   A Version Negotiation packet is inherently not version-specific.
       *   Upon receipt by a client, it will be identified as a Version
       *   Negotiation packet based on the Version field having a value of
       *   0. *)
      Negotiation
    | other ->
      Number other

  let serialize = function Negotiation -> Int32.zero | Number n -> n
end

module Header = struct
  module Type = struct
    type t =
      | Initial
      | Zero_RTT
      | Handshake
      | Retry

    let parse = function
      | 0x0 ->
        Initial
      | 0x1 ->
        Zero_RTT
      | 0x2 ->
        Handshake
      | 0x3 ->
        Retry
      | _ ->
        assert false

    let serialize = function
      | Initial ->
        0x0
      | Zero_RTT ->
        0x1
      | Handshake ->
        0x2
      | Retry ->
        0x3
  end

  type t =
    | Initial of
        { version : Version.t
        ; source_cid : CID.t
        ; dest_cid : CID.t
        ; token : string
        }
    | Zero_RTT of
        { version : Version.t
        ; source_cid : CID.t
        ; dest_cid : CID.t
        }
    | Handshake of
        { version : Version.t
        ; source_cid : CID.t
        ; dest_cid : CID.t
        }
    | Short of { dest_cid : CID.t }
end

type t =
  | VersionNegotiation of
      { source_cid : CID.t
      ; dest_cid : CID.t
      ; versions : Version.t list
      }
  | Crypt of
      { header : Header.t
      ; payload : Bigstringaf.t
      }
  | Retry of
      { version : Version.t
      ; source_cid : CID.t
      ; dest_cid : CID.t
      ; token : string
      ; pseudo : Bigstringaf.t
      ; tag : string
      }
