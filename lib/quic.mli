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

module Config : sig
  type t =
    { certificates : Tls.Config.own_cert
    ; alpn_protocols : string list
    }
end

module IOVec : sig
  type 'a t = 'a Faraday.iovec =
    { buffer : 'a
    ; off : int
    ; len : int
    }

  val length : _ t -> int

  val lengthv : _ t list -> int

  val shift : 'a t -> int -> 'a t

  val shiftv : 'a t list -> int -> 'a t list

  val pp_hum : Format.formatter -> _ t -> unit [@@ocaml.toplevel_printer]
end

module Stream_id : sig
  type t = int64

  val is_bidi : t -> bool

  val is_uni : t -> bool

  val is_client_initiated : t -> bool

  val is_server_initiated : t -> bool
end

module Direction : sig
  type t =
    | Unidirectional
    | Bidirectional

  val classify : Stream_id.t -> t
end

module Stream : sig
  type t

  val schedule_read
    :  t
    -> on_eof:(unit -> unit)
    -> on_read:(Bigstringaf.t -> off:int -> len:int -> unit)
    -> unit

  val write_uint8 : t -> int -> unit

  val write_char : t -> char -> unit

  val write_string : t -> ?off:int -> ?len:int -> string -> unit

  val write_bigstring : t -> ?off:int -> ?len:int -> Bigstringaf.t -> unit

  val schedule_bigstring : t -> ?off:int -> ?len:int -> Bigstringaf.t -> unit

  val flush : t -> (unit -> unit) -> unit

  val close_reader : t -> unit

  val close_writer : t -> unit

  val is_closed : t -> bool

  val unsafe_faraday : t -> Faraday.t
end

module Server_connection : sig
  type 'a t

  val create
    :  config:Config.t
    -> (Stream.t -> direction:Direction.t -> id:Stream_id.t -> unit)
    -> _ t

  val next_read_operation : _ t -> [ `Read | `Yield | `Close ]

  val read
    :  'a t
    -> client_address:'a
    -> Bigstringaf.t
    -> off:int
    -> len:int
    -> int

  val read_eof : _ t -> Bigstringaf.t -> off:int -> len:int -> int

  val yield_reader : _ t -> (unit -> unit) -> unit

  val next_write_operation
    :  'a t
    -> [ `Writev of Faraday.bigstring Faraday.iovec list * 'a * string
       | `Yield
       | `Close of int
       ]

  val report_write_result
    :  _ t
    -> cid:string
    -> [ `Ok of int | `Closed ]
    -> unit

  val yield_writer : _ t -> (unit -> unit) -> unit

  val report_exn : _ t -> exn -> unit

  val is_closed : _ t -> bool
end
