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
  type transport_parameters =
    { initial_max_data : int
    ; max_idle_timeout : int
    ; initial_max_stream_data_bidi_local : int
    ; initial_max_stream_data_bidi_remote : int
    ; initial_max_stream_data_uni : int
    ; initial_max_streams_bidi : int
    ; initial_max_streams_uni : int
    }

  val default_transport_parameters : transport_parameters

  val default_max_datagram_size : int

  type t =
    { certificates : Tls.Config.own_cert
    ; alpn_protocols : string list
    ; transport_parameters : transport_parameters
    ; max_datagram_size : int
    }
end

module Crypto : sig
  type backend =
    [ `Legacy
    | `OpenSSL
    ]

  val backend : backend ref
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

  val id : t -> Stream_id.t
  val direction : t -> Direction.t
  val peer_address : t -> string option

  val schedule_read
    :  t
    -> on_eof:(unit -> unit)
    -> on_read:(Bigstringaf.t -> off:int -> len:int -> unit)
    -> unit

  val write_uint8 : t -> int -> unit
  val write_char : t -> char -> unit
  val write_string : t -> ?off:int -> ?len:int -> string -> unit
  val write_bytes_unsafe : t -> ?off:int -> ?len:int -> bytes -> unit
  val write_bigstring : t -> ?off:int -> ?len:int -> Bigstringaf.t -> unit
  val write_bigstring_copy : t -> ?off:int -> ?len:int -> Bigstringaf.t -> unit
  val schedule_bigstring : t -> ?off:int -> ?len:int -> Bigstringaf.t -> unit
  val flush : t -> (unit -> unit) -> unit
  val close_reader : t -> unit
  val close_writer : t -> unit
  val is_closed : t -> bool
  val report_application_error : t -> int -> unit
  val unsafe_faraday : t -> Faraday.t
end

module Transport : sig
  type t
  type error_handler = int -> unit
  type on_error_handler = { on_error : error_handler }
  type start_stream = ?error_handler:error_handler -> Direction.t -> Stream.t
  type stream_handler = F of (Stream.t -> on_error_handler)

  val next_read_operation : t -> [ `Read | `Yield | `Close ]
  val on_timeout : t -> unit

  val read
    :  t
    -> client_address:string
    -> Bigstringaf.t
    -> off:int
    -> len:int
    -> int

  val read_eof : t -> Bigstringaf.t -> off:int -> len:int -> int
  val yield_reader : t -> (unit -> unit) -> unit

  val next_write_operation
    :  t
    -> [ `Writev of Faraday.bigstring Faraday.iovec list * string * string
       | `Yield of int64 option
       | `Close of int
       ]

  val report_write_result : t -> cid:string -> [ `Ok of int | `Closed ] -> unit
  val yield_writer : t -> (unit -> unit) -> unit
  val ready_to_write : t -> unit -> unit
  val report_exn : t -> exn -> unit
  val is_closed : t -> bool
  val shutdown : t -> unit

  module Server : sig
    val create
      :  now_ms:(unit -> int64)
      -> config:Config.t
      -> (cid:string -> start_stream:start_stream -> stream_handler)
      -> t
  end

  module Client : sig
    val create
      :  now_ms:(unit -> int64)
      -> config:Config.t
      -> (cid:string -> start_stream:start_stream -> stream_handler)
      -> t
  end

  val connect
    :  ?max_datagram_size:int
    -> t
    -> address:string
    -> host:string
    -> (cid:string -> start_stream:start_stream -> stream_handler)
    -> unit
end
