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

module Method : module type of Httpaf.Method

module Status : sig
  include
    module type of Httpaf.Status
      with type client_error := Httpaf.Status.client_error
       and type standard := Httpaf.Status.standard
       and type t := Httpaf.Status.t

  (** The 4xx (Client Error) class of status code indicates that the client
      seems to have erred.

      See {{:https://tools.ietf.org/html/rfc7231#section-6.5} RFC7231§6.5} for
      more details.

      In addition to http/af, this type also includes the 421 (Misdirected
      Request) tag. See {{:https://tools.ietf.org/html/rfc7540#section-9.1.2}
      RFC7540§9.1.2} for more details. *)
  type client_error =
    [ Httpaf.Status.client_error
    | `Misdirected_request
    ]

  (** The status codes defined in the HTTP/1.1 RFCs, excluding the
      [Switching Protocols] status and including the [Misdirected Request] as
      per the HTTP/2 RFC.

      See {{:https://tools.ietf.org/html/rfc7540#section-8.1.1} RFC7540§8.1.1}
      and {{:https://tools.ietf.org/html/rfc7540#section-9.1.2} RFC7540§9.1.2}
      for more details. *)
  type standard =
    [ Httpaf.Status.standard
    | client_error
    ]

  (** The standard codes along with support for custom codes. *)
  type t =
    [ standard
    | `Code of int
    ]

  val default_reason_phrase : standard -> string
  (** [default_reason_phrase standard] is the example reason phrase provided by
      RFC7231 for the [standard] status code. The RFC allows servers to use
      reason phrases besides these in responses. *)

  val to_code : t -> int
  (** [to_code t] is the integer representation of [t]. *)

  val of_code : int -> t
  (** [of_code i] is the [t] representation of [i]. [of_code] raises [Failure]
      if [i] is not a positive three-digit number. *)

  val unsafe_of_code : int -> t
  (** [unsafe_of_code i] is equivalent to [of_code i], except it accepts any
      positive code, regardless of the number of digits it has. On negative
      codes, it will still raise [Failure]. *)

  val is_informational : t -> bool
  (** [is_informational t] is [true] iff [t] belongs to the Informational class
      of status codes. *)

  val is_successful : t -> bool
  (** [is_successful t] is [true] iff [t] belongs to the Successful class of
      status codes. *)

  val is_redirection : t -> bool
  (** [is_redirection t] is [true] iff [t] belongs to the Redirection class of
      status codes. *)

  val is_client_error : t -> bool
  (** [is_client_error t] is [true] iff [t] belongs to the Client Error class of
      status codes. *)

  val is_server_error : t -> bool
  (** [is_server_error t] is [true] iff [t] belongs to the Server Error class of
      status codes. *)

  val is_error : t -> bool
  (** [is_server_error t] is [true] iff [t] belongs to the Client Error or
      Server Error class of status codes. *)

  val to_string : t -> string

  val of_string : string -> t

  val pp_hum : Format.formatter -> t -> unit
end

module Headers : sig
  (** The type of a group of header fields. *)
  type t

  (** The type of a lowercase header name. *)
  type name = string

  (** The type of a header value. *)
  type value = string

  (** {3 Constructor} *)

  val empty : t
  (** [empty] is the empty collection of header fields. *)

  val of_list : (name * value) list -> t
  (** [of_list assoc] is a collection of header fields defined by the
      association list [assoc]. [of_list] assumes the order of header fields in
      [assoc] is the intended transmission order. The following equations should
      hold:

      - [to_list (of_list lst) = lst]
      - [get (of_list \[("k", "v1"); ("k", "v2")\]) "k" = Some "v2"]. *)

  val of_rev_list : (name * value) list -> t
  (** [of_list assoc] is a collection of header fields defined by the
      association list [assoc]. [of_list] assumes the order of header fields in
      [assoc] is the {i reverse} of the intended trasmission order. The
      following equations should hold:

      - [to_list (of_rev_list lst) = List.rev lst]
      - [get (of_rev_list \[("k", "v1"); ("k", "v2")\]) "k" = Some "v1"]. *)

  val to_list : t -> (name * value) list
  (** [to_list t] is the association list of header fields contained in [t] in
      transmission order. *)

  val to_rev_list : t -> (name * value) list
  (** [to_rev_list t] is the association list of header fields contained in [t]
      in {i reverse} transmission order. *)

  val add : t -> ?sensitive:bool -> name -> value -> t
  (** [add t ?sensitive name value] is a collection of header fields that is the
      same as [t] except with [(name, value)] added at the end of the
      trasmission order. Additionally, [sensitive] specifies whether this header
      field should not be compressed by HPACK and instead encoded as a
      never-indexed literal (see
      {{:https://tools.ietf.org/html/rfc7541#section-7.1.3} RFC7541§7.1.3} for
      more details).

      The following equations should hold:

      - [get (add t name value) name = Some value] *)

  val add_unless_exists : t -> ?sensitive:bool -> name -> value -> t
  (** [add_unless_exists t ?sensitive name value] is a collection of header
      fields that is the same as [t] if [t] already inclues [name], and
      otherwise is equivalent to [add t ?sensitive name value]. *)

  val add_list : t -> (name * value) list -> t
  (** [add_list t assoc] is a collection of header fields that is the same as
      [t] except with all the header fields in [assoc] added to the end of the
      transmission order, in reverse order. *)

  val add_multi : t -> (name * value list) list -> t
  (** [add_multi t assoc] is the same as

      {[
        add_list
          t
          (List.concat_map assoc ~f:(fun (name, values) ->
               List.map values ~f:(fun value -> name, value)))
      ]}

      but is implemented more efficiently. For example,

      {[
        add_multi t [ "name1", [ "x", "y" ]; "name2", [ "p", "q" ] ]
        = add_list [ "name1", "x"; "name1", "y"; "name2", "p"; "name2", "q" ]
      ]} *)

  val remove : t -> name -> t
  (** [remove t name] is a collection of header fields that contains all the
      header fields of [t] except those that have a header-field name that are
      equal to [name]. If [t] contains multiple header fields whose name is
      [name], they will all be removed. *)

  val replace : t -> ?sensitive:bool -> name -> value -> t
  (** [replace t ?sensitive name value] is a collection of header fields that is
      the same as [t] except with all header fields with a name equal to [name]
      removed and replaced with a single header field whose name is [name] and
      whose value is [value]. This new header field will appear in the
      transmission order where the first occurrence of a header field with a
      name matching [name] was found.

      If no header field with a name equal to [name] is present in [t], then the
      result is simply [t], unchanged. *)

  (** {3 Destructors} *)

  val mem : t -> name -> bool
  (** [mem t name] is [true] iff [t] includes a header field with a name that is
      equal to [name]. *)

  val get : t -> name -> value option
  (** [get t name] returns the last header from [t] with name [name], or [None]
      if no such header is present. *)

  val get_exn : t -> name -> value
  (** [get t name] returns the last header from [t] with name [name], or raises
      if no such header is present. *)

  val get_multi : t -> name -> value list
  (** [get_multi t name] is the list of header values in [t] whose names are
      equal to [name]. The returned list is in transmission order. *)

  (** {3 Iteration} *)

  val iter : f:(name -> value -> unit) -> t -> unit

  val fold : f:(name -> value -> 'a -> 'a) -> init:'a -> t -> 'a

  (** {3 Utilities} *)

  val to_string : t -> string

  val pp_hum : Format.formatter -> t -> unit
end

module Body : sig
  type 'rw t

  val schedule_read
    :  [ `read ] t
    -> on_eof:(unit -> unit)
    -> on_read:(Bigstringaf.t -> off:int -> len:int -> unit)
    -> unit
  (** [schedule_read t ~on_eof ~on_read] will setup [on_read] and [on_eof] as
      callbacks for when bytes are available in [t] for the application to
      consume, or when the input channel has been closed and no further bytes
      will be received by the application.

      Once either of these callbacks have been called, they become inactive. The
      application is responsible for scheduling subsequent reads, either within
      the [on_read] callback or by some other mechanism. *)

  val write_char : [ `write ] t -> char -> unit
  (** [write_char w char] copies [char] into an internal buffer. If possible,
      this write will be combined with previous and/or subsequent writes before
      transmission. *)

  val write_string : [ `write ] t -> ?off:int -> ?len:int -> string -> unit
  (** [write_string w ?off ?len str] copies [str] into an internal buffer. If
      possible, this write will be combined with previous and/or subsequent
      writes before transmission. *)

  val write_bigstring
    :  [ `write ] t
    -> ?off:int
    -> ?len:int
    -> Bigstringaf.t
    -> unit
  (** [write_bigstring w ?off ?len bs] copies [bs] into an internal buffer. If
      possible, this write will be combined with previous and/or subsequent
      writes before transmission. *)

  val schedule_bigstring
    :  [ `write ] t
    -> ?off:int
    -> ?len:int
    -> Bigstringaf.t
    -> unit
  (** [schedule_bigstring w ?off ?len bs] schedules [bs] to be transmitted at
      the next opportunity without performing a copy. [bs] should not be
      modified until a subsequent call to {!flush} has successfully completed. *)

  val flush : [ `write ] t -> (unit -> unit) -> unit
  (** [flush t f] makes all bytes in [t] available for writing to the awaiting
      output channel. Once those bytes have reached that output channel, [f]
      will be called.

      The type of the output channel is runtime-dependent, as are guarantees
      about whether those packets have been queued for delivery or have actually
      been received by the intended recipient. *)

  val close_reader : [ `read ] t -> unit
  (** [close_reader t] closes [t], indicating that any subsequent input received
      should be discarded. *)

  val close_writer : [ `write ] t -> unit
  (** [close_writer t] closes [t], causing subsequent write calls to raise. If
      [t] is writable, this will cause any pending output to become available to
      the output channel. *)

  val is_closed : _ t -> bool
  (** [is_closed t] is [true] if {!close} has been called on [t] and [false]
      otherwise. A closed [t] may still have pending output. *)
end

module Request : sig
  type t =
    { meth : Method.t
    ; target : string
    ; scheme : string
    ; headers : Headers.t
    }

  val create
    :  ?headers:Headers.t (** default is {!Headers.empty} *)
    -> scheme:string
    -> Method.t
    -> string
    -> t
  (** [create ?headers ~scheme meth target] creates an HTTP request with the
      given parameters. In HTTP/2, the [:scheme] pseudo-header field is required
      and includes the scheme portion of the target URI. The [headers] parameter
      is optional, however clients will want to include the [:authority]
      pseudo-header field in most cases. The [:authority] pseudo-header field
      includes the authority portion of the target URI, and should be used
      instead of the [Host] header field in HTTP/2.

      See {{:https://tools.ietf.org/html/rfc7540#section-8.1.2.3}
      RFC7540§8.1.2.4} for more details. *)

  val body_length
    :  t
    -> [ `Error of [ `Bad_request ] | `Fixed of int64 | `Unknown ]
  (** [body_length t] is the length of the message body accompanying [t].

      See {{:https://tools.ietf.org/html/rfc7230#section-3.3.3} RFC7230§3.3.3}
      for more details. *)

  val pp_hum : Format.formatter -> t -> unit
end

module Response : sig
  type t =
    { status : Status.t
    ; headers : Headers.t
    }

  val create
    :  ?headers:Headers.t (** default is {!Headers.empty} *)
    -> Status.t
    -> t
  (** [create ?headers status] creates an HTTP response with the given
      parameters. Unlike the [Response] type in http/af, h2 does not define a
      way for responses to carry reason phrases or protocol version.

      See {{:https://tools.ietf.org/html/rfc7540#section-8.1.2.4}
      RFC7540§8.1.2.4} for more details. *)

  val body_length
    :  t
    -> [ `Error of [ `Bad_request ] | `Fixed of int64 | `Unknown ]
  (** [body_length t] is the length of the message body accompanying [t].

      See {{:https://tools.ietf.org/html/rfc7230#section-3.3.3} RFC7230§3.3.3}
      for more details. *)

  val pp_hum : Format.formatter -> t -> unit
end

module Reqd : sig
  type t

  val request : t -> Request.t

  val request_body : t -> [ `read ] Body.t

  val response : t -> Response.t option

  val response_exn : t -> Response.t

  (** {3 Responding}

      The following functions will initiate a response for the corresponding
      request in [t]. When the response is fully transmitted to the wire, the
      stream completes.

      From {{:https://tools.ietf.org/html/rfc7540#section-8.1} RFC7540§8.1}: An
      HTTP request/response exchange fully consumes a single stream. *)

  val respond_with_string : t -> Response.t -> string -> unit

  val respond_with_bigstring : t -> Response.t -> Bigstringaf.t -> unit

  val respond_with_streaming
    :  t
    -> ?flush_headers_immediately:bool
    -> Response.t
    -> [ `write ] Body.t

  (** {3 Pushing}

      HTTP/2 allows a server to pre-emptively send (or "push") responses (along
      with corresponding "promised" requests) to a client in association with a
      previous client-initiated request. This can be useful when the server
      knows the client will need to have those responses available in order to
      fully process the response to the original request.

      {4 {b An additional note regarding server push:}}

      In HTTP/2, PUSH_PROMISE frames must only be sent in the open or
      half-closed ("remote") stream states. In practice, this means that calling
      {!Reqd.push} must happen before the entire response body for the
      associated client-initiated request has been written to the wire. As such,
      it is dangerous to start a server pushed response in association with
      either {!Reqd.respond_with_string} or {!Reqd.respond_with_bigstring}, as
      the entire body for the response that they produce is sent to the output
      channel immediately, causing the corresponding stream to enter the closed
      state.

      See {{:https://tools.ietf.org/html/rfc7540#section-8.2} RFC7540§8.2} for
      more details. *)

  (** {3 Exception Handling} *)

  val report_exn : t -> exn -> unit

  val try_with : t -> (unit -> unit) -> (unit, exn) result
end

module Server_connection : sig
  type error =
    [ `Bad_request
    | `Internal_server_error
    | `Exn of exn
    ]

  type request_handler = Reqd.t -> unit

  type error_handler =
    ?request:Request.t -> error -> (Headers.t -> [ `write ] Body.t) -> unit

  val create
    :  ?error_handler:error_handler
    -> request_handler
    -> cid:string
    -> start_stream:Quic.Server_connection.start_stream
    -> Quic.Server_connection.stream_handler
  (** [create ?config ?error_handler ~request_handler] creates a connection
      handler that will service individual requests with [request_handler]. *)

  (* val error_code : t -> error option *)
  (** [error_code t] returns the [error_code] that caused the connection to
      close, if one exists. *)
end
