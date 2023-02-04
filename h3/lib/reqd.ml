(*----------------------------------------------------------------------------
 *  Copyright (c) 2017 Inhabited Type LLC.
 *  Copyright (c) 2020 Antonio N. Monteiro.
 *
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  3. Neither the name of the author nor the names of his contributors
 *     may be used to endorse or promote products derived from this software
 *     without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS ``AS IS'' AND ANY EXPRESS
 *  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 *  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 *  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 *  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *---------------------------------------------------------------------------*)

type error =
  [ `Bad_request
  | `Internal_server_error
  | `Exn of exn
  ]

type error_handler =
  ?request:Request.t -> error -> (Headers.t -> [ `write ] Body.t) -> unit

module Writer = Serialize.Writer

type response_state =
  | Waiting
  | Streaming of Response.t * [ `write ] Body.t
  | Complete of Response.t

type t =
  { id : Quic.Stream_id.t
  ; request : Request.t
  ; request_body : [ `read ] Body.t
  ; stream : Quic.Stream.t
  ; writer : Writer.t
  ; encoder : Qpack.Encoder.t
  ; encoder_stream : Quic.Stream.t
  ; error_handler : error_handler
  ; mutable response_state : response_state
  ; mutable error_code : [ `Ok | error ] * Error.Code.t option
  }

let create
    error_handler
    ~stream_id
    ~encoder
    ~encoder_stream
    request
    request_body
    stream
    writer
  =
  { id = stream_id
  ; request
  ; request_body
  ; encoder
  ; encoder_stream
  ; stream
  ; writer
  ; error_handler
  ; response_state = Waiting
  ; error_code = `Ok, None
  }

let request t = t.request

let request_body t = t.request_body

let response t =
  match t.response_state with
  | Waiting ->
    None
  | Streaming (response, _) | Complete response ->
    Some response

let response_exn t =
  match t.response_state with
  | Waiting ->
    failwith "h2.Reqd.response_exn: response has not started"
  | Streaming (response, _) | Complete response ->
    response

let write_buffer_data writer buffer =
  match buffer with
  | `String str ->
    Writer.write_data writer str
  | `Bigstring bstr ->
    Writer.schedule_data writer bstr

let unsafe_respond_with_data t response data =
  match t.response_state with
  | Waiting ->
    let iovec, length =
      match data with
      | `String s ->
        `String s, String.length s
      | `Bigstring b ->
        `Bigstring b, Bigstringaf.length b
    in
    Writer.write_response_headers
      t.writer
      t.encoder
      ~encoder_stream:t.encoder_stream
      ~stream_id:t.id
      response;
    if length > 0 then
      write_buffer_data t.writer iovec;
    (* From RFC<HTTP3-RFC>§4.1:
     *   An HTTP request/response exchange fully consumes a client-initiated
     *   bidirectional QUIC stream. [...] After sending a final response, the
     *   server MUST close the stream for sending. *)
    Quic.Stream.close_writer t.stream;
    t.response_state <- Complete response
  | Streaming _ ->
    failwith "h3.Reqd.respond_with_*: response already started"
  | Complete _ ->
    failwith "h3.Reqd.respond_with_*: response already complete"

let respond_with_string t response str =
  if fst t.error_code <> `Ok then
    failwith
      "h3.Reqd.respond_with_string: invalid state, currently handling error";
  unsafe_respond_with_data t response (`String str)

let respond_with_bigstring t response bstr =
  if fst t.error_code <> `Ok then
    failwith
      "h3.Reqd.respond_with_bigstring: invalid state, currently handling error";
  unsafe_respond_with_data t response (`Bigstring bstr)

let unsafe_respond_with_streaming ~flush_headers_immediately:_ t response =
  match t.response_state with
  | Waiting ->
    let response_body = Body.create t.stream in
    Writer.write_response_headers
      t.writer
      t.encoder
      ~encoder_stream:t.encoder_stream
      ~stream_id:t.id
      response;
    t.response_state <- Streaming (response, response_body);
    response_body
  | Streaming _ ->
    failwith "h3.Reqd.respond_with_streaming: response already started"
  | Complete _ ->
    failwith "h3.Reqd.respond_with_streaming: response already complete"

let respond_with_streaming t ?(flush_headers_immediately = false) response =
  if fst t.error_code <> `Ok then
    failwith
      "h2.Reqd.respond_with_streaming: invalid state, currently handling error";
  unsafe_respond_with_streaming ~flush_headers_immediately t response

(* let _report_error ?request t exn error_code = match t.response_state, fst
   t.error_code with | Waiting, `Ok -> t.error_code <- (exn :> [ `Ok | error ]),
   Some error_code; let status = match (exn :> [ error | Status.standard ]) with
   | `Exn _ -> `Internal_server_error | #Status.standard as status -> status in
   t.error_handler ?request exn (fun headers -> let response = Response.create
   ~headers status in unsafe_respond_with_streaming
   ~flush_headers_immediately:true t response) | Waiting, `Exn _ -> (*
   XXX(seliopou): Decide what to do in this unlikely case. There is an *
   outstanding call to the [error_handler], but an intervening exception * has
   been reported as well. *) failwith "h2.Reqd.report_exn: NYI" | Streaming
   (_response, response_body), `Ok -> Body.close_writer response_body;
   t.error_code <- (exn :> [ `Ok | error ]), Some error_code; reset_stream t
   error_code | Streaming (_response, response_body), `Exn _ ->
   Body.close_writer response_body; t.error_code <- fst t.error_code, Some
   error_code; reset_stream t error_code; Writer.close_and_drain t.writer |
   (Complete _ | Streaming _ | Waiting), _ -> (* XXX(seliopou): Once additional
   logging support is added, log the error * in case it is not spurious. *) (*
   Still need to send an RST_STREAM frame. Set t.error_code with * `error_code`
   and `flush_response_body` below will take care of it. *) t.error_code <- fst
   t.error_code, Some error_code; reset_stream t error_code *)

let report_error t _exn _error_code =
  Body.close_reader t.request_body;
  (* TODO: *)
  (* _report_error t stream ~request exn error_code; *)
  ()

let report_exn t exn = report_error t (`Exn exn) Error.Code.Internal_error

let try_with t f : (unit, exn) result =
  try
    f ();
    Ok ()
  with
  | exn ->
    report_exn t exn;
    Error exn

(* Private API, not exposed to the user through h2.mli *)

let error_code t =
  match fst t.error_code with #error as error -> Some error | `Ok -> None
