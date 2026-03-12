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

module Reader = Parse.Reader
module Stream = Quic.Stream
module Qdecoder = Qpack.Decoder.Buffered
module Writer = Serialize.Writer

type response_handler = Response.t -> Body.Reader.t -> unit

type error =
  [ `Malformed_response of string
  | `Invalid_response_body_length of Response.t
  | `Protocol_error of Error.t * string
  | `Exn of exn
  ]

type error_handler = error -> unit

type bidirectional_stream_state =
  | Uninitialized
  | Awaiting_response of response_handler
  | Received_response of Response.t * Body.Reader.t
  (* | Upgraded of Response.t *)
  | Closed

type stream =
  { stream : Stream.t
  ; direction : Quic.Direction.t
  ; writer : Writer.t
  ; mutable state : bidirectional_stream_state
  }

type critical_streams =
  { mutable control : stream option
  ; mutable peer_control : stream option
  ; mutable qencoder : Stream.t option
  ; mutable peer_qencoder : Stream.t option
  ; mutable qdecoder : Stream.t option
  ; mutable peer_qdecoder : Stream.t option
  }

type t =
  { mutable settings : Settings.t
        (* ; writer : Writer.t *)
        (* ; config : Config.t *)
  ; mutable saw_control_settings : bool
  ; mutable peer_goaway : int option
  ; critical_streams : critical_streams
  ; streams : (Quic.Stream_id.t, stream) Hashtbl.t
  ; error_handler : error_handler
  ; qpack_encoder : Qpack.Encoder.t
  ; qpack_decoder : Qdecoder.t
  ; start_stream : Quic.Transport.start_stream
  }

let close_with_h3_error stream code =
  Quic.Stream.report_application_error stream.stream (Error.Code.serialize code)

let handle_headers _t stream headers =
  (* let stream_id = Stream.id stream in *)
  if Headers.valid_response_headers headers
  then
    match Headers.get_multi_pseudo headers "status" with
    | [ status ] ->
      (match Message.body_length headers with
      | `Error _e -> failwith "ProtocolError"
      | _body_length ->
        (match stream.state with
        | Uninitialized | Received_response _ | Closed -> assert false
        | Awaiting_response response_handler ->
          let response = Response.create ~headers (Status.of_string status) in
          let response_body = Body.Reader.create (Bigstringaf.create 0x1000) in
          stream.state <- Received_response (response, response_body);
          response_handler response response_body))
    | _ -> failwith "no status in response"
  else failwith "something, look up in RFC"

let process_headers_frame t stream headers_block =
  let stream_id = Stream.id stream.stream in
  let f bs =
    match
      Angstrom.parse_bigstring
        ~consume:All
        (Qdecoder.parser t.qpack_decoder ~stream_id)
        bs
    with
    | Ok (Ok (headers, _instructions)) ->
      handle_headers t stream (Headers.of_qpack_list headers)
    | Ok (Error _) | Error _ -> assert false
  in
  match
    Qdecoder.decode_header_block t.qpack_decoder ~stream_id headers_block f
  with
  | _ -> ()

let flush_response_body response_body =
  if Body.Reader.has_pending_output response_body
  then
    try Body.Reader.execute_read response_body with
    | exn ->
      failwith
        (Format.asprintf "report error TODO: %s" (Printexc.to_string exn))
(* report_error t (`Exn exn) InternalError *)

let process_data_frame (_t : t) stream bs =
  match stream.state with
  | Received_response (_response, response_body) ->
    let faraday = Body.Reader.unsafe_faraday response_body in
    if not (Faraday.is_closed faraday)
    then Faraday.schedule_bigstring faraday bs
  | Awaiting_response _ | Uninitialized | Closed -> assert false

let process_settings_frame t stream _settings_list =
  match t.saw_control_settings with
  | false ->
    (match t.critical_streams.peer_control with
    | Some control_stream
      when Stream.id stream.stream = Stream.id control_stream.stream ->
      t.saw_control_settings <- true;
      () (* TODO: actually process settings *)
    | _ ->
      (* From RFC9114§7.2.4:
       *   If an endpoint receives a SETTINGS frame on a different stream, the
       *   endpoint MUST respond with a connection error of type
       *   H3_FRAME_UNEXPECTED. *)
      failwith "TODO: report error")
  | true ->
    (* From RFC9114§7.2.4:
     *   If an endpoint receives a second SETTINGS frame on the control stream,
     *   the endpoint MUST respond with a connection error of type
     *   H3_FRAME_UNEXPECTED. *)
    failwith "TODO: report error"

let is_client_initiated_bidirectional_stream_id id = id >= 0 && id land 0x3 = 0

let process_goaway_frame t stream id =
  if not (is_client_initiated_bidirectional_stream_id id)
  then close_with_h3_error stream Error.Code.Id_error
  else
    match t.peer_goaway with
    | None -> t.peer_goaway <- Some id
    | Some previous when id <= previous -> t.peer_goaway <- Some id
    | Some _ -> close_with_h3_error stream Error.Code.Id_error

let register_peer_control_stream t stream =
  match t.critical_streams.peer_control with
  | None ->
    t.critical_streams.peer_control <- Some stream;
    true
  | Some existing when Stream.id existing.stream = Stream.id stream.stream -> true
  | Some _ ->
    close_with_h3_error stream Error.Code.Stream_creation_error;
    false

let register_peer_qencoder_stream t stream =
  match t.critical_streams.peer_qencoder with
  | None ->
    t.critical_streams.peer_qencoder <- Some stream.stream;
    true
  | Some existing when Stream.id existing = Stream.id stream.stream -> true
  | Some _ ->
    close_with_h3_error stream Error.Code.Stream_creation_error;
    false

let register_peer_qdecoder_stream t stream =
  match t.critical_streams.peer_qdecoder with
  | None ->
    t.critical_streams.peer_qdecoder <- Some stream.stream;
    true
  | Some existing when Stream.id existing = Stream.id stream.stream -> true
  | Some _ ->
    close_with_h3_error stream Error.Code.Stream_creation_error;
    false

let read_eof _t stream ~reader () =
  Reader.read_with_more reader Bigstringaf.empty Complete;
  match stream.state with
  | Received_response (_response, response_body) ->
    flush_response_body response_body;
    Body.Reader.close response_body
  | Uninitialized -> ()
  | _ -> assert false

let read_eof_unidirectional _t _stream ~reader () =
  Reader.read_with_more reader Bigstringaf.empty Complete;
  ()

let parser_input bs ~off ~len =
  if off = 0 && len = Bigstringaf.length bs then bs else Bigstringaf.sub bs ~off ~len

(* TODO: need to schedule read again. *)
let rec read t stream ~reader bs ~off ~len =
  Reader.read_with_more reader (parser_input bs ~off ~len) Incomplete;
  (match stream.state with
  | Received_response (_response, response_body) ->
    flush_response_body response_body
  | Awaiting_response _ | Uninitialized | Closed -> ());
  Stream.schedule_read
    stream.stream
    ~on_eof:(read_eof t stream ~reader)
    ~on_read:(read t stream ~reader)

let rec read_unidirectional t stream ~reader bs ~off ~len =
  Reader.read_with_more reader (parser_input bs ~off ~len) Incomplete;
  Stream.schedule_read
    stream.stream
    ~on_eof:(read_eof t stream ~reader)
    ~on_read:(read_unidirectional t stream ~reader)

(* From RFC<HTTP3-RFC>§8.1:
 *   After the QUIC connection is established, a SETTINGS frame (Section
 *   7.2.4) MUST be sent by each endpoint as the initial frame of their
 *   respective HTTP control stream; see Section 6.2.1. *)
let frame_handler t (stream : stream) frame =
  match frame with
  | Frame.Headers header_block -> process_headers_frame t stream header_block
  | Data bs -> process_data_frame t stream bs
  | Settings settings -> process_settings_frame t stream settings
  | Push_promise _ -> assert false
  | Cancel_push _ -> ()
  | Max_push_id _ -> ()
  | GoAway id -> process_goaway_frame t stream id
  | Ignored _ | Unknown _ -> ()

let start_unidirectional_stream ~start_stream unitype =
  let stream = start_stream Quic.Direction.Unidirectional in
  Writer.write_unidirectional_stream_type stream unitype;
  stream

let start_control_stream ~start_stream =
  let quic_stream = start_unidirectional_stream ~start_stream Control in
  let control_stream =
    { stream = quic_stream
    ; direction = Unidirectional
    ; writer = Writer.create quic_stream
    ; state = Uninitialized
    }
  in
  control_stream

let unistream_frame_handler t (stream : stream) unitype =
  let open Angstrom in
  match unitype with
  | Unidirectional_stream.Qencoder ->
    if register_peer_qencoder_stream t stream
    then
      let f = Faraday.create 0x100 in
      (Qdecoder.parse_instructions t.qpack_decoder f >>| function
       | Ok () -> Ok ()
       | Error _ -> Ok ())
    else Reader.ignored_stream
  | Qdecoder ->
    if register_peer_qdecoder_stream t stream
    then
      let rec parse_qdecoder_stream () =
        peek_char >>= function
        | None -> return (Ok ())
        | Some _ ->
          Qpack.Encoder.Instruction.parser t.qpack_encoder >>= function
          | Ok _ -> parse_qdecoder_stream ()
          | Error _ -> return (Ok ())
      in
      parse_qdecoder_stream ()
    else Reader.ignored_stream
  | Control ->
    if register_peer_control_stream t stream
    then Reader.http3_frames (frame_handler t stream)
    else Reader.ignored_stream
  | Push _ ->
    (* Client shouldn't send push frames. *)
    assert false
  | Ignored _ | Unknown _ ->
    (* From RFC<HTTP3-RFC>§8.1:
     *   Stream types of the format 0x1f * N + 0x21 for non-negative integer
     *   values of N are reserved to exercise the requirement that unknown
     *   types be ignored. These streams have no semantics, and can be sent
     *   when application-layer padding is desired. *)
    Reader.ignored_stream

let bidirectional_frames t stream =
  let reader = Reader.bidirectional_frames (frame_handler t stream) in
  reader

(* ?(config = Config.default) *)
let create ~error_handler ~cid:_ ~(start_stream : Quic.Transport.start_stream) =
  let settings = Settings.default in
  let t =
    { settings (* ; config *)
    ; saw_control_settings = false
    ; peer_goaway = None
    ; streams = Hashtbl.create ~random:true 1024
    ; error_handler
    ; qpack_encoder = Qpack.Encoder.create 0
    ; qpack_decoder = Qdecoder.create ~max_size:0 ~max_blocked_streams:100
    ; critical_streams =
        { control = Some (start_control_stream ~start_stream)
        ; peer_control = None
        ; qencoder = Some (start_unidirectional_stream ~start_stream Qencoder)
        ; peer_qencoder = None
        ; qdecoder = Some (start_unidirectional_stream ~start_stream Qdecoder)
        ; peer_qdecoder = None
        }
    ; start_stream : Quic.Transport.start_stream
    }
  in
  (* From RFC9114§6.2.1:
   *   Each side MUST initiate a single control stream at the beginning of
   *   the connection and send its SETTINGS frame as the first frame on this
   *   stream. *)
  Writer.write_settings
    (Option.get t.critical_streams.control).writer
    Settings.default;

  ( t
  , Quic.Transport.F
      (fun quic_stream ->
        let id = Stream.id quic_stream in
        let direction = Stream.direction quic_stream in
        let stream =
          match Hashtbl.find_opt t.streams id with
          | Some _stream -> assert false
          | None ->
            { stream = quic_stream
            ; direction
            ; writer = Writer.create quic_stream
            ; state = Uninitialized
            }
        in
        (match direction with
        | Quic.Direction.Unidirectional ->
          let reader =
            Reader.unirectional_frames (unistream_frame_handler t stream)
          in
          Stream.schedule_read
            stream.stream
            ~on_eof:(read_eof_unidirectional t stream ~reader)
            ~on_read:(read_unidirectional t stream ~reader)
        | Bidirectional ->
          let reader = bidirectional_frames t stream in
          Stream.schedule_read
            stream.stream
            ~on_eof:(read_eof t stream ~reader)
            ~on_read:(read t stream ~reader));
        Hashtbl.add t.streams id stream;
        { Quic.Transport.on_error =
            (fun code ->
              Format.eprintf "H3 ERROR CODE: %d@." code;
              ())
        }) )

let make_error_handler ~(error_handler : error_handler)
    : Quic.Transport.error_handler
  =
 fun code ->
  let error_code = Error.Code.parse code in
  let error = Error.StreamError error_code in
  error_handler (`Protocol_error (error, Error.message error))

let request t request ~error_handler ~response_handler =
  let quic_stream =
    let error_handler = make_error_handler ~error_handler in
    t.start_stream ~error_handler Quic.Direction.Bidirectional
  in
  let stream =
    { stream = quic_stream
    ; direction = Bidirectional
    ; writer = Writer.create quic_stream
    ; state = Awaiting_response response_handler
    }
  in
  let stream_id = Stream.id quic_stream in
  Hashtbl.replace t.streams stream_id stream;
  let request_body = Body.Writer.create quic_stream in
  Writer.write_request_like_frame
    stream.writer
    ~stream_id
    ~encoder_stream:(Option.get t.critical_streams.qencoder)
    t.qpack_encoder
    request;

  let reader = bidirectional_frames t stream in
  Stream.schedule_read
    stream.stream
    ~on_eof:(read_eof t stream ~reader)
    ~on_read:(read t stream ~reader);

  (* Closing the request body puts the stream in the half-closed (local) state.
   * This is handled by {!Respd.flush_request_body}, which transitions the
   * state once it verifies that there's no more data to send for the
   * stream. *)
  request_body
