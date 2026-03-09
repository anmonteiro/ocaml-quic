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

type request_handler = Reqd.t -> unit

type error =
  [ `Bad_request
  | `Internal_server_error
  | `Exn of exn
  ]

type error_handler =
  ?request:Request.t -> error -> (Headers.t -> Body.Writer.t) -> unit

type stream =
  { stream : Stream.t
  ; direction : Quic.Direction.t
  ; mutable reqd : Reqd.t option
  ; writer : Writer.t
  }

type critical_streams =
  { mutable control : stream
  ; mutable peer_control : stream option
  ; mutable qencoder : stream
  ; mutable peer_qencoder : Stream.t option
  ; mutable qdecoder : stream
  ; mutable peer_qdecoder : Stream.t option
  }

type t =
  { mutable settings : Settings.t
    (* ; writer : Writer.t *)
    (* ; config : Config.t *)
  ; mutable saw_control_settings : bool
  ; critical_streams : critical_streams
  ; streams : (Quic.Stream_id.t, stream) Hashtbl.t
  ; request_handler : request_handler
  ; error_handler : error_handler
  ; qpack_encoder : Qpack.Encoder.t
  ; qpack_decoder : Qdecoder.t
  }

let qpack_decompression_failed = 0x200
let qpack_encoder_stream_error = 0x201
let qpack_decoder_stream_error = 0x202

let close_connection stream code =
  Quic.Stream.report_application_error stream.stream code

let close_with_h3_error stream code =
  close_connection stream (Error.Code.serialize code)

let close_with_qpack_error stream = function
  | Qpack.QPACK_DECOMPRESSION_FAILED ->
    close_connection stream qpack_decompression_failed
  | Qpack.QPACK_ENCODER_STREAM_ERROR ->
    close_connection stream qpack_encoder_stream_error
  | Qpack.QPACK_DECODER_STREAM_ERROR ->
    close_connection stream qpack_decoder_stream_error

let default_error_handler ?request:_ error handle =
  let message =
    match error with
    | `Exn exn -> Printexc.to_string exn
    | (#Status.client_error | #Status.server_error) as error ->
      Status.to_string error
  in
  let body = handle Headers.empty in
  Body.Writer.write_string body message;
  Body.Writer.close body

let handle_headers t ({ stream; writer; _ } as stream_state) headers =
  let stream_id = Stream.id stream in
  match Headers.method_path_and_scheme_or_malformed headers with
  | `Malformed -> `Malformed
  | `Valid (meth, path, scheme) ->
    (match Message.body_length headers with
    | `Error _e -> `Malformed
    | _body_length ->
      let request =
        Request.create ~scheme ~headers (Httpaf.Method.of_string meth) path
      in
      let request_body = Body.Reader.create (Bigstringaf.create 0x1000) in
      let reqd =
        Reqd.create
          t.error_handler
          ~stream_id
          ~encoder:t.qpack_encoder
          ~encoder_stream:t.critical_streams.qencoder.stream
          request
          request_body
          stream
          writer
      in
      stream_state.reqd <- Some reqd;
      t.request_handler reqd;
      `Ok)

let process_headers_frame t stream headers_block =
  let stream_id = Stream.id stream.stream in
  let f bs =
    try
      match
        Angstrom.parse_bigstring
          ~consume:All
          (Qdecoder.parser t.qpack_decoder ~stream_id)
          bs
      with
      | Ok (Ok (headers, _instructions)) ->
        (match handle_headers t stream (Headers.of_qpack_list headers) with
        | `Ok -> ()
        | `Malformed -> close_with_h3_error stream Error.Code.Message_error)
      | Ok (Error qpack_error) -> close_with_qpack_error stream qpack_error
      | Error _ ->
        close_with_qpack_error stream Qpack.QPACK_DECOMPRESSION_FAILED
    with
    | _exn -> close_with_qpack_error stream Qpack.QPACK_DECOMPRESSION_FAILED
  in
  try
    match
      Qdecoder.decode_header_block t.qpack_decoder ~stream_id headers_block f
    with
    | Ok () -> ()
    | Error qpack_error -> close_with_qpack_error stream qpack_error
  with
  | _exn -> close_with_qpack_error stream Qpack.QPACK_DECOMPRESSION_FAILED

let process_data_frame stream bs =
  match stream.reqd with
  | None -> close_with_h3_error stream Error.Code.Frame_unexpected
  | Some reqd ->
    let request_body = Reqd.request_body reqd in
    let faraday = Body.Reader.unsafe_faraday request_body in
    if not (Faraday.is_closed faraday)
    then (
      Faraday.schedule_bigstring faraday bs;
      Body.Reader.execute_read request_body)

let process_settings_frame t stream settings =
  match t.saw_control_settings with
  | false ->
    (match t.critical_streams.peer_control with
    | Some control_stream
      when Stream.id stream.stream = Stream.id control_stream.stream ->
      if settings.Settings.has_h2_forbidden
      then close_with_h3_error stream Error.Code.Settings_error
      else t.saw_control_settings <- true
    | _ ->
      (* From RFC9114§7.2.4:
       *   If an endpoint receives a SETTINGS frame on a different stream, the
       *   endpoint MUST respond with a connection error of type
       *   H3_FRAME_UNEXPECTED. *)
      close_with_h3_error stream Error.Code.Frame_unexpected)
  | true ->
    (* From RFC9114§7.2.4:
     *   If an endpoint receives a second SETTINGS frame on the control stream,
     *   the endpoint MUST respond with a connection error of type
     *   H3_FRAME_UNEXPECTED. *)
    close_with_h3_error stream Error.Code.Frame_unexpected

let process_goaway_frame _t _id = ()

let is_peer_critical_stream t stream_id =
  let is_control =
    match t.critical_streams.peer_control with
    | Some stream -> Stream.id stream.stream = stream_id
    | None -> false
  in
  let is_qencoder =
    match t.critical_streams.peer_qencoder with
    | Some stream -> Stream.id stream = stream_id
    | None -> false
  in
  let is_qdecoder =
    match t.critical_streams.peer_qdecoder with
    | Some stream -> Stream.id stream = stream_id
    | None -> false
  in
  is_control || is_qencoder || is_qdecoder

let rec read t stream ~reader bs ~off ~len:_ =
  assert (off = 0);
  Reader.read_with_more reader bs Incomplete;
  Stream.schedule_read
    stream.stream
    ~on_eof:(read_eof t stream ~reader)
    ~on_read:(read t stream ~reader)

and read_eof t stream ~reader () =
  Reader.read_with_more reader Bigstringaf.empty Complete;
  if is_peer_critical_stream t (Stream.id stream.stream)
  then close_with_h3_error stream Error.Code.Closed_critical_stream

(* From RFC9114§8.1:
 *   After the QUIC connection is established, a SETTINGS frame (Section
 *   7.2.4) MUST be sent by each endpoint as the initial frame of their
 *   respective HTTP control stream; see Section 6.2.1. *)
let frame_handler t (stream : stream) frame =
  let is_peer_control_stream =
    match t.critical_streams.peer_control with
    | Some control_stream ->
      Stream.id stream.stream = Stream.id control_stream.stream
    | None -> false
  in
  if is_peer_control_stream
  then
    if not t.saw_control_settings
    then
      match frame with
      | Frame.Settings settings -> process_settings_frame t stream settings
      | _ -> close_with_h3_error stream Error.Code.Missing_settings
    else
      match frame with
      | Frame.Settings _ | Data _ | Headers _ ->
        close_with_h3_error stream Error.Code.Frame_unexpected
      | Push_promise _ | Max_push_id _ ->
        close_with_h3_error stream Error.Code.Frame_unexpected
      | GoAway id -> process_goaway_frame t id
      | Cancel_push _ | Ignored _ | Unknown _ -> ()
  else
    match frame with
    | Headers header_block -> process_headers_frame t stream header_block
    | Data bs -> process_data_frame stream bs
    | Cancel_push _ | Frame.Settings _ | Push_promise _ | Max_push_id _
    | GoAway _ ->
      close_with_h3_error stream Error.Code.Frame_unexpected
    | Ignored _ | Unknown _ -> ()

let start_unidirectional_stream
      ~(start_stream : Quic.Transport.start_stream)
      unitype
  =
  let stream = start_stream Quic.Direction.Unidirectional in
  Writer.write_unidirectional_stream_type stream unitype;
  stream

let start_unidirectional_stream ~start_stream typ =
  let quic_stream = start_unidirectional_stream ~start_stream typ in
  let control_stream =
    { stream = quic_stream
    ; direction = Unidirectional
    ; writer = Writer.create quic_stream
    ; reqd = None
    }
  in
  control_stream

let unistream_frame_handler t (stream : stream) unitype =
  (* TODO: check that these are only called once. The client shouldn't open more
     than one of these streams. *)
  let open Angstrom in
  match unitype with
  | Unidirectional_stream.Qencoder ->
    t.critical_streams.peer_qencoder <- Some stream.stream;
    let f = Stream.unsafe_faraday stream.stream in
    Qdecoder.parse_instructions t.qpack_decoder f >>| ( function
     | Ok () -> Ok ()
     | Error qpack_error ->
       close_with_qpack_error stream qpack_error;
       Ok () )
  | Qdecoder ->
    t.critical_streams.peer_qdecoder <- Some stream.stream;
    let rec parse_qdecoder_stream () =
      peek_char >>= function
      | None -> return (Ok ())
      | Some _ ->
        Qpack.Encoder.Instruction.parser t.qpack_encoder >>= ( function
         | Ok (Qpack.Encoder.Instruction.Insert_count_increment 0) ->
           close_connection stream qpack_decoder_stream_error;
           return (Ok ())
         | Ok _ -> parse_qdecoder_stream ()
         | Error _ ->
           close_connection stream qpack_decoder_stream_error;
           return (Ok ()) )
    in
    parse_qdecoder_stream ()
  | Control ->
    t.critical_streams.peer_control <- Some stream;
    Reader.http3_frames (frame_handler t stream)
  | Push _ ->
    (* Client shouldn't send push frames. *)
    assert false
  | Ignored _ ->
    (* From RFC9114§8.1:
     *   Stream types of the format 0x1f * N + 0x21 for non-negative integer
     *   values of N are reserved to exercise the requirement that unknown
     *   types be ignored. These streams have no semantics, and can be sent
     *   when application-layer padding is desired. *)
    Reader.ignored_stream

(* ?(config = Config.default) *)
let create
      ?(error_handler = default_error_handler)
      request_handler
      ~cid:_
      ~start_stream
  =
  let settings = Settings.default in
  let t =
    { settings (* ; config *)
    ; saw_control_settings = false
    ; streams = Hashtbl.create ~random:true 1024
    ; request_handler
    ; error_handler
    ; qpack_encoder = Qpack.Encoder.create 0
    ; qpack_decoder = Qdecoder.create ~max_size:0 ~max_blocked_streams:100
    ; critical_streams =
        { control = start_unidirectional_stream ~start_stream Control
        ; peer_control = None
        ; qencoder = start_unidirectional_stream ~start_stream Qencoder
        ; peer_qencoder = None
        ; qdecoder = start_unidirectional_stream ~start_stream Qdecoder
        ; peer_qdecoder = None
        }
    }
  in
  (* From RFC9114§6.2.1:
   *   Each side MUST initiate a single control stream at the beginning of
   *   the connection and send its SETTINGS frame as the first frame on this
   *   stream. *)
  Writer.write_settings t.critical_streams.control.writer Settings.default;

  Quic.Transport.F
    (fun quic_stream ->
      let id = Stream.id quic_stream in
      let direction = Stream.direction quic_stream in
      let stream =
        match Hashtbl.find_opt t.streams id with
        | Some _stream -> assert false
        | None ->
          { stream = quic_stream
          ; direction
          ; reqd = None
          ; writer = Writer.create quic_stream
          }
      in
      let reader =
        match direction with
        | Quic.Direction.Unidirectional ->
          Reader.unirectional_frames (unistream_frame_handler t stream)
        | Bidirectional ->
          Format.eprintf "bidi: %Ld@." id;
          Reader.bidirectional_frames (frame_handler t stream)
      in
      Stream.schedule_read
        stream.stream
        ~on_eof:(read_eof t stream ~reader)
        ~on_read:(read t stream ~reader);
      Hashtbl.add t.streams id stream;
      { Quic.Transport.on_error = ignore })
