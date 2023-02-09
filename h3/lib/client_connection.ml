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
  ; mutable qencoder : Stream.t option
  ; mutable qdecoder : Stream.t option
  }

type t =
  { mutable settings : Settings.t
        (* ; writer : Writer.t *)
        (* ; config : Config.t *)
  ; mutable saw_control_settings : bool
  ; critical_streams : critical_streams
  ; streams : (Quic.Stream_id.t, stream) Hashtbl.t
  ; error_handler : error_handler
  ; qpack_encoder : Qpack.Encoder.t
  ; qpack_decoder : Qdecoder.t
  ; start_stream : Quic.Transport.start_stream
  }

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
    then (
      Faraday.schedule_bigstring faraday bs;
      flush_response_body response_body)
  | Awaiting_response _ | Uninitialized | Closed -> assert false

let process_settings_frame _t _settings_list = failwith "NYI: settings"
let process_goaway_frame _t _id = failwith "NYI: goaway"

let read_eof _t stream ~reader () =
  Reader.read_with_more reader Bigstringaf.empty Complete;
  match stream.state with
  | Received_response (_response, response_body) ->
    Body.Reader.close response_body
  | Uninitialized -> ()
  | _ -> assert false

(* TODO: need to schedule read again. *)
let rec read t stream ~reader bs ~off ~len:_ =
  assert (off = 0);
  Reader.read_with_more reader bs Incomplete;
  Stream.schedule_read
    stream.stream
    ~on_eof:(read_eof t stream ~reader)
    ~on_read:(read t stream ~reader)

(* From RFC<HTTP3-RFC>§8.1:
 *   After the QUIC connection is established, a SETTINGS frame (Section
 *   7.2.4) MUST be sent by each endpoint as the initial frame of their
 *   respective HTTP control stream; see Section 6.2.1. *)
let frame_handler t (stream : stream) r =
  match r with
  | Error _e ->
    (* report_error t e *)
    ()
  | Ok frame ->
    (match frame with
    | Frame.Headers header_block -> process_headers_frame t stream header_block
    | Data bs -> process_data_frame t stream bs
    | Settings settings -> process_settings_frame t settings
    | Push_promise _ -> assert false
    | Cancel_push _ -> ()
    | Max_push_id _ -> ()
    | GoAway id -> process_goaway_frame t id
    | Ignored _ | Unknown _ -> ())

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
  (* TODO: check that these are only called once. The client shouldn't open more
     than one of these streams. *)
  let open Angstrom in
  match unitype with
  | Unidirectional_stream.Qencoder ->
    skip_many (Qpack.Encoder.Instruction.parser t.qpack_encoder) >>| fun () ->
    Ok ()
  | Qdecoder ->
    (* let f = Stream.unsafe_faraday stream.stream in *)
    let f = Faraday.create 0x100 in
    Qdecoder.parse_instructions t.qpack_decoder f >>| fun () -> Ok ()
  | Control ->
    (* From RFC<HTTP3-RFC>§6.2.1:
     *   Each side MUST initiate a single control stream at the beginning of
     *   the connection and send its SETTINGS frame as the first frame on this
     *   stream. *)
    Reader.http3_frames (frame_handler t stream)
  | Push _ ->
    (* Client shouldn't send push frames. *)
    assert false
  | Ignored _ ->
    (* From RFC<HTTP3-RFC>§8.1:
     *   Stream types of the format 0x1f * N + 0x21 for non-negative integer
     *   values of N are reserved to exercise the requirement that unknown
     *   types be ignored. These streams have no semantics, and can be sent
     *   when application-layer padding is desired. *)
    Reader.ignored_stream

let bidirectional_frames t stream =
  let reader = Reader.bidirectional_frames (frame_handler t stream) in
  Format.eprintf "bidi: %Ld@." (Stream.id stream.stream);
  reader

(* ?(config = Config.default) *)
let create ~error_handler ~cid:_ ~(start_stream : Quic.Transport.start_stream) =
  let settings = Settings.default in
  let t =
    { settings (* ; config *)
    ; saw_control_settings = false
    ; streams = Hashtbl.create ~random:true 1024
    ; error_handler
    ; qpack_encoder = Qpack.Encoder.create 0
    ; qpack_decoder = Qdecoder.create ~max_size:0 ~max_blocked_streams:100
    ; critical_streams =
        { control = Some (start_control_stream ~start_stream)
        ; qencoder = Some (start_unidirectional_stream ~start_stream Qencoder)
        ; qdecoder = Some (start_unidirectional_stream ~start_stream Qdecoder)
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
        let reader =
          match direction with
          | Quic.Direction.Unidirectional ->
            Reader.unirectional_frames (unistream_frame_handler t stream)
          | Bidirectional -> bidirectional_frames t stream
        in
        Stream.schedule_read
          stream.stream
          ~on_eof:(read_eof t stream ~reader)
          ~on_read:(read t stream ~reader);
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
