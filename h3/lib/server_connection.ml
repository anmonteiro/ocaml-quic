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
  ; request_handler : request_handler
  ; error_handler : error_handler
  ; qpack_encoder : Qpack.Encoder.t
  ; qpack_decoder : Qdecoder.t
  }

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

let handle_headers t { stream; writer; _ } headers =
  let stream_id = Stream.id stream in
  match Headers.method_path_and_scheme_or_malformed headers with
  | `Malformed -> failwith "`Bad_request ProtocolError"
  | `Valid (meth, path, scheme) ->
    (match Message.body_length headers with
    | `Error _e -> failwith "ProtocolError"
    | _body_length ->
      let request =
        Request.create ~scheme ~headers (Httpaf.Method.of_string meth) path
      in
      let request_body = Body.Reader.create stream in
      let reqd =
        Reqd.create
          t.error_handler
          ~stream_id
          ~encoder:t.qpack_encoder
          ~encoder_stream:(Option.get t.critical_streams.qencoder)
          request
          request_body
          stream
          writer
      in
      t.request_handler reqd)

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

let process_data_frame _t _bs = failwith "NYI: process_data"
let process_settings_frame _t _settings_list = failwith "NYI: settings"
let process_goaway_frame _t _id = failwith "NYI: goaway"

(* TODO: need to schedule read again. *)
let read _t _stream ~reader bs ~off ~len:_ =
  assert (off = 0);
  Reader.read_with_more reader bs Incomplete

let read_eof _t _stream ~reader () =
  Reader.read_with_more reader Bigstringaf.empty Complete

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
    | Data bs -> process_data_frame t bs
    | Settings settings -> process_settings_frame t settings
    | Push_promise _ -> assert false
    | Cancel_push _ -> ()
    | Max_push_id _ -> ()
    | GoAway id -> process_goaway_frame t id
    | Ignored _ | Unknown _ -> ())

let start_unidirectional_stream ~start_stream unitype =
  let stream = start_stream ~direction:Quic.Direction.Unidirectional in
  Writer.write_unidirectional_stream_type stream unitype;
  stream

let unistream_frame_handler t ~start_stream (stream : stream) unitype =
  (* TODO: check that these are only called once. The client shouldn't open more
     than one of these streams. *)
  let open Angstrom in
  match unitype with
  | Unidirectional_stream.Qencoder ->
    t.critical_streams.qencoder <-
      Some (start_unidirectional_stream ~start_stream unitype);
    skip_many (Qpack.Encoder.Instruction.parser t.qpack_encoder) >>| fun () ->
    Ok ()
  | Qdecoder ->
    let stream = start_unidirectional_stream ~start_stream unitype in
    t.critical_streams.qdecoder <- Some stream;
    let f = Stream.unsafe_faraday stream in
    Qdecoder.parse_instructions t.qpack_decoder f >>| fun () -> Ok ()
  | Control ->
    let quic_stream = start_unidirectional_stream ~start_stream unitype in
    let control_stream =
      { stream = quic_stream
      ; reqd = None
      ; direction = Unidirectional
      ; writer = Writer.create quic_stream
      }
    in
    t.critical_streams.control <- Some control_stream;
    (* From RFC<HTTP3-RFC>§6.2.1:
     *   Each side MUST initiate a single control stream at the beginning of
     *   the connection and send its SETTINGS frame as the first frame on this
     *   stream. *)
    Writer.write_settings control_stream.writer Settings.default;
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
    ; critical_streams = { control = None; qencoder = None; qdecoder = None }
    }
  in
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
          Reader.unirectional_frames
            (unistream_frame_handler t ~start_stream stream)
        | Bidirectional ->
          Format.eprintf "bidi: %Ld@." id;
          Reader.bidirectional_frames (frame_handler t stream)
      in
      Stream.schedule_read
        stream.stream
        ~on_eof:(read_eof t stream ~reader)
        ~on_read:(read t stream ~reader);
      Hashtbl.add t.streams id stream)
