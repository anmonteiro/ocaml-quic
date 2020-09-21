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

(* module Writer = Serialize.Writer *)
type request_handler = Reqd.t -> unit

type error =
  [ `Bad_request
  | `Internal_server_error
  | `Exn of exn
  ]

type error_handler =
  ?request:Request.t -> error -> (Headers.t -> [ `write ] Body.t) -> unit

type stream =
  { reader : Reader.frame
  ; stream : Stream.t
  ; id : Quic.Stream_id.t
  ; direction : Quic.Direction.t
  ; mutable reqd : Reqd.t option
  }

type critical_streams =
  { mutable control : Stream.t option
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
    | `Exn exn ->
      Printexc.to_string exn
    | (#Status.client_error | #Status.server_error) as error ->
      Status.to_string error
  in
  let body = handle Headers.empty in
  Body.write_string body message;
  Body.close_writer body

let handle_headers t ~stream_id stream headers =
  match Headers.method_path_and_scheme_or_malformed headers with
  | `Malformed ->
    Format.eprintf "wat: %a@." Headers.pp_hum headers;
    failwith "`Bad_request ProtocolError"
  | `Valid (meth, path, scheme) ->
    match Message.body_length headers with
    | `Error _e ->
      failwith "ProtocolError"
    | _body_length ->
      let request =
        Request.create ~scheme ~headers (Httpaf.Method.of_string meth) path
      in
      let request_body = Body.create stream in
      let reqd =
        Reqd.create
          t.error_handler
          ~stream_id
          ~encoder:t.qpack_encoder
          ~encoder_stream:(Option.get t.critical_streams.qencoder)
          request
          request_body
          stream
      in
      t.request_handler reqd

let process_headers_frame t ~stream_id stream headers_block =
  let f bs =
    match
      Angstrom.parse_bigstring
        ~consume:All
        (Qdecoder.parser t.qpack_decoder ~stream_id)
        bs
    with
    | Ok (Ok (headers, _instructions)) ->
      handle_headers t ~stream_id stream (Headers.of_qpack_list headers)
    | Ok (Error _) | Error _ ->
      assert false
  in
  match
    Qdecoder.decode_header_block t.qpack_decoder ~stream_id headers_block f
  with
  | _ ->
    ()

let process_data_frame _t _bs = failwith "NYI: process_data"

let process_settings_frame _t _settings_list = failwith "NYI: settings"

let process_goaway_frame _t _id = failwith "NYI: goaway"

let read _t stream bs ~off ~len =
  Format.eprintf "LEN: %d@." len;
  let read = Reader.read_with_more stream.reader bs ~off ~len Incomplete in
  assert (read > 0)

let read_eof _t stream () =
  let read =
    Reader.read_with_more stream.reader Bigstringaf.empty ~off:0 ~len:0 Complete
  in
  assert (read = 0)

let frame_handler t stream ~id r =
  match r with
  | Error _e ->
    (* report_error t e *)
    ()
  | Ok frame ->
    match frame with
    | Frame.Headers header_block ->
      process_headers_frame t ~stream_id:id stream header_block
    | Data bs ->
      process_data_frame t bs
    | Settings settings ->
      process_settings_frame t settings
    | Push_promise _ ->
      assert false
    | Cancel_push _ ->
      ()
    | Max_push_id _ ->
      ()
    | GoAway id ->
      process_goaway_frame t id
    | Ignored _ | Unknown _ ->
      ()

let unistream_frame_handler t ~id stream unitype =
  let open Angstrom in
  Format.eprintf "GOT: %d@." (Unidirectional_stream.serialize unitype);
  match unitype with
  | Unidirectional_stream.Qencoder ->
    skip_many (Qpack.Encoder.Instruction.parser t.qpack_encoder) >>| fun () ->
    Ok ()
  | Qdecoder ->
    let tmpf = Faraday.create 0x10 in
    Qdecoder.parse_instructions t.qpack_decoder tmpf >>| fun () -> Ok ()
  | Control ->
    (* TODO: write settings frame, start a new unidirectional stream and
     * encoder streams. *)
    Reader.http3_frames (frame_handler t stream ~id)
  | Push _ ->
    Reader.http3_frames (frame_handler t stream ~id)
  | Ignored _ ->
    (* From RFC<HTTP3-RFC>§8.1:
     *   Stream types of the format 0x1f * N + 0x21 for non-negative integer
     *   values of N are reserved to exercise the requirement that unknown
     *   types be ignored. These streams have no semantics, and can be sent
     *   when application-layer padding is desired. *)
    Reader.http3_frames ignore

(* ?(config = Config.default) *)
let create ?(error_handler = default_error_handler) request_handler =
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
  fun stream ~direction ~id ->
    let stream =
      match Hashtbl.find_opt t.streams id with
      | Some _stream ->
        assert false
      | None ->
        let reader =
          match direction with
          | Quic.Direction.Unidirectional ->
            Format.eprintf "uni: %Ld@." id;
            Reader.unirectional_frames (unistream_frame_handler t ~id stream)
          | Bidirectional ->
            Format.eprintf "bidi: %Ld@." id;
            Reader.bidirectional_frames (frame_handler t ~id stream)
        in
        { stream; reader; direction; id; reqd = None }
    in
    Stream.schedule_read
      stream.stream
      ~on_eof:(read_eof t stream)
      ~on_read:(read t stream);
    Hashtbl.add t.streams id stream
