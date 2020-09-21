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

open Angstrom

let varint_encoding_length n =
  if n < 1 lsl 6 then
    1
  else if n < 1 lsl 14 then
    2
  else if n < 1 lsl 30 then
    4
  else
    8

(* XXX: technically could be a 62-bit int. *)
let variable_length_integer =
  let rec inner r = function [] -> r | b :: xs -> inner ((r * 256) + b) xs in
  let parse_remaining r n = lift (inner r) (count n any_uint8) in
  any_uint8 >>= fun first_byte ->
  let encoding = first_byte lsr 6 in
  let b1 = first_byte land 0b00111111 in
  match encoding with
  | 0 ->
    return b1
  | 1 ->
    parse_remaining b1 1
  | 2 ->
    parse_remaining b1 3
  | _ ->
    assert (encoding = 3);
    parse_remaining b1 7

let parse_data_frame length =
  lift (fun bs -> Frame.Data bs) (take_bigstring length)

let parse_headers_frame length =
  lift (fun bs -> Frame.Headers bs) (take_bigstring length)

let parse_cancel_push_frame length =
  lift
    (fun i ->
      assert (length = varint_encoding_length i);
      Frame.Cancel_push (Int64.of_int i))
    variable_length_integer

let parse_settings_frame length =
  fix (fun m ->
      lift3
        (fun k v (settings, acc) ->
          let acc' =
            varint_encoding_length k + varint_encoding_length v + acc
          in
          match k with
          | x when Settings.Type.is_unknown x ->
            (* From RFC<HTTP3-RFC>§7.2.4.1:
             *   Setting identifiers of the format 0x1f * N + 0x21 for
             *   non-negative integer values of N are reserved to exercise the
             *   requirement that unknown identifiers be ignored. Such settings
             *   have no defined meaning.  Endpoints SHOULD include at least
             *   one such setting in their SETTINGS frame. Endpoints MUST NOT
             *   consider such settings to have any meaning upon receipt. *)
            settings, acc'
          | 0x6 ->
            (* From RFC<HTTP3-RFC>§7.2.4.1:
             *   SETTINGS_MAX_FIELD_SECTION_SIZE (0x6): The default value is
             *   unlimited. See Section 4.1.1 for usage. *)
            { Settings.max_field_section_size = v }, acc'
          | _ ->
            assert false)
        variable_length_integer
        variable_length_integer
        m
      <|> return (Settings.default, 0))
  >>| fun (settings, total_length) ->
  assert (total_length = length);
  Frame.Settings settings

let parse_push_promise_frame length =
  variable_length_integer >>= fun push_id ->
  let id_len = varint_encoding_length push_id in
  lift
    (fun headers -> Frame.Push_promise { push_id; headers })
    (take_bigstring (length - id_len))

let parse_goaway_frame length =
  lift
    (fun i ->
      assert (length = varint_encoding_length i);
      Frame.GoAway i)
    variable_length_integer

let parse_max_push_id_frame length =
  lift
    (fun i ->
      assert (length = varint_encoding_length i);
      Frame.Max_push_id i)
    variable_length_integer

let parse_frame =
  variable_length_integer >>= fun frame_type ->
  variable_length_integer >>= fun length ->
  match Frame.Type.parse frame_type with
  | Data ->
    parse_data_frame length
  | Headers ->
    parse_headers_frame length
  | Cancel_push ->
    parse_cancel_push_frame length
  | Settings ->
    parse_settings_frame length
  | Push_promise ->
    parse_push_promise_frame length
  | GoAway ->
    parse_goaway_frame length
  | Max_push_id ->
    parse_max_push_id_frame length
  | Ignored x ->
    advance length *> return (Frame.Ignored x)
  | Unknown x ->
    advance length *> return (Frame.Unknown x)

let unidirectional_stream_header =
  (* From RFC<HTTP3-RFC>§6.2:
   *   Unidirectional streams, in either direction, are used for a range of
   *   purposes. The purpose is indicated by a stream type, which is sent as a
   *   variable-length integer at the start of the stream. *)
  variable_length_integer >>= function
  | 0x00 ->
    (* From RFC<HTTP3-RFC>§6.2.1:
     *   A control stream is indicated by a stream type of 0x00. Data on this
     *   stream consists of HTTP/3 frames, as defined in Section 7.2. *)
    return Unidirectional_stream.Control
  | 0x01 ->
    (* From RFC<HTTP3-RFC>§6.2.2:
     *   A push stream is indicated by a stream type of 0x01, followed by the
     *   Push ID of the promise that it fulfills, encoded as a variable-length
     *   integer. *)
    lift (fun id -> Unidirectional_stream.Push id) variable_length_integer
  | 0x02 ->
    (* From RFC<QPACK-RFC>§4.2:
     *   An encoder stream is a unidirectional stream of type 0x02. It carries
     *   an unframed sequence of encoder instructions from encoder to decoder. *)
    return Unidirectional_stream.Qencoder
  | 0x03 ->
    (* From RFC<QPACK-RFC>§4.2:
     *   A decoder stream is a unidirectional stream of type 0x03. It carries
     *   an unframed sequence of decoder instructions from decoder to encoder. *)
    return Unidirectional_stream.Qdecoder
  | x when Settings.Type.is_unknown x ->
    (* From RFC<HTTP3-RFC>§8.1:
     *   Stream types of the format 0x1f * N + 0x21 for non-negative integer
     *   values of N are reserved to exercise the requirement that unknown
     *   types be ignored. These streams have no semantics, and can be sent
     *   when application-layer padding is desired. *)
    return (Unidirectional_stream.Ignored (Settings.Type.unknown_n x))
  | _ ->
    failwith "unknown"

module Reader = struct
  module AU = Angstrom.Unbuffered

  type parse_context =
    { mutable remaining_bytes_to_skip : int
    ; mutable did_report_stream_error : bool
    }

  type parse_error =
    (* Parse error reported by Angstrom *)
    [ `Parse of string list * string
    | (* Full error information *)
      `Error of Error.t
    | `Error_code of Error.Code.t
    ]

  type 'error parse_state =
    | Initial
    | Fail of 'error
    | Partial of
        (Bigstringaf.t
         -> off:int
         -> len:int
         -> AU.more
         -> (unit, 'error) result AU.state)

  type 'error t =
    { parser : (unit, 'error) result Angstrom.t
    ; mutable parse_state : 'error parse_state
          (* The state of the parse for the current request *)
    ; mutable closed : bool
          (* Whether the input source has left the building, indicating that no
           * further input will be received. *)
    ; parse_context : parse_context
          (* The current stream identifier being processed, in order to discern
           * whether the error that needs to be assembled is a stream or
           * connection error. *)
    }

  type frame = parse_error t

  let create parser parse_context =
    { parser; parse_state = Initial; closed = false; parse_context }

  let create_parse_context () =
    { remaining_bytes_to_skip = 0; did_report_stream_error = false }

  (* From RFC<HTTP3-RFC>§8.1:
   *   After the QUIC connection is established, a SETTINGS frame (Section
   *   7.2.4) MUST be sent by each endpoint as the initial frame of their
   *   respective HTTP control stream; see Section 6.2.1. *)

  let settings_preface _parse_context =
    (* From RFC7540§3.5:
     *   [...] the connection preface starts with the string
     *   PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n). This sequence MUST be followed by
     *   a SETTINGS frame (Section 6.5), which MAY be empty. *)
    parse_frame >>= fun x ->
    return (Ok x) >>| function
    | Ok (Frame.Settings settings as frame) ->
      Ok (frame, settings)
    | Ok _ ->
      (* From RFC7540§3.5:
       *   Clients and servers MUST treat an invalid connection preface as a
       *   connection error (Section 5.4.1) of type PROTOCOL_ERROR. A GOAWAY
       *   frame (Section 6.8) MAY be omitted in this case, since an invalid
       *   preface indicates that the peer is not using HTTP/2. *)
      Error
        (`Error
          Error.(
            ConnectionError
              (Error.Code.Frame_unexpected, "Invalid connection preface")))
    | Error e ->
      Error (`Error e)

  let http3_frames handler =
    skip_many (parse_frame <* commit >>| fun frame -> handler (Ok frame))
    >>| fun () -> Ok ()

  let unirectional_frames select_stream_parser =
    let parse_context = create_parse_context () in
    let parser =
      unidirectional_stream_header <* commit >>= select_stream_parser
    in
    create parser parse_context

  let bidirectional_frames frame_handler =
    let parse_context = create_parse_context () in
    let parser = http3_frames frame_handler in
    create parser parse_context

  let is_closed t = t.closed

  let transition t state =
    match state with
    | AU.Done (consumed, Ok ()) ->
      t.parse_state <- Initial;
      consumed
    | Done (consumed, Error error) ->
      t.parse_state <- Fail error;
      consumed
    | Fail (consumed, marks, msg) ->
      t.parse_state <- Fail (`Parse (marks, msg));
      consumed
    | Partial { committed; continue } ->
      (* If we have bytes to skip over then it means we've spotted a
       * FRAME_SIZE_ERROR, a case where, due to our unbuffered parsing, the
       * payload length declared in a frame header is larger than the
       * underlying buffer can fit. *)
      if t.parse_context.remaining_bytes_to_skip > 0 then
        t.parse_state <- Fail (`Error_code Error.Code.Frame_error)
      else
        t.parse_state <- Partial continue;
      committed

  let start t state =
    match state with
    | AU.Done _ ->
      failwith "h2.Parse.Reader.unable to start parser"
    | Fail (0, marks, msg) ->
      t.parse_state <- Fail (`Parse (marks, msg))
    | Partial { committed = 0; continue } ->
      t.parse_state <- Partial continue
    | Partial _ | Fail _ ->
      assert false

  let rec read_with_more t bs ~off ~len more =
    let consumed =
      match t.parse_state with
      | Fail _ ->
        let parser_ctx = t.parse_context in
        let remaining_bytes = parser_ctx.remaining_bytes_to_skip in
        (* Just skip input if we need to *)
        if remaining_bytes > 0 then (
          assert (remaining_bytes >= len);
          let remaining_bytes' = remaining_bytes - len in
          parser_ctx.remaining_bytes_to_skip <- remaining_bytes';
          assert (remaining_bytes' >= 0);
          if remaining_bytes' = 0 then
            (* Reset the parser state to `Done` so that we can read the next
             * frame (after skipping through the bad input) *)
            t.parse_state <- Initial;
          len)
        else
          0
      | Initial ->
        start t (AU.parse t.parser);
        read_with_more t bs ~off ~len more
      | Partial continue ->
        transition t (continue bs more ~off ~len)
    in
    (match more with Complete -> t.closed <- true | Incomplete -> ());
    consumed

  let force_close t = t.closed <- true

  let fail_to_string marks err = String.concat " > " marks ^ ": " ^ err

  (* let next_from_error t ?(msg = "") error_code = *)
  (* match t.parse_context, error_code with *)
  (* | ( { frame_header = *)
  (* { frame_type = *)
  (* Headers | PushPromise | Continuation | Settings | Unknown _ *)
  (* ; _ *)
  (* } *)
  (* ; _ *)
  (* } *)
  (* , Error_code.FrameSizeError ) *)
  (* | { frame_header = { Frame.stream_id = 0x0l; _ }; _ }, _ -> *)
  (* From RFC7540§4.2:
   *   A frame size error in a frame that could alter the state of the
   *   entire connection MUST be treated as a connection error (Section
   *   5.4.1); this includes any frame carrying a header block (Section
   *   4.3) (that is, HEADERS, PUSH_PROMISE, and CONTINUATION), SETTINGS,
   *   and any frame with a stream identifier of 0. *)
  (* `Error Error.(ConnectionError (error_code, msg)) *)
  (* | { did_report_stream_error = true; _ }, _ -> *)
  (* If the parser is in a `Fail` state and would report a stream error,
   * just issue a `Read` operation if we've already reported that error. *)
  (* if t.closed then *)
  (* `Close *)
  (* else *)
  (* `Read *)
  (* | { frame_header = { Frame.stream_id; _ }; _ }, _ -> *)
  (* t.parse_context.did_report_stream_error <- true; *)
  (* `Error Error.(StreamError (stream_id, error_code)) *)

  let next t =
    match t.parse_state with
    | Fail error ->
      (match error with
      | `Error e ->
        `Error e
      | `Error_code _error_code ->
        failwith "fix me"
      | `Parse (marks, msg) ->
        let _error_code =
          match marks, msg with
          | [ "frame_payload" ], "not enough input" ->
            (* From RFC7540§4.2:
             *   An endpoint MUST send an error code of FRAME_SIZE_ERROR if a
             *   frame exceeds the size defined in SETTINGS_MAX_FRAME_SIZE,
             *   exceeds any limit defined for the frame type, or is too small
             *   to contain mandatory frame data. *)
            Error.Code.Frame_error
          | _ ->
            Error.Code.General_protocol_error
        in
        failwith "fix me")
    | _ when t.closed ->
      `Close
    | Partial _ ->
      `Read
    | Initial ->
      if t.closed then
        `Close
      else
        `Read
end
