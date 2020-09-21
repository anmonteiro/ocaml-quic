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
  module AB = Angstrom.Buffered

  type parse_error =
    [ (* Full error information *)
      `Error of Error.t
    | `Error_code of Error.Code.t
    ]

  type 'error t =
    { parser : (unit, 'error) result Angstrom.t
    ; mutable parse_state : (unit, 'error) result AB.state
          (* The state of the parse for the current request *)
    ; mutable closed : bool
          (* Whether the input source has left the building, indicating that no
           * further input will be received. *)
    }

  type frame = parse_error t

  let create parser = { parser; parse_state = AB.parse parser; closed = false }

  let ignored_stream = skip_many (any_char <* commit) >>| fun () -> Ok ()

  let http3_frames handler =
    skip_many (parse_frame <* commit >>| fun frame -> handler (Ok frame))
    >>| fun () -> Ok ()

  let unirectional_frames select_stream_parser =
    let parser =
      unidirectional_stream_header <* commit >>= select_stream_parser
    in
    create parser

  let bidirectional_frames frame_handler =
    let parser = http3_frames frame_handler in
    create parser

  let is_closed t = t.closed

  let transition t bs =
    match t.parse_state with
    | AB.Done (_unconsumed, Ok ()) ->
      assert false
    | Done (_unconsumed, Error _error) ->
      (* t.parse_state <- Fail error; *)
      assert false
    | Fail (_unconsumed, _marks, _msg) ->
      t.parse_state
    | Partial continue ->
      continue (`Bigstring bs)

  let read_with_more t bs more =
    t.parse_state <- transition t bs;
    match more with
    | Angstrom.Unbuffered.Complete ->
      t.closed <- true;
      t.parse_state <- AB.feed t.parse_state `Eof
    | Incomplete ->
      ()

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
    | Done (_, Error error) ->
      (match error with
      | `Error e ->
        `Error e
      | `Error_code _error_code ->
        failwith "fix me")
    | Fail (_, marks, msg) ->
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
      failwith "fix me"
    | _ when t.closed ->
      `Close
    | Partial _ ->
      `Read
    | Done _ ->
      if t.closed then
        `Close
      else
        `Read
end
