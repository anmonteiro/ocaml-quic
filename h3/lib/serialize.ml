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

let varint_encoding_length n =
  if n < 1 lsl 6 then
    1
  else if n < 1 lsl 14 then
    2
  else if n < 1 lsl 30 then
    4
  else
    8

let rec decomp n acc x =
  if n = 0 then
    acc
  else
    decomp (n - 1) ((x land 0xff) :: acc) (x lsr 8)

let write_variable_length_integer t n =
  let encoding_bytes, encoding =
    if n < 1 lsl 6 then
      1, 0
    else if n < 1 lsl 14 then
      2, 1
    else if n < 1 lsl 30 then
      4, 2
    else
      8, 3
  in
  let ns = decomp encoding_bytes [] n in
  let hd = List.hd ns in
  let tl = List.tl ns in
  (* From RFC<QUIC-RFC>§16:
   *   The QUIC variable-length integer encoding reserves the two most
   *   significant bits of the first byte to encode the base 2 logarithm of the
   *   integer encoding length in bytes. The integer value is encoded on the
   *   remaining bits, in network byte order. *)
  Quic.Stream.write_uint8 t ((encoding lsl 6) lor hd);
  List.iter (fun n -> Quic.Stream.write_uint8 t n) tl

let write_data_frame t data =
  write_variable_length_integer t (String.length data);
  Quic.Stream.write_string t data

let schedule_data_frame t ?off ?len data =
  let len =
    match len with None -> Bigstringaf.length data | Some len -> len
  in
  write_variable_length_integer t len;
  Quic.Stream.schedule_bigstring t ?off ~len data

let schedule_headers_frame t header_block =
  write_variable_length_integer t (Bigstringaf.length header_block);
  Quic.Stream.schedule_bigstring t header_block

let write_cancel_push_frame t id =
  write_variable_length_integer t (varint_encoding_length id);
  write_variable_length_integer t id

let write_settings_frame t { Settings.max_field_section_size } =
  let settings =
    [ Settings.Type.max_field_section_size, max_field_section_size
    ; (* From RFC<HTTP3-RFC>§7.2.4.1:
       *   Setting identifiers of the format 0x1f * N + 0x21 for non-negative
       *   integer values of N are reserved to exercise the requirement that
       *   unknown identifiers be ignored. Such settings have no defined
       *   meaning.  Endpoints SHOULD include at least one such setting in
       *   their SETTINGS frame.  Endpoints MUST NOT consider such settings to
       *   have any meaning upon receipt. *)
      Settings.Type.unknown 1, 0
    ]
  in
  let length =
    List.fold_left
      (fun acc (k, v) ->
        acc + varint_encoding_length k + varint_encoding_length v)
      0
      settings
  in
  write_variable_length_integer t length;
  List.iter
    (fun (k, v) ->
      write_variable_length_integer t k;
      write_variable_length_integer t v)
    settings

let write_push_promise_frame t ~push_id header_block =
  let length =
    varint_encoding_length push_id + Bigstringaf.length header_block
  in
  write_variable_length_integer t length;
  write_variable_length_integer t push_id;
  Quic.Stream.schedule_bigstring t header_block

let write_goaway_frame t id =
  write_variable_length_integer t (varint_encoding_length id);
  write_variable_length_integer t id

let write_max_push_id_frame t id =
  write_variable_length_integer t (varint_encoding_length id);
  write_variable_length_integer t id

module Writer = struct
  let encode_headers t qencoder ~encoder_stream ~stream_id headers =
    let f = Quic.Stream.unsafe_faraday t in
    let encoder_buffer = Quic.Stream.unsafe_faraday encoder_stream in
    Qpack.Encoder.encode_headers qencoder ~stream_id ~encoder_buffer f headers

  let write_request_like_frame t ~stream_id ~encoder_stream qencoder request =
    let { Request.meth; target; scheme; headers } = request in
    let headers =
      { Headers.name = ":method"
      ; value = Httpaf.Method.to_string meth
      ; sensitive = false
      }
      :: Headers.to_qpack_list headers
    in
    let headers =
      match meth with
      | `CONNECT ->
        (* From RFC<HTTP3-RFC>§4.2:
         *   The ":scheme" and ":path" pseudo-header fields are omitted *)
        { Headers.name = ":path"; value = target; sensitive = false }
        :: { Headers.name = ":scheme"; value = scheme; sensitive = false }
        :: headers
      | _ ->
        headers
    in
    encode_headers t qencoder ~encoder_stream ~stream_id headers

  let write_response_headers t qencoder ~encoder_stream ~stream_id response =
    let { Response.status; headers; _ } = response in
    let headers =
      { Headers.name = ":status"
      ; value = Status.to_string status
      ; sensitive = false
      }
      :: headers
    in
    encode_headers t qencoder ~encoder_stream ~stream_id headers

  let write_data t s = write_data_frame t s

  let schedule_data t ?off ?len s = schedule_data_frame ?off ?len t s
end
