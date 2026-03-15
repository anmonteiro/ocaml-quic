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

let packet_number_length pn =
  (* From RFC9000§17.1:
   *   Packet numbers are integers in the range 0 to 2^62-1 (Section 12.3).
   *   When present in long or short packet headers, they are encoded in 1 to 4
   *   bytes. *)
  if Int64.compare pn (Int64.shift_left 1L 8) < 0
  then 1
  else if Int64.compare pn (Int64.shift_left 1L 16) < 0
  then 2
  else if Int64.compare pn (Int64.shift_left 1L 32) < 0
  then 3
  else 4

let varint_encoding_length n =
  if n < 1 lsl 6
  then 1
  else if n < 1 lsl 14
  then 2
  else if n < 1 lsl 30
  then 4
  else 8

let write_variable_length_integer t n =
  let encoding_bytes, encoding =
    if n < 1 lsl 6
    then 1, 0
    else if n < 1 lsl 14
    then 2, 1
    else if n < 1 lsl 30
    then 4, 2
    else 8, 3
  in
  let write_byte shift = Faraday.write_uint8 t ((n lsr shift) land 0xff) in
  (* From RFC9000§16:
   *   The QUIC variable-length integer encoding reserves the two most
   *   significant bits of the first byte to encode the base 2 logarithm of the
   *   integer encoding length in bytes. The integer value is encoded on the
   *   remaining bits, in network byte order. *)
  match encoding_bytes with
  | 1 -> Faraday.write_uint8 t ((encoding lsl 6) lor n)
  | 2 ->
    Faraday.write_uint8 t ((encoding lsl 6) lor ((n lsr 8) land 0x3f));
    write_byte 0
  | 4 ->
    Faraday.write_uint8 t ((encoding lsl 6) lor ((n lsr 24) land 0x3f));
    write_byte 16;
    write_byte 8;
    write_byte 0
  | 8 ->
    Faraday.write_uint8 t ((encoding lsl 6) lor ((n lsr 56) land 0x3f));
    write_byte 48;
    write_byte 40;
    write_byte 32;
    write_byte 24;
    write_byte 16;
    write_byte 8;
    write_byte 0
  | _ -> assert false

module Frame_desc = Frame

module Frame = struct
  let padding = Bigstringaf.of_string ~off:0 ~len:1 "\x00"

  let write_padding t n =
    for _i = 0 to n - 1 do
      Faraday.schedule_bigstring t padding
    done

  let write_ack t ~delay ~ranges ~ecn_counts =
    let range_len = List.length ranges in
    let range_count = range_len - 1 in
    assert (range_len > 0);
    let first, rest = List.hd ranges, List.tl ranges in
    let first_range = Int64.sub first.Frame.Range.last first.first in
    let largest = first.Frame.Range.last in
    write_variable_length_integer t (Int64.to_int largest);
    write_variable_length_integer t delay;
    write_variable_length_integer t range_count;
    write_variable_length_integer t (Int64.to_int first_range);
    let (_ : int64) =
      List.fold_left
        (fun smallest_ack { Frame.Range.first; last } ->
           (* RFC9000§19.3.1: gap = previous_smallest - current_largest - 2 *)
           let gap = Int64.sub (Int64.sub smallest_ack last) 2L in
           let len = Int64.sub last first in
           write_variable_length_integer t (Int64.to_int gap);
           write_variable_length_integer t (Int64.to_int len);
           first)
        first.first
        rest
    in
    match ecn_counts with
    | Some (ect0, ect1, cn) ->
      write_variable_length_integer t ect0;
      write_variable_length_integer t ect1;
      write_variable_length_integer t cn
    | None -> ()

  let write_reset_stream t ~stream_id ~application_protocol_error ~final_size =
    write_variable_length_integer t (Int64.to_int stream_id);
    write_variable_length_integer t application_protocol_error;
    write_variable_length_integer t final_size

  let write_stop_sending t ~stream_id ~application_protocol_error =
    write_variable_length_integer t (Int64.to_int stream_id);
    write_variable_length_integer t application_protocol_error

  let write_crypto t ~fragment =
    let { Frame.off; len; payload; payload_off } = fragment in
    write_variable_length_integer t off;
    write_variable_length_integer t len;
    Faraday.write_string t ~off:payload_off ~len payload

  let write_new_token t ~length ~data =
    write_variable_length_integer t length;
    Faraday.schedule_bigstring t data

  let write_stream t ~stream_id ~fragment =
    let { Frame.off; len; payload; payload_off } = fragment in
    write_variable_length_integer t (Int64.to_int stream_id);
    if off > 0 then write_variable_length_integer t off;
    if len > 0 then write_variable_length_integer t len;
    Faraday.write_string t ~off:payload_off ~len payload

  let write_max_data t ~max = write_variable_length_integer t max

  let write_max_stream_data t ~stream_id ~max =
    write_variable_length_integer t (Int64.to_int stream_id);
    write_variable_length_integer t max

  let write_max_streams t ~max = write_variable_length_integer t max
  let write_data_blocked t ~max = write_variable_length_integer t max

  let write_stream_data_blocked t ~id ~max =
    write_variable_length_integer t (Int64.to_int id);
    write_variable_length_integer t max

  let write_streams_blocked t ~max = write_variable_length_integer t max

  let write_new_connection_id
        t
        ~cid
        ~stateless_reset_token
        ~retire_prior_to
        ~sequence_no
    =
    write_variable_length_integer t sequence_no;
    write_variable_length_integer t retire_prior_to;
    CID.serialize t cid;
    Faraday.write_string t stateless_reset_token

  let write_retire_connection_id t ~sequence_no =
    write_variable_length_integer t sequence_no

  let write_path_challenge t ~data = Faraday.schedule_bigstring t data
  let write_path_response t ~data = Faraday.schedule_bigstring t data

  let write_connection_close_quic t ~frame_type ~reason_phrase ~error_code =
    write_variable_length_integer t error_code;
    write_variable_length_integer t (Frame.Type.serialize frame_type);
    write_variable_length_integer t (String.length reason_phrase);
    Faraday.write_string t reason_phrase

  let write_connection_close_app t ~reason_phrase ~error_code =
    write_variable_length_integer t error_code;
    write_variable_length_integer t (String.length reason_phrase);
    Faraday.write_string t reason_phrase

  let write_frame t frame =
    (* From RFC9000§12.4:
     *   The Frame Type field uses a variable length integer encoding (see
     *   Section 16) with one exception. To ensure simple and efficient
     *   implementations of frame parsing, a frame type MUST use the shortest
     *   possible encoding. *)
    let frame_type = Frame.(Type.serialize (to_frame_type frame)) in
    write_variable_length_integer t frame_type;
    match frame with
    | Padding n -> write_padding t n
    | Ping -> ()
    | Ack { delay; ranges; ecn_counts } ->
      write_ack t ~delay ~ranges ~ecn_counts
    | Reset_stream { stream_id; application_protocol_error; final_size } ->
      write_reset_stream t ~stream_id ~application_protocol_error ~final_size
    | Stop_sending { stream_id; application_protocol_error } ->
      write_stop_sending t ~stream_id ~application_protocol_error
    | Crypto fragment -> write_crypto t ~fragment
    | New_token { length; data } -> write_new_token t ~length ~data
    | Stream { id; fragment; _ } -> write_stream t ~stream_id:id ~fragment
    | Max_data max -> write_max_data t ~max
    | Max_stream_data { stream_id; max_data } ->
      write_max_stream_data t ~stream_id ~max:max_data
    | Max_streams (_, max) -> write_max_streams t ~max
    | Data_blocked n -> write_data_blocked t ~max:n
    | Stream_data_blocked { id; max_data } ->
      write_stream_data_blocked t ~id ~max:max_data
    | Streams_blocked (_, n) -> write_streams_blocked t ~max:n
    | New_connection_id
        { cid; stateless_reset_token; retire_prior_to; sequence_no } ->
      write_new_connection_id
        t
        ~cid
        ~stateless_reset_token
        ~retire_prior_to
        ~sequence_no
    | Retire_connection_id sequence_no ->
      write_retire_connection_id t ~sequence_no
    | Path_challenge data -> write_path_challenge t ~data
    | Path_response data -> write_path_response t ~data
    | Connection_close_quic { frame_type; reason_phrase; error_code } ->
      let error_code = Error.serialize error_code in
      write_connection_close_quic t ~frame_type ~reason_phrase ~error_code
    | Connection_close_app { reason_phrase; error_code } ->
      write_connection_close_app t ~reason_phrase ~error_code
    | Handshake_done -> ()
    | Unknown _ -> assert false
end

module Pkt = struct
  module Header = struct
    let write_connection_ids t ~source_cid ~dest_cid =
      CID.serialize t dest_cid;
      CID.serialize t source_cid

    let write_packet_number t ~pn_length ~packet_number =
      let packet_number =
        Int64.to_int (Int64.logand packet_number 0xFFFFFFFFL)
      in
      match pn_length with
      | 1 -> Faraday.write_uint8 t packet_number
      | 2 ->
        Faraday.write_uint8 t ((packet_number lsr 8) land 0xff);
        Faraday.write_uint8 t (packet_number land 0xff)
      | 3 ->
        Faraday.write_uint8 t ((packet_number lsr 16) land 0xff);
        Faraday.write_uint8 t ((packet_number lsr 8) land 0xff);
        Faraday.write_uint8 t (packet_number land 0xff)
      | 4 ->
        Faraday.write_uint8 t ((packet_number lsr 24) land 0xff);
        Faraday.write_uint8 t ((packet_number lsr 16) land 0xff);
        Faraday.write_uint8 t ((packet_number lsr 8) land 0xff);
        Faraday.write_uint8 t (packet_number land 0xff)
      | _ -> assert false

    let write_payload_length t ~pn_length ~header len =
      match header with
      | Packet.Header.Initial _
      | Long { packet_type = Initial | Zero_RTT | Handshake; _ } ->
        (* From RFC9000§17.2:
         * Length: The length of the remainder of the packet (that is, the
         *         Packet Number and Payload fields) in bytes, encoded as a
         *         variable-length integer (Section 16). *)
        write_variable_length_integer t (pn_length + len)
      | Short _ | Long { packet_type = Retry; _ } -> ()

    let write_long_header t ~pn_length ~header =
      let packet_type = Packet.Header.long_packet_type header in
      assert (1 <= pn_length && pn_length <= 4);
      (* From RFC9000§17.2:
       *   Header Form: The most significant bit (0x80) of byte 0 (the first
       *                byte) is set to 1 for long headers.
       *
       *   Fixed Bit: The next bit (0x40) of byte 0 is set to 1. Packets
       *              containing a zero value for this bit are not valid
       *              packets in this version and MUST be discarded. *)
      let form_and_fixed_bits = 0b11000000 in
      (* From RFC9000§17.2.1:
       *   Long Packet Type: The next two bits (those with a mask of 0x30) of
       *                     byte 0 contain a packet type. Packet types are
       *                     listed in Table 5. *)
      let first_byte = Packet.Type.serialize packet_type lsl 4 in
      let first_byte = form_and_fixed_bits lor first_byte in
      (* From RFC9000§17.2:
       *   Reserved Bits: Two bits (those with a mask of 0x0c) of byte 0 are
       *                  reserved across multiple packet types. [...] The
       *                  value included prior to protection MUST be set to
       *                  0. *)
      assert (first_byte land 0b00001100 = 0);
      let first_byte =
        match packet_type with
        | Initial | Zero_RTT | Handshake ->
          (* From RFC9000§17.2:
           *   In packet types which contain a Packet Number field, the least
           *   significant two bits (those with a mask of 0x03) of byte 0
           *   contain the length of the packet number, encoded as an unsigned,
           *   two-bit integer that is one less than the length of the packet
           *   number field in bytes. *)
          first_byte lor ((pn_length - 1) land 0b11)
        | Retry ->
          (* last 4 bits are unused. *)
          first_byte
      in
      Faraday.write_uint8 t first_byte;
      match header with
      | Packet.Header.Initial { version; source_cid; dest_cid; token; _ } ->
        Faraday.BE.write_uint32 t version;
        write_connection_ids t ~source_cid ~dest_cid;
        write_variable_length_integer t (String.length token);
        Faraday.write_string t token
      | Long { version; source_cid; dest_cid; _ } ->
        Faraday.BE.write_uint32 t version;
        write_connection_ids t ~source_cid ~dest_cid
      | Short _ -> assert false

    let write_short_header t ~pn_length ~dest_cid =
      (* From RFC9000§17.3:
       *   Header Form: The most significant bit (0x80) of byte 0 is set to 0
       *   for the short header.
       *   Fixed Bit: The next bit (0x40) of byte 0 is set to 1. Packets
       *              containing a zero value for this bit are not valid
       *              packets in this version and MUST be discarded. *)
      let form_and_fixed_bits = 0b01000000 in
      (* TODO: spin bit, key phase *)
      let first_byte = form_and_fixed_bits lor ((pn_length - 1) land 0b11) in
      (* From RFC9000§17.2:
       *   Reserved Bits: The next two bits (those with a mask of 0x18) of byte
       *                  0 are reserved. These bits are protected using header
       *                  protection; see Section 5.4 of [QUIC-TLS]. The value
       *                  included prior to protection MUST be set to 0. *)
      assert (first_byte land 0b00011000 = 0);
      Faraday.write_uint8 t first_byte;
      Faraday.write_string t (CID.to_string dest_cid)

    let write_packet_header t ~pn_length ~header =
      (* TODO: proper packet number length *)
      match header with
      | Packet.Header.Initial _ | Long _ ->
        write_long_header t ~pn_length ~header
      | Short { dest_cid } -> write_short_header t ~pn_length ~dest_cid
  end

  let write_version_negotiation_packet t ~versions ~source_cid ~dest_cid =
    (* From RFC9000§17.2:
     *   Header Form: The most significant bit (0x80) of byte 0 (the first
     *                byte) is set to 1 for long headers.
     *
     *   Fixed Bit: The next bit (0x40) of byte 0 is set to 1. Packets
     *              containing a zero value for this bit are not valid
     *              packets in this version and MUST be discarded. *)
    let form_and_fixed_bits = 0b11000000 in
    Faraday.write_uint8 t form_and_fixed_bits;
    (* From RFC9000§17.2.1:
     *   The Version field of a Version Negotiation packet MUST be set to
     *   0x00000000. *)
    Faraday.write_string t "\x00\x00\x00\x00";
    Header.write_connection_ids t ~source_cid ~dest_cid;
    List.iter (fun version -> Faraday.BE.write_uint32 t version) versions

  let write_packet_payload t payload =
    (* From RFC9000§17.1:
     *   When present in long or short packet headers, they are encoded in 1
     *   to 4 bytes. The number of bits required to represent the packet
     *   number is reduced by including the least significant bits of the
     *   packet number. *)
    match payload with
    | Packet.Payload.Bigstring payload -> Faraday.schedule_bigstring t payload
    | Packet.Payload.String payload -> Faraday.write_string t payload

  let write_retry_payload t ~token ~tag =
    Faraday.write_string t token;
    Faraday.schedule_bigstring t tag

  let write_packet t packet =
    match packet with
    | Packet.VersionNegotiation { source_cid; dest_cid; versions } ->
      write_version_negotiation_packet t ~source_cid ~dest_cid ~versions
    | Frames { header; payload_length; payload; packet_number; _ } ->
      let pn_length = packet_number_length packet_number in
      Header.write_packet_header t ~pn_length ~header;
      Header.write_payload_length t ~pn_length ~header payload_length;
      Header.write_packet_number t ~pn_length ~packet_number;
      write_packet_payload t payload
    | Retry { header; token; tag; _ } ->
      (* PN Length doesn't matter here, retry packets don't have a packet
       * number.
       * TODO: make this better *)
      Header.write_long_header t ~pn_length:0 ~header;
      write_retry_payload t ~token ~tag
end

module Writer = struct
  open Faraday

  let single_frame_needs_legacy_serializer = function
    | Frame_desc.Stream { fragment = { Frame_desc.off; _ }; _ }
    | Frame_desc.Crypto { Frame_desc.off; _ } ->
      off >= (1 lsl 14)
    | _ -> false

  type header_info =
    { version : int32
    ; source_cid : CID.t
    ; dest_cid : CID.t
    ; token : string
    ; encryption_level : Encryption_level.level
    ; packet_number : int64
    ; encrypter : Crypto.AEAD.t
    }

  type t =
    { buffer : Bigstringaf.t
      (* The buffer that the encoder uses for buffered writes. Managed by
       * the control module for the encoder. *)
    ; encoder : Faraday.t
      (* The encoder that handles encoding for writes. Uses the [buffer]
       * referenced above internally. *)
    ; mutable drained_bytes : int
      (* The number of bytes that were not written due to the output stream
       * being closed before all buffered output could be written. Useful
       * for detecting error cases. *)
    }

  let create buffer_size =
    let buffer = Bigstringaf.create buffer_size in
    let encoder = Faraday.of_bigstring buffer in
    { buffer; encoder; drained_bytes = 0 }

  (* From RFC9000§15:
   *   Version numbers used to identify IETF drafts are created by adding the
   *   draft number to 0xff000000. For example, draft-ietf-quic-transport-13
   *   would be identified as 0xff00000D.
   *
   * 29 (dec) = 0x1d
   *
   * 0xff000000 + 0x1d = 0xff00001d *)
  let make_header_info
        ~encrypter
        ~packet_number
        ~encryption_level
        ?(source_cid = CID.empty)
        ?(version = 0x1l)
        ~token
        dest_cid
    =
    { encrypter
    ; version
    ; source_cid
    ; dest_cid
    ; token
    ; packet_number
    ; encryption_level
    }

  (* From RFC<QUIC-TLS-RFC>§4:
   *
   *     +---------------------+-----------------+------------------+
   *     | Packet Type         | Encryption Keys | PN Space         |
   *     +=====================+=================+==================+
   *     | Initial             | Initial secrets | Initial          |
   *     +---------------------+-----------------+------------------+
   *     | 0-RTT Protected     | 0-RTT           | Application data |
   *     +---------------------+-----------------+------------------+
   *     | Handshake           | Handshake       | Handshake        |
   *     +---------------------+-----------------+------------------+
   *     | Retry               | Retry           | N/A              |
   *     +---------------------+-----------------+------------------+
   *     | Version Negotiation | N/A             | N/A              |
   *     +---------------------+-----------------+------------------+
   *     | Short Header        | 1-RTT           | Application data |
   *     +---------------------+-----------------+------------------+
   *
   *               Table 1: Encryption Keys by Packet Type
   *)
  let header_of_encryption_level
        { version; source_cid; dest_cid; token; encryption_level; _ }
    =
    match encryption_level with
    | Encryption_level.Initial ->
      Packet.Header.Initial { version; source_cid; dest_cid; token }
    | Zero_RTT -> Long { version; source_cid; dest_cid; packet_type = Zero_RTT }
    | Handshake ->
      Long { version; source_cid; dest_cid; packet_type = Handshake }
    | Application_data -> Short { dest_cid }

  let write_uint8_bytes buf off byte =
    Bytes.set_uint8 buf off byte;
    off + 1

  let write_uint32_be_bytes buf off n =
    let n = Int32.to_int n in
    let off = write_uint8_bytes buf off ((n lsr 24) land 0xff) in
    let off = write_uint8_bytes buf off ((n lsr 16) land 0xff) in
    let off = write_uint8_bytes buf off ((n lsr 8) land 0xff) in
    write_uint8_bytes buf off (n land 0xff)

  let write_string_bytes buf off s =
    Bytes.blit_string s 0 buf off (String.length s);
    off + String.length s

  let write_string_slice_bytes buf off s ~src_off ~len =
    Bytes.blit_string s src_off buf off len;
    off + len

  let write_bigstring_bytes buf off bs ~src_off ~len =
    Bigstringaf.blit_to_bytes bs ~src_off buf ~dst_off:off ~len;
    off + len

  let write_varint_bytes buf off n =
    let encoding_bytes, encoding =
      if n < 1 lsl 6
      then 1, 0
      else if n < 1 lsl 14
      then 2, 1
      else if n < 1 lsl 30
      then 4, 2
      else 8, 3
    in
    match encoding_bytes with
    | 1 -> write_uint8_bytes buf off ((encoding lsl 6) lor n)
    | 2 ->
      let off =
        write_uint8_bytes buf off ((encoding lsl 6) lor ((n lsr 8) land 0x3f))
      in
      write_uint8_bytes buf off (n land 0xff)
    | 4 ->
      let off =
        write_uint8_bytes buf off ((encoding lsl 6) lor ((n lsr 24) land 0x3f))
      in
      let off = write_uint8_bytes buf off ((n lsr 16) land 0xff) in
      let off = write_uint8_bytes buf off ((n lsr 8) land 0xff) in
      write_uint8_bytes buf off (n land 0xff)
    | 8 ->
      let off =
        write_uint8_bytes buf off ((encoding lsl 6) lor ((n lsr 56) land 0x3f))
      in
      let off = write_uint8_bytes buf off ((n lsr 48) land 0xff) in
      let off = write_uint8_bytes buf off ((n lsr 40) land 0xff) in
      let off = write_uint8_bytes buf off ((n lsr 32) land 0xff) in
      let off = write_uint8_bytes buf off ((n lsr 24) land 0xff) in
      let off = write_uint8_bytes buf off ((n lsr 16) land 0xff) in
      let off = write_uint8_bytes buf off ((n lsr 8) land 0xff) in
      write_uint8_bytes buf off (n land 0xff)
    | _ -> assert false

  let cid_encoded_length cid = 1 + CID.length cid

  let header_base_length header =
    match header with
    | Packet.Header.Initial { token; source_cid; dest_cid; _ } ->
      1
      + 4
      + cid_encoded_length dest_cid
      + cid_encoded_length source_cid
      + varint_encoding_length (String.length token)
      + String.length token
    | Long { source_cid; dest_cid; packet_type = Initial | Zero_RTT | Handshake; _ } ->
      1 + 4 + cid_encoded_length dest_cid + cid_encoded_length source_cid
    | Short { dest_cid } -> 1 + CID.length dest_cid
    | Long { packet_type = Retry; _ } -> assert false

  let write_connection_ids_bytes buf off ~source_cid ~dest_cid =
    let off = write_uint8_bytes buf off (CID.length dest_cid) in
    let off = write_string_bytes buf off (CID.to_string dest_cid) in
    let off = write_uint8_bytes buf off (CID.length source_cid) in
    write_string_bytes buf off (CID.to_string source_cid)

  let write_packet_number_bytes buf off ~pn_length ~packet_number =
    let packet_number =
      Int64.to_int (Int64.logand packet_number 0xFFFFFFFFL)
    in
    match pn_length with
    | 1 -> write_uint8_bytes buf off packet_number
    | 2 ->
      let off = write_uint8_bytes buf off ((packet_number lsr 8) land 0xff) in
      write_uint8_bytes buf off (packet_number land 0xff)
    | 3 ->
      let off = write_uint8_bytes buf off ((packet_number lsr 16) land 0xff) in
      let off = write_uint8_bytes buf off ((packet_number lsr 8) land 0xff) in
      write_uint8_bytes buf off (packet_number land 0xff)
    | 4 ->
      let off = write_uint8_bytes buf off ((packet_number lsr 24) land 0xff) in
      let off = write_uint8_bytes buf off ((packet_number lsr 16) land 0xff) in
      let off = write_uint8_bytes buf off ((packet_number lsr 8) land 0xff) in
      write_uint8_bytes buf off (packet_number land 0xff)
    | _ -> assert false

  let frame_type_length frame =
    varint_encoding_length Frame_desc.(Type.serialize (to_frame_type frame))

  let ack_payload_length ~ranges ~ecn_counts ~delay =
    let range_len = List.length ranges in
    assert (range_len > 0);
    let first, rest = List.hd ranges, List.tl ranges in
    let first_range =
      Int64.sub first.Frame_desc.Range.last first.first |> Int64.to_int
    in
    let base =
      varint_encoding_length (Int64.to_int first.Frame_desc.Range.last)
      + varint_encoding_length delay
      + varint_encoding_length (range_len - 1)
      + varint_encoding_length first_range
    in
    let ranges_len, (_ : int64) =
      List.fold_left
        (fun (acc, smallest_ack) { Frame_desc.Range.first; last } ->
           let gap = Int64.sub (Int64.sub smallest_ack last) 2L |> Int64.to_int in
           let len = Int64.sub last first |> Int64.to_int in
           (acc + varint_encoding_length gap + varint_encoding_length len, first))
        (0, first.first)
        rest
    in
    let ecn_len =
      match ecn_counts with
      | Some (ect0, ect1, cn) ->
        varint_encoding_length ect0
        + varint_encoding_length ect1
        + varint_encoding_length cn
      | None -> 0
    in
    base + ranges_len + ecn_len

  let frame_payload_length = function
    | Frame_desc.Padding n -> n
    | Frame_desc.Ping | Handshake_done -> 0
    | Frame_desc.Ack { delay; ranges; ecn_counts } ->
      ack_payload_length ~ranges ~ecn_counts ~delay
    | Reset_stream { stream_id; application_protocol_error; final_size } ->
      varint_encoding_length (Int64.to_int stream_id)
      + varint_encoding_length application_protocol_error
      + varint_encoding_length final_size
    | Stop_sending { stream_id; application_protocol_error } ->
      varint_encoding_length (Int64.to_int stream_id)
      + varint_encoding_length application_protocol_error
    | Frame_desc.Crypto { Frame_desc.off; len; _ } ->
      varint_encoding_length off + varint_encoding_length len + len
    | Frame_desc.New_token { length; data } ->
      varint_encoding_length length + Bigstringaf.length data
    | Frame_desc.Stream { id; fragment = { Frame_desc.off; len; _ }; _ } ->
      varint_encoding_length (Int64.to_int id)
      + (if off > 0 then varint_encoding_length off else 0)
      + (if len > 0 then varint_encoding_length len else 0)
      + len
    | Frame_desc.Max_data max -> varint_encoding_length max
    | Frame_desc.Max_stream_data { stream_id; max_data } ->
      varint_encoding_length (Int64.to_int stream_id)
      + varint_encoding_length max_data
    | Frame_desc.Max_streams (_, max)
    | Frame_desc.Data_blocked max
    | Frame_desc.Streams_blocked (_, max)
    | Frame_desc.Retire_connection_id max ->
      varint_encoding_length max
    | Frame_desc.Stream_data_blocked { id; max_data } ->
      varint_encoding_length (Int64.to_int id)
      + varint_encoding_length max_data
    | Frame_desc.New_connection_id
        { cid; stateless_reset_token; retire_prior_to; sequence_no } ->
      varint_encoding_length sequence_no
      + varint_encoding_length retire_prior_to
      + cid_encoded_length cid
      + String.length stateless_reset_token
    | Frame_desc.Path_challenge data | Path_response data -> Bigstringaf.length data
    | Frame_desc.Connection_close_quic { frame_type; reason_phrase; error_code } ->
      varint_encoding_length (Error.serialize error_code)
      + varint_encoding_length (Frame_desc.Type.serialize frame_type)
      + varint_encoding_length (String.length reason_phrase)
      + String.length reason_phrase
    | Frame_desc.Connection_close_app { reason_phrase; error_code } ->
      varint_encoding_length error_code
      + varint_encoding_length (String.length reason_phrase)
      + String.length reason_phrase
    | Frame_desc.Unknown _ -> assert false

  let frame_encoded_length frame = frame_type_length frame + frame_payload_length frame

  let write_ack_bytes buf off ~delay ~ranges ~ecn_counts =
    let range_len = List.length ranges in
    assert (range_len > 0);
    let first, rest = List.hd ranges, List.tl ranges in
    let off =
      write_varint_bytes buf off (Int64.to_int first.Frame_desc.Range.last)
    in
    let off = write_varint_bytes buf off delay in
    let off = write_varint_bytes buf off (range_len - 1) in
    let off =
      write_varint_bytes
        buf
        off
        (Int64.sub first.Frame_desc.Range.last first.first |> Int64.to_int)
    in
    let off, (_ : int64) =
      List.fold_left
        (fun (off, smallest_ack) { Frame_desc.Range.first; last } ->
           let gap = Int64.sub (Int64.sub smallest_ack last) 2L |> Int64.to_int in
           let len = Int64.sub last first |> Int64.to_int in
           let off = write_varint_bytes buf off gap in
           let off = write_varint_bytes buf off len in
           off, first)
        (off, first.first)
        rest
    in
    match ecn_counts with
    | Some (ect0, ect1, cn) ->
      let off = write_varint_bytes buf off ect0 in
      let off = write_varint_bytes buf off ect1 in
      write_varint_bytes buf off cn
    | None -> off

  let write_frame_bytes buf off frame =
    let off =
      write_varint_bytes buf off Frame_desc.(Type.serialize (to_frame_type frame))
    in
    match frame with
    | Frame_desc.Padding n ->
      Bytes.fill buf off n '\x00';
      off + n
    | Frame_desc.Ping | Handshake_done -> off
    | Frame_desc.Ack { delay; ranges; ecn_counts } ->
      write_ack_bytes buf off ~delay ~ranges ~ecn_counts
    | Frame_desc.Reset_stream { stream_id; application_protocol_error; final_size } ->
      let off = write_varint_bytes buf off (Int64.to_int stream_id) in
      let off = write_varint_bytes buf off application_protocol_error in
      write_varint_bytes buf off final_size
    | Frame_desc.Stop_sending { stream_id; application_protocol_error } ->
      let off = write_varint_bytes buf off (Int64.to_int stream_id) in
      write_varint_bytes buf off application_protocol_error
    | Frame_desc.Crypto { Frame_desc.off = frame_off; len; payload; payload_off } ->
      let off = write_varint_bytes buf off frame_off in
      let off = write_varint_bytes buf off len in
      write_string_slice_bytes buf off payload ~src_off:payload_off ~len
    | Frame_desc.New_token { length; data } ->
      let off = write_varint_bytes buf off length in
      write_bigstring_bytes buf off data ~src_off:0 ~len:(Bigstringaf.length data)
    | Frame_desc.Stream
        { id
        ; fragment = { Frame_desc.off = frame_off; len; payload; payload_off }
        ; _
        } ->
      let off = write_varint_bytes buf off (Int64.to_int id) in
      let off =
        if frame_off > 0 then write_varint_bytes buf off frame_off else off
      in
      let off = if len > 0 then write_varint_bytes buf off len else off in
      write_string_slice_bytes buf off payload ~src_off:payload_off ~len
    | Frame_desc.Max_data max -> write_varint_bytes buf off max
    | Frame_desc.Max_stream_data { stream_id; max_data } ->
      let off = write_varint_bytes buf off (Int64.to_int stream_id) in
      write_varint_bytes buf off max_data
    | Frame_desc.Max_streams (_, max)
    | Frame_desc.Data_blocked max
    | Frame_desc.Streams_blocked (_, max)
    | Frame_desc.Retire_connection_id max ->
      write_varint_bytes buf off max
    | Frame_desc.Stream_data_blocked { id; max_data } ->
      let off = write_varint_bytes buf off (Int64.to_int id) in
      write_varint_bytes buf off max_data
    | Frame_desc.New_connection_id
        { cid; stateless_reset_token; retire_prior_to; sequence_no } ->
      let off = write_varint_bytes buf off sequence_no in
      let off = write_varint_bytes buf off retire_prior_to in
      let cid_s = CID.to_string cid in
      let off = write_uint8_bytes buf off (String.length cid_s) in
      let off = write_string_bytes buf off cid_s in
      write_string_bytes buf off stateless_reset_token
    | Frame_desc.Path_challenge data | Path_response data ->
      write_bigstring_bytes buf off data ~src_off:0 ~len:(Bigstringaf.length data)
    | Frame_desc.Connection_close_quic { frame_type; reason_phrase; error_code } ->
      let off = write_varint_bytes buf off (Error.serialize error_code) in
      let off = write_varint_bytes buf off (Frame_desc.Type.serialize frame_type) in
      let off = write_varint_bytes buf off (String.length reason_phrase) in
      write_string_bytes buf off reason_phrase
    | Frame_desc.Connection_close_app { reason_phrase; error_code } ->
      let off = write_varint_bytes buf off error_code in
      let off = write_varint_bytes buf off (String.length reason_phrase) in
      write_string_bytes buf off reason_phrase
    | Frame_desc.Unknown _ -> assert false

  let write_packet_header_bytes buf off ~pn_length ~header =
    match header with
    | Packet.Header.Initial { version; source_cid; dest_cid; token } ->
      let first_byte = 0b11000000 lor ((Packet.Type.serialize Initial lsl 4) lor ((pn_length - 1) land 0b11)) in
      let off = write_uint8_bytes buf off first_byte in
      let off = write_uint32_be_bytes buf off version in
      let off = write_connection_ids_bytes buf off ~source_cid ~dest_cid in
      let off = write_varint_bytes buf off (String.length token) in
      write_string_bytes buf off token
    | Long { version; source_cid; dest_cid; packet_type } ->
      let first_byte =
        0b11000000 lor ((Packet.Type.serialize packet_type lsl 4) lor ((pn_length - 1) land 0b11))
      in
      let off = write_uint8_bytes buf off first_byte in
      let off = write_uint32_be_bytes buf off version in
      write_connection_ids_bytes buf off ~source_cid ~dest_cid
    | Short { dest_cid } ->
      let off = write_uint8_bytes buf off (0b01000000 lor ((pn_length - 1) land 0b11)) in
      write_string_bytes buf off (CID.to_string dest_cid)

  let write_frames_packet_legacy t ~header_info frames =
    assert (frames <> []);
    let tag_len = Crypto.AEAD.tag_len header_info.encrypter in
    let pn_length = packet_number_length header_info.packet_number in
    let payloadf = Faraday.create 0x400 in
    List.iter (Frame.write_frame payloadf) frames;
    let pn_offset = 4 - pn_length in
    let cur_size = Faraday.pending_bytes payloadf + tag_len in
    (if
       pn_offset
       +
       (* sample size *)
       16
       > cur_size
     then
       (* needs padding *)
       let n_padding = pn_offset + 16 - cur_size in
       Frame.write_padding payloadf n_padding);
    let plaintext = Faraday.serialize_to_string payloadf in
    (* AEAD ciphertext length is the same as the plaintext length (+ tag). *)
    let payload_length = String.length plaintext + tag_len in
    let header = header_of_encryption_level header_info in
    let hf = Faraday.create 0x100 in
    Pkt.Header.write_packet_header hf ~pn_length ~header;

    let payload_length, plaintext =
      let packet_len =
        Faraday.pending_bytes hf
        + payload_length
        + pn_length
        + varint_encoding_length 1200
      in
      match header_info.encryption_level, packet_len with
      | Initial, packet_len when packet_len < 1200 ->
        (* From RFC9000§14.1:
         *   A client MUST expand the payload of all UDP datagrams carrying
         *   Initial packets to at least the smallest allowed maximum datagram
         *   size of 1200 bytes by adding PADDING frames to the Initial packet or
         *   by coalescing the Initial packet; see Section 12.2. Initial packets
         *   can even be coalesced with invalid packets, which a receiver will
         *   discard. Similarly, a server MUST expand the payload of all UDP
         *   datagrams carrying ack-eliciting Initial packets to at least the
         *   smallest allowed maximum datagram size of 1200 bytes. *)
        let padding_n = 1200 - packet_len in
        let padded_payload = Bytes.create (String.length plaintext + padding_n) in
        Bytes.blit_string plaintext 0 padded_payload 0 (String.length plaintext);
        Bytes.fill padded_payload (String.length plaintext) padding_n '\x00';
        payload_length + padding_n, Bytes.unsafe_to_string padded_payload
      | _ -> payload_length, plaintext
    in

    Pkt.Header.write_payload_length hf ~pn_length ~header payload_length;
    Pkt.Header.write_packet_number
      hf
      ~pn_length
      ~packet_number:header_info.packet_number;

    let unprotected_header = Faraday.serialize_to_string hf in

    let encrypted_header, sealed_payload =
      Crypto.AEAD.encrypt_packet_parts
        header_info.encrypter
        ~packet_number:header_info.packet_number
        ~header:unprotected_header
        plaintext
    in
    Faraday.write_string t.encoder encrypted_header;
    Faraday.write_string t.encoder sealed_payload

  let write_frames_packet t ~header_info frames =
    let use_legacy =
      match frames with
      | [ frame ] -> single_frame_needs_legacy_serializer frame
      | _ -> false
    in
    if use_legacy
    then write_frames_packet_legacy t ~header_info frames
    else (
      assert (frames <> []);
      let tag_len = Crypto.AEAD.tag_len header_info.encrypter in
      let pn_length = packet_number_length header_info.packet_number in
      let payload_len =
        List.fold_left (fun acc frame -> acc + frame_encoded_length frame) 0 frames
      in
      let write_frames plaintext =
        ignore (List.fold_left (write_frame_bytes plaintext) 0 frames)
      in
      let pn_offset = 4 - pn_length in
      let min_payload_len = pn_offset + 16 - tag_len in
      let padding =
        if payload_len < min_payload_len then min_payload_len - payload_len else 0
      in
      let payload_len = payload_len + padding in
      let plaintext = Bytes.create payload_len in
      write_frames plaintext;
      let payload_off = payload_len - padding in
      let payload_off =
        if padding > 0
        then (
          Bytes.fill plaintext payload_off padding '\x00';
          payload_off + padding)
        else payload_off
      in
      assert (payload_off = payload_len);
      let header = header_of_encryption_level header_info in
      let payload_length = payload_len + tag_len in
      let header_len payload_length =
        let payload_len_field =
          match header with
          | Packet.Header.Initial _
          | Long { packet_type = Initial | Zero_RTT | Handshake; _ } ->
            varint_encoding_length (pn_length + payload_length)
          | Short _ -> 0
          | Long { packet_type = Retry; _ } -> assert false
        in
        header_base_length header + payload_len_field + pn_length
      in
      let packet_len_for_initial_padding =
        header_base_length header
        + payload_length
        + pn_length
        + varint_encoding_length 1200
      in
      let payload_length, plaintext =
        match header_info.encryption_level, packet_len_for_initial_padding with
        | Initial, packet_len when packet_len < 1200 ->
          let padding_n = 1200 - packet_len in
          let padded = Bytes.create (payload_len + padding_n) in
          Bytes.blit plaintext 0 padded 0 payload_len;
          Bytes.fill padded payload_len padding_n '\x00';
          payload_length + padding_n, padded
        | _ -> payload_length, plaintext
      in
      let header_len = header_len payload_length in
      let unprotected_header = Bytes.create header_len in
      let off = write_packet_header_bytes unprotected_header 0 ~pn_length ~header in
      let off =
        match header with
        | Packet.Header.Initial _
        | Long { packet_type = Initial | Zero_RTT | Handshake; _ } ->
          write_varint_bytes unprotected_header off (pn_length + payload_length)
        | Short _ -> off
        | Long { packet_type = Retry; _ } -> assert false
      in
      let off =
        write_packet_number_bytes
          unprotected_header
          off
          ~pn_length
          ~packet_number:header_info.packet_number
      in
      assert (off = header_len);
      let encrypted_header, sealed_payload =
        Crypto.AEAD.encrypt_packet_parts
          header_info.encrypter
          ~packet_number:header_info.packet_number
          ~header:(Bytes.unsafe_to_string unprotected_header)
          (Bytes.unsafe_to_string plaintext)
      in
      Faraday.write_string t.encoder encrypted_header;
      Faraday.write_string t.encoder sealed_payload)

  let faraday t = t.encoder
  let flush t f = flush t.encoder f
  let yield t = Faraday.yield t.encoder
  let close t = Faraday.close t.encoder

  let close_and_drain t =
    Faraday.close t.encoder;
    let drained = Faraday.drain t.encoder in
    t.drained_bytes <- t.drained_bytes + drained

  let is_closed t = Faraday.is_closed t.encoder
  let drained_bytes t = t.drained_bytes

  let report_result t result =
    match result with
    | `Closed -> close_and_drain t
    | `Ok len -> shift t.encoder len

  let next t =
    match Faraday.operation t.encoder with
    | `Close -> `Close (drained_bytes t)
    | `Yield -> `Yield
    | `Writev iovecs -> `Write iovecs
end
