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

let rec decomp n acc x =
  if n = 0 then acc else decomp (n - 1) ((x land 0xff) :: acc) (x lsr 8)

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
  let ns = decomp encoding_bytes [] n in
  let hd = List.hd ns in
  let tl = List.tl ns in
  (* From RFC9000§16:
   *   The QUIC variable-length integer encoding reserves the two most
   *   significant bits of the first byte to encode the base 2 logarithm of the
   *   integer encoding length in bytes. The integer value is encoded on the
   *   remaining bits, in network byte order. *)
  Faraday.write_uint8 t ((encoding lsl 6) lor hd);
  List.iter (fun n -> Faraday.write_uint8 t n) tl

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
          let gap = Int64.sub smallest_ack last in
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
    let { IOVec.off; len; buffer } = fragment in
    write_variable_length_integer t off;
    write_variable_length_integer t len;
    Faraday.schedule_bigstring t buffer

  let write_new_token t ~length ~data =
    write_variable_length_integer t length;
    Faraday.schedule_bigstring t data

  let write_stream t ~stream_id ~fragment =
    let { IOVec.off; len; buffer } = fragment in
    write_variable_length_integer t (Int64.to_int stream_id);
    if off > 0 then write_variable_length_integer t off;
    if len > 0 then write_variable_length_integer t len;
    Faraday.schedule_bigstring t buffer

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
      let pn_bytes = decomp pn_length [] packet_number in
      List.iter (fun byte -> Faraday.write_uint8 t byte) pn_bytes

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
    Faraday.schedule_bigstring t payload

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

  let write_frames_packet t ~header_info frames =
    assert (frames <> []);
    let tag_len = Crypto.AEAD.tag_len header_info.encrypter in
    let pn_length = packet_number_length header_info.packet_number in
    let tmpf = Faraday.create 0x400 in
    List.iter (Frame.write_frame tmpf) frames;
    let frames = Faraday.serialize_to_bigstring tmpf in
    let tmpf = Faraday.create 0x400 in
    Pkt.write_packet_payload tmpf frames;
    let pn_offset = 4 - pn_length in
    let cur_size = Bigstringaf.length frames + tag_len in
    (if pn_offset + (* sample size *) 16 > cur_size
    then
      (* needs padding *)
      let n_padding = pn_offset + 16 - cur_size in
      Frame.write_padding tmpf n_padding);
    let plaintext = Cstruct.of_bigarray (Faraday.serialize_to_bigstring tmpf) in
    (* AEAD ciphertext length is the same as the plaintext length (+ tag). *)
    let payload_length = Cstruct.length plaintext + tag_len in
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
        let padding_f = Faraday.create padding_n in
        Frame.write_padding padding_f padding_n;
        ( payload_length + padding_n
        , Cstruct.append
            plaintext
            (Cstruct.of_bigarray (Faraday.serialize_to_bigstring padding_f)) )
      | _ -> payload_length, plaintext
    in

    Pkt.Header.write_payload_length hf ~pn_length ~header payload_length;
    Pkt.Header.write_packet_number
      hf
      ~pn_length
      ~packet_number:header_info.packet_number;

    let unprotected_header =
      Cstruct.of_bigarray (Faraday.serialize_to_bigstring hf)
    in

    let protected =
      Crypto.AEAD.encrypt_packet
        header_info.encrypter
        ~packet_number:header_info.packet_number
        ~header:unprotected_header
        plaintext
    in
    Faraday.schedule_bigstring t.encoder (Cstruct.to_bigarray protected)

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
