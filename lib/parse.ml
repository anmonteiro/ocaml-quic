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

module Frame = struct
  let parse_padding_frames () =
    let count = ref 0 in
    skip_while (fun c ->
        let r = Char.code c = 0x0 in
        if r then incr count;
        r)
    >>| fun () -> !count

  let parse_ack_frame ecn_counts =
    variable_length_integer >>= fun largest_ack ->
    variable_length_integer >>= fun ack_delay ->
    variable_length_integer >>= fun ack_range_count ->
    variable_length_integer >>= fun first_ack_range ->
    count
      ack_range_count
      (lift2
         (fun gap len -> gap, len)
         variable_length_integer
         variable_length_integer)
    >>= fun ranges ->
    (if not ecn_counts then
       return None
    else
      lift3
        (fun ect0 ect1 cn -> Some (ect0, ect1, cn))
        variable_length_integer
        variable_length_integer
        variable_length_integer)
    >>| fun ecn_counts ->
    Frame.Ack
      { largest = largest_ack
      ; delay = ack_delay
      ; first_range = first_ack_range
      ; ranges
      ; ecn_counts
      }

  let parse_reset_stream_frame =
    lift3
      (fun stream_id error final_size ->
        Frame.Reset_stream
          { stream_id; application_protocol_error = error; final_size })
      variable_length_integer
      variable_length_integer
      variable_length_integer

  let parse_stop_sending_frame =
    lift2
      (fun stream_id error ->
        Frame.Stop_sending { stream_id; application_protocol_error = error })
      variable_length_integer
      variable_length_integer

  let parse_crypto_frame =
    variable_length_integer >>= fun offset ->
    variable_length_integer >>= fun length ->
    lift
      (fun data -> Frame.Crypto { offset; length; data })
      (take_bigstring length)

  let parse_new_token_frame =
    variable_length_integer >>= fun length ->
    lift (fun data -> Frame.New_token { length; data }) (take_bigstring length)

  let parse_stream_frame ~off ~len ~fin =
    let parse_off = if off then variable_length_integer else return 0 in
    let parse_len = if len then variable_length_integer else available in
    variable_length_integer >>= fun stream_id ->
    parse_off >>= fun offset ->
    parse_len >>= fun length ->
    lift
      (fun data ->
        Frame.Stream { stream_id; offset; length; data; is_fin = fin })
      (take_bigstring length)

  let parse_max_data_frame =
    lift (fun n -> Frame.Max_data n) variable_length_integer

  let parse_max_stream_data_frame =
    lift2
      (fun stream_id n -> Frame.Max_stream_data { stream_id; max_data = n })
      variable_length_integer
      variable_length_integer

  let parse_max_streams_frame direction =
    lift (fun n -> Frame.Max_streams (direction, n)) variable_length_integer

  let parse_data_blocked_frame =
    lift (fun n -> Frame.Data_blocked n) variable_length_integer

  let parse_stream_data_blocked_frame =
    lift2
      (fun stream_id n -> Frame.Stream_data_blocked { stream_id; max_data = n })
      variable_length_integer
      variable_length_integer

  let parse_streams_blocked_frame direction =
    lift (fun n -> Frame.Streams_blocked (direction, n)) variable_length_integer

  let parse_new_connection_id_frame =
    variable_length_integer >>= fun sequence_no ->
    variable_length_integer >>= fun retire_prior_to ->
    any_uint8 >>= fun length ->
    lift2
      (fun conn_id stateless_reset_token ->
        Frame.New_connection_id
          { cid = { Packet.CID.length; id = conn_id }
          ; sequence_no
          ; stateless_reset_token
          ; retire_prior_to
          })
      (take length)
      (take 16)

  let parse_retire_connection_id_frame =
    lift
      (fun seq_no -> Frame.Retire_connection_id seq_no)
      variable_length_integer

  let parse_path_challenge_frame =
    lift (fun data -> Frame.Path_challenge data) (take_bigstring 8)

  let parse_path_response_frame =
    lift (fun data -> Frame.Path_response data) (take_bigstring 8)

  let parse_connection_close_quic_frame =
    variable_length_integer >>= fun error_code ->
    variable_length_integer >>= fun frame_type ->
    variable_length_integer >>= fun reason_phrase_length ->
    lift
      (fun reason_phrase ->
        Frame.Connection_close_quic
          { error_code
          ; frame_type = Frame.Type.parse frame_type
          ; reason_phrase
          })
      (take reason_phrase_length)

  let parse_connection_close_app_frame =
    variable_length_integer >>= fun error_code ->
    variable_length_integer >>= fun reason_phrase_length ->
    lift
      (fun reason_phrase ->
        Frame.Connection_close_app { error_code; reason_phrase })
      (take reason_phrase_length)

  let parser =
    (* From RFC<QUIC-RFC>§12.4:
     *   The Frame Type field uses a variable length integer encoding (see
     *   Section 16) with one exception. To ensure simple and efficient
     *   implementations of frame parsing, a frame type MUST use the shortest
     *   possible encoding. *)
    variable_length_integer >>| Frame.Type.parse >>= function
    | Frame.Type.Padding ->
      (* From RFC<QUIC-RFC>§19.1:
       *   [...] a PADDING frame consists of the single byte that identifies
       *   the frame as a PADDING frame. *)
      lift (fun count -> Frame.Padding count) (parse_padding_frames ())
    | Ping ->
      return Frame.Ping
    | Ack { ecn_counts } ->
      parse_ack_frame ecn_counts
    | Reset_stream ->
      parse_reset_stream_frame
    | Stop_sending ->
      parse_stop_sending_frame
    | Crypto ->
      parse_crypto_frame
    | New_token ->
      parse_new_token_frame
    | Stream { off; len; fin } ->
      parse_stream_frame ~off ~len ~fin
    | Max_data ->
      parse_max_data_frame
    | Max_stream_data ->
      parse_max_stream_data_frame
    | Max_streams direction ->
      parse_max_streams_frame direction
    | Data_blocked ->
      parse_data_blocked_frame
    | Stream_data_blocked ->
      parse_stream_data_blocked_frame
    | Streams_blocked direction ->
      parse_streams_blocked_frame direction
    | New_connection_id ->
      parse_new_connection_id_frame
    | Retire_connection_id ->
      parse_retire_connection_id_frame
    | Path_challenge ->
      parse_path_challenge_frame
    | Path_response ->
      parse_path_response_frame
    | Connection_close_quic ->
      parse_connection_close_quic_frame
    | Connection_close_app ->
      parse_connection_close_app_frame
    | Handshake_done ->
      return Frame.Handshake_done
    | Unknown x ->
      return (Frame.Unknown x)
end

module Packet = struct
  module Header = struct
    module Long = struct
      let parse =
        BE.any_int32 >>= fun version ->
        any_uint8 >>= fun dst_len ->
        (* From RFC<QUIC-RFC>§17.2:
         *   This length is encoded as an 8-bit unsigned integer. In QUIC version
         *   1, this value MUST NOT exceed 20. Endpoints that receive a version 1
         *   long header with a value larger than 20 MUST drop the packet.
         *   Servers SHOULD be able to read longer connection IDs from other QUIC
         *   versions in order to properly form a version negotiation packet. *)
        (* TODO: "drop" the packet. *)
        take dst_len >>= fun dst_cid ->
        any_uint8 >>= fun src_len ->
        take src_len >>= fun src_cid ->
        return
          ( Packet.Version.parse version
          , { Packet.CID.length = src_len; id = src_cid }
          , { Packet.CID.length = dst_len; id = dst_cid } )
    end

    module Short = struct
      let parse = take Packet.CID.length
    end
  end

  let parse_long_header_packet_payload =
    variable_length_integer >>= take_bigstring

  let parse_version_negotiation_packet =
    (* From RFC<QUIC-RFC>§17.2:
     *   The Version Negotiation packet does not include the Packet Number
     *   and Length fields present in other packets that use the long header
     *   form. Consequently, a Version Negotiation packet consumes an entire
     *   UDP datagram.
     *
     *   A server MUST NOT send more than one Version Negotiation packet in
     *   response to a single UDP datagram. *)
    available >>= fun remaining_size ->
    count remaining_size (lift Packet.Version.parse BE.any_int32)

  (*
   *  Retry Packet {
   *    Header Form (1) = 1,
   *    Fixed Bit (1) = 1,
   *    Long Packet Type (2) = 3,
   *    Unused (4),
   *    Version (32),
   *    Destination Connection ID Length (8),
   *    Destination Connection ID (0..160),
   *    Source Connection ID Length (8),
   *    Source Connection ID (0..160),
   *    Retry Token (..),
   *    Retry Integrity Tag (128),
   *  }
   *)
  let parse_retry_packet =
    (* From RFC<QUIC-RFC>§12.2:
     *   Retry packets (Section 17.2.5), Version Negotiation packets (Section
     *   17.2.1), and packets with a short header (Section 17.3) do not contain a
     *   Length field and so cannot be followed by other packets in the same UDP
     *   datagram. *)
    available >>= fun remaining_size ->
    (* take until the last 128 bits, reserved for the integrity tag *)
    take (remaining_size - 16) >>= fun retry_token ->
    pos >>= fun position ->
    (* XXX(anmonteiro): terrible hack, do better here *)
    Unsafe.take 0 (fun bs ~off:_ ~len:_ ->
        Bigstringaf.sub bs ~off:0 ~len:position)
    >>= fun pseudo -> lift (fun tag -> retry_token, pseudo, tag) (take 16)

  (*
   *  Long Header Packet {
   *    Header Form (1) = 1,
   *    Fixed Bit (1) = 1,
   *    Long Packet Type (2),
   *    Type-Specific Bits (4),
   *    Version (32),
   *    Destination Connection ID Length (8),
   *    Destination Connection ID (0..160),
   *    Source Connection ID Length (8),
   *    Source Connection ID (0..160),
   *  }
   *)
  let parse_long_header_packet first_byte =
    Header.Long.parse >>= fun (version, src_cid, dst_cid) ->
    match version with
    | Negotiation ->
      lift
        (fun versions ->
          Packet.VersionNegotiation
            { source_cid = src_cid; dest_cid = dst_cid; versions })
        parse_version_negotiation_packet
    | Number _ ->
      (match Packet.Header.parse_type first_byte with
      | Initial ->
        variable_length_integer >>= fun token_length ->
        take token_length >>= fun token ->
        let header =
          Packet.Header.Initial
            { version; source_cid = src_cid; dest_cid = dst_cid; token }
        in
        lift
          (fun bs -> Packet.Crypt { header; payload = bs })
          parse_long_header_packet_payload
      | Zero_RTT ->
        let header =
          Packet.Header.Zero_RTT
            { version; source_cid = src_cid; dest_cid = dst_cid }
        in
        lift
          (fun bs -> Packet.Crypt { header; payload = bs })
          parse_long_header_packet_payload
      | Handshake ->
        let header =
          Packet.Header.Zero_RTT
            { version; source_cid = src_cid; dest_cid = dst_cid }
        in
        lift
          (fun bs -> Packet.Crypt { header; payload = bs })
          parse_long_header_packet_payload
      | Retry ->
        lift
          (fun (retry_token, pseudo, tag) ->
            Packet.Retry
              { version
              ; source_cid = src_cid
              ; dest_cid = dst_cid
              ; token = retry_token
              ; pseudo
              ; tag
              })
          parse_retry_packet)

  (*
   *  Short Header Packet {
   *    Header Form (1) = 0,
   *    Fixed Bit (1) = 1,
   *    Spin Bit (1),
   *    Reserved Bits (2),
   *    Key Phase (1),
   *    Packet Number Length (2),
   *    Destination Connection ID (0..160),
   *    Packet Number (8..32),
   *    Packet Payload (..),
   *  }
   *)
  let parse_short_header_packet =
    Header.Short.parse >>= fun dest_cid ->
    let header =
      Packet.Header.Short { dest_cid = Packet.CID.{ id = dest_cid; length } }
    in
    lift
      (fun payload -> Packet.Crypt { header; payload })
      (available >>= take_bigstring)

  let parser =
    any_uint8 >>= fun first_byte ->
    if not (Bits.test first_byte 6) then
      (* From RFC<QUIC-RFC>§17.2:
       *   Fixed Bit: The next bit (0x40) of byte 0 is set to 1. Packets
       *   containing a zero value for this bit are not valid packets in
       *   this version and MUST be discarded. *)
      failwith "TODO: error"
    else
      match Bits.test first_byte 7 with
      | true ->
        (* From RFC<QUIC-RFC>§17.2:
         *   Header Form: The most significant bit (0x80) of byte 0 (the
         *   first byte) is set to 1 for long headers. *)
        parse_long_header_packet first_byte
      | false ->
        (* From RFC<QUIC-RFC>§17.3:
         *   Header Form: The most significant bit (0x80) of byte 0 is set
         *   to 0 for the short header. *)
        parse_short_header_packet
end

(* TODO: parse packet number?! *)
