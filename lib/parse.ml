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

module Result = Stdlib.Result
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
         (fun gap len -> Int64.of_int gap, Int64.of_int len)
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
    (* From RFC<QUIC-RFC>§19.3.1:
     *   Thus, given a largest packet number for the range, the smallest value
     *   is determined by the formula:
     *
     *     smallest = largest - ack_range
     *)
    let smallest_ack = largest_ack - first_ack_range in
    let first_range =
      { Frame.Range.first = Int64.of_int smallest_ack
      ; last = Int64.of_int largest_ack
      }
    in
    let ranges =
      List.fold_left
        (fun acc (gap, len) ->
          (* TODO: validate smallest < gap + 2 *)
          (* From RFC<QUIC-RFC>§19.3.1:
           *   Gap and ACK Range value use a relative integer encoding for
           *   efficiency. Though each encoded value is positive, the values are
           *   subtracted, so that each ACK Range describes progressively
           *   lower-numbered packets. *)
          let smallest_ack = (List.hd acc).Frame.Range.first in
          (* From RFC<QUIC-RFC>§19.3.1:
           *   The value of the Gap field establishes the largest packet number
           *   value for the subsequent ACK Range using the following formula:
           *
           *     largest = previous_smallest - gap - 2
           *)
          let largest_ack = Int64.(sub (sub smallest_ack gap) 2L) in
          let smallest_ack = Int64.sub largest_ack len in
          { Frame.Range.first = smallest_ack; last = largest_ack } :: acc)
        [ first_range ]
        ranges
    in
    Frame.Ack { delay = ack_delay; ranges; ecn_counts }

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
    variable_length_integer >>= fun off ->
    variable_length_integer >>= fun len ->
    lift
      (fun buffer -> Frame.Crypto { IOVec.off; len; buffer })
      (take_bigstring len)

  let parse_new_token_frame =
    variable_length_integer >>= fun length ->
    lift (fun data -> Frame.New_token { length; data }) (take_bigstring length)

  let parse_stream_frame ~off ~len ~fin =
    let parse_off = if off then variable_length_integer else return 0 in
    let parse_len = if len then variable_length_integer else available in
    variable_length_integer >>= fun stream_id ->
    parse_off >>= fun off ->
    parse_len >>= fun len ->
    lift
      (fun buffer ->
        Frame.Stream
          { id = stream_id
          ; fragment = { IOVec.off; len; buffer }
          ; is_fin = fin
          })
      (take_bigstring len)

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
    lift2
      (fun cid stateless_reset_token ->
        Frame.New_connection_id
          { cid; sequence_no; stateless_reset_token; retire_prior_to })
      CID.parse
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

  let frame =
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

  let parser handler = skip_many (frame <* commit >>| handler)
end

module Packet = struct
  module Header = struct
    module Long = struct
      let parse =
        lift3
          (fun version dst_cid src_cid ->
            (* From RFC<QUIC-RFC>§17.2:
             *   In QUIC version 1, this value MUST NOT exceed 20. Endpoints that
             *   receive a version 1 long header with a value larger than 20 MUST
             *   drop the packet.  Servers SHOULD be able to read longer connection
             *   IDs from other QUIC versions in order to properly form a version
             *   negotiation packet. *)
            (* TODO: "drop" the packet. *)
            Packet.Version.parse version, src_cid, dst_cid)
          BE.any_int32
          CID.parse
          CID.parse
    end

    module Short = struct
      let parse = take CID.length
    end
  end

  module Payload = struct
    let version_negotiation ~source_cid ~dest_cid =
      (* From RFC<QUIC-RFC>§17.2:
       *   The Version Negotiation packet does not include the Packet Number
       *   and Length fields present in other packets that use the long header
       *   form. Consequently, a Version Negotiation packet consumes an entire
       *   UDP datagram.
       *
       *   A server MUST NOT send more than one Version Negotiation packet in
       *   response to a single UDP datagram. *)
      available >>= fun remaining_size ->
      lift
        (fun versions ->
          (* TODO: do we need to validate that version is not 0? *)
          Packet.VersionNegotiation { source_cid; dest_cid; versions })
        (count remaining_size BE.any_int32)

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
    let retry ~version ~source_cid ~dest_cid =
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
      >>= fun pseudo ->
      lift
        (fun tag ->
          Packet.Retry
            { header =
                Long { version; source_cid; dest_cid; packet_type = Retry }
            ; token = retry_token
            ; pseudo
            ; tag
            })
        (take 16)

    let payload ~payload_length ~header ~packet_number plaintext =
      let plaintext = Cstruct.to_bigarray plaintext in
      assert (payload_length >= Bigstringaf.length plaintext);
      advance payload_length >>| fun () ->
      Packet.Frames
        { header; payload_length; payload = plaintext; packet_number }

    let parser ~pn_length ~header ~packet_number ~payload_length plaintext =
      match header with
      | Packet.Header.Short _ ->
        payload ~payload_length ~header ~packet_number plaintext
      | Initial _ | Long _ ->
        (* From RFC<QUIC-RFC>§17.2:
         *   Length: The length of the remainder of the packet (that is, the
         *   Packet Number and Payload fields) in bytes, encoded as a
         *   variable-length integer (Section 16). *)
        let payload_length = payload_length - pn_length in
        payload ~payload_length ~header ~packet_number plaintext
  end

  let unprotected =
    Header.Long.parse >>= fun (version, source_cid, dest_cid) ->
    match version with
    | Negotiation ->
      Payload.version_negotiation ~source_cid ~dest_cid
    | Number version ->
      Payload.retry ~version ~source_cid ~dest_cid

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
  let protected_long_header ~packet_type =
    Header.Long.parse >>= fun (version, source_cid, dest_cid) ->
    match version with
    | Negotiation ->
      assert false
    | Number version ->
      match packet_type with
      | Packet.Type.Initial ->
        variable_length_integer >>= fun token_length ->
        lift2
          (fun token payload_length ->
            Format.eprintf
              "AHOY \"%a\" \"%a\"@."
              Hex.pp
              (Hex.of_string source_cid.id)
              Hex.pp
              (Hex.of_string dest_cid.id);
            ( Packet.Header.Initial { version; source_cid; dest_cid; token }
            , payload_length ))
          (take token_length)
          variable_length_integer
      | Zero_RTT | Handshake ->
        lift
          (fun payload_length ->
            ( Packet.Header.Long { version; source_cid; dest_cid; packet_type }
            , payload_length ))
          variable_length_integer
      | Retry ->
        failwith "retry is unprotected"

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
  let short_header =
    lift
      (fun dest_cid ->
        Packet.Header.Short { dest_cid = CID.{ id = dest_cid; length } })
      Header.Short.parse

  let protected_header =
    any_uint8 >>= fun first_byte ->
    match Packet.Header.Type.parse first_byte with
    | Packet.Header.Type.Long ->
      protected_long_header ~packet_type:(Packet.parse_type first_byte)
    | Short ->
      short_header >>= fun hdr ->
      available >>| fun avail -> hdr, avail

  let is_protected bs ~off =
    let first_byte = Char.code (Bigstringaf.unsafe_get bs off) in
    let version = Bigstringaf.unsafe_get_int32_be bs (off + 1) in
    (* From RFC<QUIC-TLS-RFC>§5.3:
     *   All QUIC packets other than Version Negotiation and Retry packets are
     *   protected with an AEAD algorithm [AEAD]. *)
    match Packet.Header.Type.parse first_byte with
    | Short ->
      true
    | Long ->
      match Packet.Version.parse version with
      | Negotiation ->
        false
      | Number _ ->
        match Packet.parse_type first_byte with Retry -> false | _ -> true

  type protection_type =
    | Unprotected
    | Decrypted of
        { header : Packet.Header.t
        ; payload_length : int
        ; decrypted : Crypto.AEAD.ret option
        }

  let parser
      ~(decrypt :
         header:Packet.Header.t
         -> Cstruct.buffer
         -> off:int
         -> len:int
         -> Crypto.AEAD.ret option)
    =
    (* XXX(anmonteiro): it's important to call `peek_char_fail` before calling
     * `available` because Angstrom.Unbuffered starts the parser with
     * `Bigstringaf.empty` before starting to get input. If `available` is
     * called right away, it'll be 0 and fail. *)
    peek_char_fail >>= fun first_byte ->
    let first_byte = Char.code first_byte in
    available >>= fun avail ->
    Unsafe.peek avail (fun bs ~off ~len ->
        (* let first_byte = Char.code (Bigstringaf.unsafe_get bs off) in *)
        if not (Bits.test first_byte 6) then
          (* From RFC<QUIC-RFC>§17.2:
           *   Fixed Bit: The next bit (0x40) of byte 0 is set to 1. Packets
           *   containing a zero value for this bit are not valid packets in
           *   this version and MUST be discarded. *)
          failwith "TODO: error"
        else
          let has_header_protection = is_protected bs ~off in
          if has_header_protection then
            let header, payload_length =
              Result.get_ok
                (Angstrom.parse_bigstring
                   ~consume:Prefix
                   protected_header
                   (Bigstringaf.sub bs ~off ~len))
            in
            Decrypted
              { header
              ; payload_length
              ; decrypted = decrypt ~header bs ~off ~len
              }
          else
            Unprotected)
    >>= function
    | Decrypted { decrypted = None; _ } ->
      failwith "failed to decrypt, fix me"
    | Decrypted
        { header
        ; payload_length
        ; decrypted =
            Some
              { Crypto.AEAD.packet_number
              ; pn_length
              ; plaintext
              ; header = header_cs
              }
        } ->
      advance (Cstruct.len header_cs) >>= fun () ->
      Payload.parser ~pn_length ~header ~packet_number ~payload_length plaintext
    | Unprotected ->
      (* From RFC<QUIC-TLS-RFC>§5.3:
       *   All QUIC packets other than Version Negotiation and Retry packets
       *   are protected with an AEAD algorithm [AEAD].
       *
       * NOTE(anmonteiro): Can only be one of the above: Negotiation or Retry.
       *)
      advance 1 *> unprotected
end

module Reader = struct
  module AU = Angstrom.Unbuffered

  type error = [ `Parse of string list * string ]

  type 'error parse_state =
    | Done
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
    ; mutable wakeup : Optional_thunk.t
    }

  type server = error t

  let create parser =
    { parser; parse_state = Done; closed = false; wakeup = Optional_thunk.none }

  let is_closed t = t.closed

  let on_wakeup t k =
    if is_closed t then
      failwith "on_wakeup on closed reader"
    else if Optional_thunk.is_some t.wakeup then
      failwith "on_wakeup: only one callback can be registered at a time"
    else
      t.wakeup <- Optional_thunk.some k

  let wakeup t =
    let f = t.wakeup in
    t.wakeup <- Optional_thunk.none;
    Optional_thunk.call_if_some f

  let packets ~decrypt handler =
    let parser = skip_many (Packet.parser ~decrypt <* commit >>| handler) in
    create (parser >>| Result.ok)

  let transition t state =
    match state with
    | AU.Done (consumed, Ok ()) ->
      t.parse_state <- Done;
      consumed
    | AU.Done (consumed, Error error) ->
      t.parse_state <- Fail error;
      consumed
    | AU.Fail (consumed, marks, msg) ->
      t.parse_state <- Fail (`Parse (marks, msg));
      consumed
    | AU.Partial { committed; continue } ->
      t.parse_state <- Partial continue;
      committed

  let start t state =
    match state with
    | AU.Done _ ->
      failwith "Quic.Parse.unable to start parser"
    | AU.Fail (0, marks, msg) ->
      t.parse_state <- Fail (`Parse (marks, msg))
    | AU.Partial { committed = 0; continue } ->
      t.parse_state <- Partial continue
    | _ ->
      assert false

  let rec read_with_more t bs ~off ~len more =
    let initial = match t.parse_state with Done -> true | _ -> false in
    let consumed =
      match t.parse_state with
      | Fail _ ->
        0
      | Done ->
        start t (AU.parse t.parser);
        read_with_more t bs ~off ~len more
      | Partial continue ->
        transition t (continue bs more ~off ~len)
    in
    (* Special case where the parser just started and was fed a zero-length
     * bigstring. Avoid putting them parser in an error state in this scenario.
     * If we were already in a `Partial` state, return the error. *)
    if initial && len = 0 then t.parse_state <- Done;
    (match more with Complete -> t.closed <- true | Incomplete -> ());
    consumed

  let force_close t = t.closed <- true

  let next t =
    match t.parse_state with
    | Fail failure ->
      `Error failure
    | _ when t.closed ->
      `Close
    | Done ->
      `Start
    | Partial _ ->
      `Read
end
