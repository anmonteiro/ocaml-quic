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
module Preferred_address = struct
  (* From RFC<QUIC-RFC>§18.2:
   *
   *   Preferred Address {
   *     IPv4 Address (32),
   *     IPv4 Port (16),
   *     IPv6 Address (128),
   *     IPv6 Port (16),
   *     CID Length (8),
   *     Connection ID (..),
   *     Stateless Reset Token (128),
   *   }
   *)
  type t =
    { ipv4_addr : string
    ; ipv4_port : int
    ; ipv6_addr : string
    ; ipv6_port : int
    ; cid : CID.t
    ; stateless_reset_token : string
    }

  let serialized_length t = 4 + 2 + 8 + 2 + 1 + t.cid.length + 8

  let parse =
    let open Angstrom in
    take 4 >>= fun ipv4_addr ->
    BE.any_uint16 >>= fun ipv4_port ->
    take 8 >>= fun ipv6_addr ->
    BE.any_uint16 >>= fun ipv6_port ->
    any_uint8 >>= fun cid_length ->
    lift2
      (fun cid token ->
        { ipv4_addr
        ; ipv4_port
        ; ipv6_addr
        ; ipv6_port
        ; cid = { CID.length = cid_length; id = cid }
        ; stateless_reset_token = token
        })
      (take cid_length)
      (take 16)

  let serialize
      f
      { ipv4_addr; ipv4_port; ipv6_addr; ipv6_port; cid; stateless_reset_token }
    =
    Faraday.write_string f ipv4_addr;
    Faraday.BE.write_uint16 f ipv4_port;
    Faraday.write_string f ipv6_addr;
    Faraday.BE.write_uint16 f ipv6_port;
    CID.serialize f cid;
    Faraday.write_string f stateless_reset_token
end

module Encoding = struct
  type t =
    | Original_destination_connection_id of CID.t
    | Max_idle_timeout of int
    | Stateless_reset_token of string
    | Max_udp_payload_size of int
    | Initial_max_data of int
    | Initial_max_stream_data_bidi_local of int
    | Initial_max_stream_data_bidi_remote of int
    | Initial_max_stream_data_uni of int
    | Initial_max_streams_bidi of int
    | Initial_max_streams_uni of int
    | Ack_delay_exponent of int
    | Max_ack_delay of int
    | Disable_active_migration of bool
    | Preferred_address of Preferred_address.t
    | Active_connection_id_limit of int
    | Initial_source_connection_id of CID.t
    | Retry_source_connection_id of CID.t

  let parse_transport_parameter type_ length =
    let open Angstrom in
    match type_ with
    | 0x00 ->
      lift
        (fun id -> Original_destination_connection_id { CID.length; id })
        (take length)
    | 0x01 ->
      lift
        (fun timeout -> Max_idle_timeout timeout)
        Parse.variable_length_integer
    | 0x02 ->
      (* From RFC<QUIC-RFC>§18.2:
       *   This parameter is a sequence of 16 bytes. *)
      assert (length = 16);
      lift (fun token -> Stateless_reset_token token) (take length)
    | 0x03 ->
      lift (fun max -> Max_udp_payload_size max) Parse.variable_length_integer
    | 0x04 ->
      lift (fun max -> Initial_max_data max) Parse.variable_length_integer
    | 0x05 ->
      lift
        (fun max -> Initial_max_stream_data_bidi_local max)
        Parse.variable_length_integer
    | 0x06 ->
      lift
        (fun max -> Initial_max_stream_data_bidi_remote max)
        Parse.variable_length_integer
    | 0x07 ->
      lift
        (fun max -> Initial_max_stream_data_uni max)
        Parse.variable_length_integer
    | 0x08 ->
      lift
        (fun max -> Initial_max_streams_bidi max)
        Parse.variable_length_integer
    | 0x09 ->
      lift
        (fun max -> Initial_max_streams_uni max)
        Parse.variable_length_integer
    | 0x0a ->
      lift
        (fun exponent -> Ack_delay_exponent exponent)
        Parse.variable_length_integer
    | 0x0b ->
      lift (fun max -> Max_ack_delay max) Parse.variable_length_integer
    | 0x0c ->
      (* From RFC<QUIC-RFC>§18.2:
       *   This parameter is a zero-length value. *)
      assert (length = 0);
      return (Disable_active_migration true)
    | 0x0d ->
      lift (fun addr -> Preferred_address addr) Preferred_address.parse
    | 0x0e ->
      lift
        (fun limit -> Active_connection_id_limit limit)
        Parse.variable_length_integer
    | 0x0f ->
      lift
        (fun id -> Initial_source_connection_id { CID.length; id })
        (take length)
    | 0x10 ->
      lift
        (fun id -> Retry_source_connection_id { CID.length; id })
        (take length)
    | _other ->
      fail "other"

  (* From RFC<QUIC-RFC>§18.1:
   *   Transport parameters with an identifier of the form 31 * N + 27 for
   *   integer values of N are reserved to exercise the requirement that unknown
   *   transport parameters be ignored. These transport parameters have no
   *   semantics, and may carry arbitrary values. *)
  let parser =
    let open Angstrom in
    let p =
      Parse.variable_length_integer >>= fun type_ ->
      Parse.variable_length_integer >>= fun length ->
      parse_transport_parameter type_ length
      >>| (fun x -> Some x)
      <|> lift (fun () -> None) (advance length)
    in
    many p >>| List.filter_map (fun x -> x)

  module Type = struct
    let serialize = function
      | Original_destination_connection_id _ ->
        0x00
      | Max_idle_timeout _ ->
        0x01
      | Stateless_reset_token _ ->
        0x02
      | Max_udp_payload_size _ ->
        0x03
      | Initial_max_data _ ->
        0x04
      | Initial_max_stream_data_bidi_local _ ->
        0x05
      | Initial_max_stream_data_bidi_remote _ ->
        0x06
      | Initial_max_stream_data_uni _ ->
        0x07
      | Initial_max_streams_bidi _ ->
        0x08
      | Initial_max_streams_uni _ ->
        0x09
      | Ack_delay_exponent _ ->
        0x0a
      | Max_ack_delay _ ->
        0x0b
      | Disable_active_migration _ ->
        0x0c
      | Preferred_address _ ->
        0x0d
      | Active_connection_id_limit _ ->
        0x0e
      | Initial_source_connection_id _ ->
        0x0f
      | Retry_source_connection_id _ ->
        0x10
  end

  let varint_encoding_length n =
    if n < 1 lsl 6 then
      1
    else if n < 1 lsl 14 then
      2
    else if n < 1 lsl 30 then
      4
    else
      8

  let serialize f t =
    let varint = Serialize.write_variable_length_integer f in
    varint (Type.serialize t);
    match t with
    | Original_destination_connection_id { CID.id; length } ->
      varint length;
      Faraday.write_string f id
    | Max_idle_timeout timeout ->
      varint (varint_encoding_length timeout);
      varint timeout
    | Stateless_reset_token token ->
      varint (String.length token);
      Faraday.write_string f token
    | Max_udp_payload_size max
    | Initial_max_data max
    | Initial_max_stream_data_bidi_local max
    | Initial_max_stream_data_bidi_remote max
    | Initial_max_stream_data_uni max
    | Initial_max_streams_bidi max
    | Initial_max_streams_uni max ->
      varint (varint_encoding_length max);
      varint max
    | Ack_delay_exponent exp ->
      varint (varint_encoding_length exp);
      varint exp
    | Max_ack_delay max ->
      varint (varint_encoding_length max);
      varint max
    | Disable_active_migration true ->
      (* From RFC<QUIC-RFC>§18.2:
       *   This parameter is a zero-length value. *)
      varint 0
    | Disable_active_migration false ->
      (* Don't include. *)
      assert false
    | Preferred_address addr ->
      varint (Preferred_address.serialized_length addr);
      Preferred_address.serialize f addr
    | Active_connection_id_limit max ->
      varint (varint_encoding_length max);
      varint max
    | Initial_source_connection_id { CID.id; length }
    | Retry_source_connection_id { CID.id; length } ->
      varint length;
      Faraday.write_string f id

  let serialize f = List.iter (serialize f)
end

type t =
  { (* From RFC<QUIC-RFC>§18.2:
     *   The value of the Destination Connection ID field from the first
     *   Initial packet sent by the client; see Section 7.3. This transport
     *   parameter is only sent by a server. *)
    original_destination_connection_id : CID.t option
  ; (* From RFC<QUIC-RFC>§18.2:
     *   The max idle timeout is a value in milliseconds that is encoded as an
     *   integer; see (Section 10.2). Idle timeout is disabled when both
     *   endpoints omit this transport parameter or specify a value of 0. *)
    max_idle_timeout : int
  ; (* From RFC<QUIC-RFC>§18.2:
     *   A stateless reset token is used in verifying a stateless reset; see
     *   Section 10.4. This parameter is a sequence of 16 bytes. This transport
     *   parameter MUST NOT be sent by a client, but MAY be sent by a server. A
     *   server that does not send this transport parameter cannot use
     *   stateless reset (Section 10.4) for the connection ID negotiated during
     *   the handshake. *)
    stateless_reset_token : string option
  ; (* From RFC<QUIC-RFC>§18.2:
     *   The maximum UDP payload size parameter is an integer value that limits
     *   the size of UDP payloads that the endpoint is willing to receive. *)
    max_udp_payload_size : int
  ; (* From RFC<QUIC-RFC>§18.2:
     *   The initial maximum data parameter is an integer value that contains
     *   the initial value for the maximum amount of data that can be sent on
     *   the connection. This is equivalent to sending a MAX_DATA (Section
     *   19.9) for the connection immediately after completing the handshake. *)
    initial_max_data : int
  ; (* From RFC<QUIC-RFC>§18.2:
     *   This parameter is an integer value specifying the initial flow control
     *   limit for locally-initiated bidirectional streams. This limit applies
     *   to newly created bidirectional streams opened by the endpoint that
     *   sends the transport parameter. *)
    initial_max_stream_data_bidi_local : int
  ; (* From RFC<QUIC-RFC>§18.2:
     *   This parameter is an integer value specifying the initial flow control
     *   limit for peer-initiated bidirectional streams. This limit applies to
     *   newly created bidirectional streams opened by the endpoint that
     *   receives the transport parameter. *)
    initial_max_stream_data_bidi_remote : int
  ; (* From RFC<QUIC-RFC>§18.2:
     *   This parameter is an integer value specifying the initial flow control
     *   limit for unidirectional streams. This limit applies to newly created
     *   unidirectional streams opened by the endpoint that receives the
     *   transport parameter. *)
    initial_max_stream_data_uni : int
  ; (* From RFC<QUIC-RFC>§18.2:
     *  The initial maximum bidirectional streams parameter is an integer value
     *  that contains the initial maximum number of bidirectional streams the
     *  peer may initiate. If this parameter is absent or zero, the peer cannot
     *  open bidirectional streams until a MAX_STREAMS frame is sent. Setting
     *  this parameter is equivalent to sending a MAX_STREAMS (Section 19.11)
     *  of the corresponding type with the same value. *)
    initial_max_streams_bidi : int
  ; (* From RFC<QUIC-RFC>§18.2:
     *   The initial maximum unidirectional streams parameter is an integer
     *   value that contains the initial maximum number of unidirectional
     *   streams the peer may initiate. If this parameter is absent or zero,
     *   the peer cannot open unidirectional streams until a MAX_STREAMS frame
     *   is sent. Setting this parameter is equivalent to sending a MAX_STREAMS
     *   (Section 19.11) of the corresponding type with the same value. *)
    initial_max_streams_uni : int
  ; (* From RFC<QUIC-RFC>§18.2:
     *   The ACK delay exponent is an integer value indicating an exponent used
     *   to decode the ACK Delay field in the ACK frame (Section 19.3). If this
     *   value is absent, a default value of 3 is assumed (indicating a
     *   multiplier of 8). Values above 20 are invalid. *)
    ack_delay_exponent : int
  ; (* From RFC<QUIC-RFC>§18.2:
     *   The maximum ACK delay is an integer value indicating the maximum
     *   amount of time in milliseconds by which the endpoint will delay
     *   sending acknowledgments. This value SHOULD include the receiver's
     *   expected delays in alarms firing. For example, if a receiver sets a
     *   timer for 5ms and alarms commonly fire up to 1ms late, then it should
     *   send a max_ack_delay of 6ms. If this value is absent, a default of 25
     *   milliseconds is assumed.  Values of 2^14 or greater are invalid. *)
    max_ack_delay : int
  ; (* From RFC<QUIC-RFC>§18.2:
     *   The disable active migration transport parameter is included if the
     *   endpoint does not support active connection migration (Section 9) on
     *   the address being used during the handshake. *)
    disable_active_migration : bool
  ; (* From RFC<QUIC-RFC>§18.2:
     *   The server's preferred address is used to effect a change in server
     *   address at the end of the handshake, as described in Section 9.6. *)
    preferred_address : Preferred_address.t option
  ; (* From RFC<QUIC-RFC>§18.2:
     *   The active connection ID limit is an integer value specifying the
     *   maximum number of connection IDs from the peer that an endpoint is
     *   willing to store. This value includes the connection ID received
     *   during the handshake, that received in the preferred_address transport
     *   parameter, and those received in NEW_CONNECTION_ID frames. *)
    active_connection_id_limit : int
  ; (* From RFC<QUIC-RFC>§18.2:
     *   The value that the endpoint included in the Source Connection ID field
     *   of the first Initial packet it sends for the connection; see Section
     *   7.3. *)
    initial_source_connection_id : CID.t option
  ; (* From RFC<QUIC-RFC>§18.2:
     *   The value that the server included in the Source Connection ID field
     *   of a Retry packet; see Section 7.3. This transport parameter is only
     *   sent by a server. *)
    retry_source_connection_id : CID.t option
  }

let default =
  { original_destination_connection_id = None
  ; (* From RFC<QUIC-RFC>§18.2:
     *   Idle timeout is disabled when both endpoints omit this transport
     *   parameter or specify a value of 0. *)
    max_idle_timeout = 0 (* 0 = disabled *)
  ; stateless_reset_token = None
  ; (* From RFC<QUIC-RFC>§18.2:
     *   The default for this parameter is the maximum permitted UDP payload of
     *   65527. Values below 1200 are invalid. *)
    max_udp_payload_size = 65527
  ; initial_max_data = -1
  ; initial_max_stream_data_bidi_local = -1
  ; initial_max_stream_data_bidi_remote = -1
  ; initial_max_stream_data_uni = -1
  ; initial_max_streams_bidi = -1
  ; initial_max_streams_uni = -1
  ; (* From RFC<QUIC-RFC>§18.2:
     *   If this value is absent, a default value of 3 is assumed (indicating a
     *   multiplier of 8). Values above 20 are invalid. *)
    ack_delay_exponent = 8 (* 2 ** 3 *)
  ; (* From RFC<QUIC-RFC>§18.2:
     *   If this value is absent, a default of 25 milliseconds is assumed.
     *   Values of 2^14 or greater are invalid. *)
    max_ack_delay = 25
  ; disable_active_migration = false
  ; preferred_address = None
  ; active_connection_id_limit = 2
  ; initial_source_connection_id = None
  ; retry_source_connection_id = None
  }

exception Local

let decode_and_validate ~(perspective : Crypto.mode) enc =
  let bs = Cstruct.to_bigarray enc in
  match Angstrom.parse_bigstring ~consume:All Encoding.parser bs with
  | Ok [] ->
    Ok default
  | Ok (_ :: _ as t) ->
    (* From RFC<QUIC-RFC>§7.4:
     *   An endpoint MUST NOT send a parameter more than once in a given
     *   transport parameters extension. An endpoint SHOULD treat receipt of
     *   duplicate transport parameters as a connection error of type
     *   TRANSPORT_PARAMETER_ERROR. *)
    (try
       let types = List.sort compare (List.map Encoding.Type.serialize t) in
       let (_ : int) =
         List.fold_left
           (fun prev cur -> if prev = cur then raise Local else cur)
           (List.hd types)
           (List.tl types)
       in
       Ok
         (List.fold_left
            (fun acc item ->
              match item with
              | Encoding.Original_destination_connection_id cid ->
                (match perspective with
                | Server ->
                  (* From RFC<QUIC-RFC>§18.2:
                   *   This transport parameter is only sent by a server. *)
                  raise Local
                | Client ->
                  { acc with original_destination_connection_id = Some cid })
              | Max_idle_timeout timeout ->
                { acc with max_idle_timeout = timeout }
              | Stateless_reset_token token ->
                (match perspective with
                | Server ->
                  (* From RFC<QUIC-RFC>§18.2:
                   *   This transport parameter MUST NOT be sent by a client,
                   *   but MAY be sent by a server. *)
                  raise Local
                | Client ->
                  { acc with stateless_reset_token = Some token })
              | Max_udp_payload_size max ->
                (* From RFC<QUIC-RFC>§18.2:
                 *   The default for this parameter is the maximum permitted
                 *   UDP payload of 65527. Values below 1200 are invalid. *)
                if max < 1200 || max > 65527 then
                  raise Local
                else
                  { acc with max_udp_payload_size = max }
              | Initial_max_data max ->
                { acc with initial_max_data = max }
              | Initial_max_stream_data_bidi_local max ->
                { acc with initial_max_stream_data_bidi_local = max }
              | Initial_max_stream_data_bidi_remote max ->
                { acc with initial_max_stream_data_bidi_remote = max }
              | Initial_max_stream_data_uni max ->
                { acc with initial_max_stream_data_uni = max }
              | Initial_max_streams_bidi max ->
                { acc with initial_max_streams_bidi = max }
              | Initial_max_streams_uni max ->
                { acc with initial_max_streams_uni = max }
              | Ack_delay_exponent exp ->
                (* From RFC<QUIC-RFC>§18.2:
                 *   Values above 20 are invalid. *)
                if exp > 20 then
                  raise Local
                else
                  { acc with
                    ack_delay_exponent = int_of_float (2. ** float_of_int exp)
                  }
              | Max_ack_delay max ->
                (* From RFC<QUIC-RFC>§18.2:
                 *   Values of 2^14 or greater are invalid. *)
                if max > 1 lsl 14 then
                  raise Local
                else
                  { acc with max_ack_delay = max }
              | Disable_active_migration disable_active_migration ->
                assert disable_active_migration;
                { acc with disable_active_migration }
              | Preferred_address addr ->
                (* TODO:
                 * From RFC<QUIC-RFC>§18.2:
                 *   A server that chooses a zero-length connection ID MUST NOT
                 *   provide a preferred address. Similarly, a server MUST NOT
                 *   include a zero-length connection ID in this transport
                 *   parameter. *)
                { acc with preferred_address = Some addr }
              | Active_connection_id_limit limit ->
                (* From RFC<QUIC-RFC>§18.2:
                 *   The value of the active_connection_id_limit parameter MUST
                 *   be at least 2. *)
                if limit < 2 then
                  raise Local
                else
                  { acc with active_connection_id_limit = limit }
              | Initial_source_connection_id cid ->
                { acc with initial_source_connection_id = Some cid }
              | Retry_source_connection_id cid ->
                (* From RFC<QUIC-RFC>§18.2:
                 *   This transport parameter is only sent by a server. *)
                match perspective with
                | Server ->
                  raise Local
                | Client ->
                  { acc with retry_source_connection_id = Some cid })
            default
            t)
     with
    | Local ->
      Error "invalid")
  | Error e ->
    Error e
