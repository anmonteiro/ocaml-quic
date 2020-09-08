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

module Direction = struct
  type t =
    | Unidirectional
    | Bidirectional
end

module Type = struct
  type t =
    (* From RFC<QUIC-RFC>§19.1:
     *   The PADDING frame (type=0x00) has no semantic value. PADDING frames
     *   can be used to increase the size of a packet. Padding can be used to
     *   increase an initial client packet to the minimum required size, or to
     *   provide protection against traffic analysis for protected packets. *)
    | Padding
    (* From RFC<QUIC-RFC>§19.1:
     *   Endpoints can use PING frames (type=0x01) to verify that their peers
     *   are still alive or to check reachability to the peer. *)
    | Ping
    (* From RFC<QUIC-RFC>§19.1:
     *   Receivers send ACK frames (types 0x02 and 0x03) to inform senders of
     *   packets they have received and processed. *)
    | Ack of { ecn_counts : bool }
    (* From RFC<QUIC-RFC>§19.1:
     *   An endpoint uses a RESET_STREAM frame (type=0x04) to abruptly
     *   terminate the sending part of a stream. *)
    | Reset_stream
    (* From RFC<QUIC-RFC>§19.1:
     *   An endpoint uses a STOP_SENDING frame (type=0x05) to communicate that
     *   incoming data is being discarded on receipt at application request.
     *   STOP_SENDING requests that a peer cease transmission on a stream. *)
    | Stop_sending
    (* From RFC<QUIC-RFC>§19.1:
     *   The CRYPTO frame (type=0x06) is used to transmit cryptographic
     *   handshake messages. It can be sent in all packet types except 0-RTT. *)
    | Crypto
    (* From RFC<QUIC-RFC>§19.1:
     *   A server sends a NEW_TOKEN frame (type=0x07) to provide the client
     *   with a token to send in the header of an Initial packet for a future
     *   connection. *)
    | New_token
    (* From RFC<QUIC-RFC>§19.1:
     *   STREAM frames implicitly create a stream and carry stream data. The
     *   STREAM frame takes the form 0b00001XXX (or the set of values from 0x08
     *   to 0x0f). The value of the three low-order bits of the frame type
     *   determines the fields that are present in the frame. *)
    | Stream of
        { off : bool
        ; len : bool
        ; fin : bool
        }
    (* From RFC<QUIC-RFC>§19.1:
     *   The MAX_DATA frame (type=0x10) is used in flow control to inform the
     *   peer of the maximum amount of data that can be sent on the connection
     *   as a whole. *)
    | Max_data
    (* From RFC<QUIC-RFC>§19.1:
     *   The MAX_STREAM_DATA frame (type=0x11) is used in flow control to
     *   inform a peer of the maximum amount of data that can be sent on a
     *   stream. *)
    | Max_stream_data
    (* From RFC<QUIC-RFC>§19.1:
     *   The MAX_STREAMS frames (type=0x12 and 0x13) inform the peer of the
     *   cumulative number of streams of a given type it is permitted to open.
     *   A MAX_STREAMS frame with a type of 0x12 applies to bidirectional
     *   streams, and a MAX_STREAMS frame with a type of 0x13 applies to
     *   unidirectional streams. *)
    | Max_streams of Direction.t
    (* From RFC<QUIC-RFC>§19.1:
     *   A sender SHOULD send a DATA_BLOCKED frame (type=0x14) when it wishes
     *   to send data, but is unable to due to connection-level flow control
     *   [...]. *)
    | Data_blocked
    (* From RFC<QUIC-RFC>§19.1:
     *   A sender SHOULD send a STREAM_DATA_BLOCKED frame (type=0x15) when it
     *   wishes to send data, but is unable to due to stream-level flow
     *   control. This frame is analogous to DATA_BLOCKED (Section 19.12). *)
    | Stream_data_blocked
    (* From RFC<QUIC-RFC>§19.1:
     *   A sender SHOULD send a STREAMS_BLOCKED frame (type=0x16 or 0x17) when
     *   it wishes to open a stream, but is unable to due to the maximum stream
     *   limit set by its peer; see Section 19.11. A STREAMS_BLOCKED frame of
     *   type 0x16 is used to indicate reaching the bidirectional stream limit,
     *   and a STREAMS_BLOCKED frame of type 0x17 indicates reaching the
     *   unidirectional stream limit. *)
    | Streams_blocked of Direction.t
    (* From RFC<QUIC-RFC>§19.1:
     *   An endpoint sends a NEW_CONNECTION_ID frame (type=0x18) to provide its
     *   peer with alternative connection IDs that can be used to break
     *   linkability when migrating connections [...]. *)
    | New_connection_id
    (* From RFC<QUIC-RFC>§19.1:
     *   An endpoint sends a RETIRE_CONNECTION_ID frame (type=0x19) to indicate
     *   that it will no longer use a connection ID that was issued by its
     *   peer. *)
    | Retire_connection_id
    (* From RFC<QUIC-RFC>§19.1:
     *   Endpoints can use PATH_CHALLENGE frames (type=0x1a) to check
     *   reachability to the peer and for path validation during connection
     *   migration. *)
    | Path_challenge
    (* From RFC<QUIC-RFC>§19.1:
     *   The PATH_RESPONSE frame (type=0x1b) is sent in response to a
     *   PATH_CHALLENGE frame. *)
    | Path_response
    (* From RFC<QUIC-RFC>§19.1:
     *   An endpoint sends a CONNECTION_CLOSE frame (type=0x1c or 0x1d) to
     *   notify its peer that the connection is being closed. The
     *   CONNECTION_CLOSE with a frame type of 0x1c is used to signal errors at
     *   only the QUIC layer, or the absence of errors (with the NO_ERROR
     *   code). *)
    | Connection_close_quic
    (* From RFC<QUIC-RFC>§19.1:
     *   An endpoint sends a CONNECTION_CLOSE frame (type=0x1c or 0x1d) to
     *   notify its peer that the connection is being closed. [...] The
     *   CONNECTION_CLOSE frame with a type of 0x1d is used to signal an error
     *   with the application that uses QUIC.*)
    | Connection_close_app
    (* From RFC<QUIC-RFC>§19.1:
     *   The server uses the HANDSHAKE_DONE frame (type=0x1e) to signal
     *   confirmation of the handshake to the client. *)
    | Handshake_done
    | Unknown of int

  let serialize = function
    | Padding ->
      0x00
    | Ping ->
      0x01
    | Ack { ecn_counts } ->
      if ecn_counts then 0x03 else 0x02
    | Reset_stream ->
      0x04
    | Stop_sending ->
      0x05
    | Crypto ->
      0x06
    | New_token ->
      0x07
    | Stream { off; len; fin } ->
      let base = 0x08 in
      let with_off = if off then base + 0x04 else base in
      let with_len = if len then with_off + 0x02 else with_off in
      let with_fin = if fin then with_len + 0x01 else with_len in
      with_fin
    | Max_data ->
      0x10
    | Max_stream_data ->
      0x11
    | Max_streams Bidirectional ->
      0x12
    | Max_streams Unidirectional ->
      0x13
    | Data_blocked ->
      0x14
    | Stream_data_blocked ->
      0x15
    | Streams_blocked Bidirectional ->
      0x16
    | Streams_blocked Unidirectional ->
      0x17
    | New_connection_id ->
      0x18
    | Retire_connection_id ->
      0x19
    | Path_challenge ->
      0x1A
    | Path_response ->
      0x1B
    | Connection_close_quic ->
      0x1c
    | Connection_close_app ->
      0x1d
    | Handshake_done ->
      0x1e
    | Unknown x ->
      x

  let parse = function
    | 0x00 ->
      Padding
    | 0x01 ->
      Ping
    | 0x02 ->
      Ack { ecn_counts = false }
    | 0x03 ->
      Ack { ecn_counts = true }
    | 0x04 ->
      Reset_stream
    | 0x05 ->
      Stop_sending
    | 0x06 ->
      Crypto
    | 0x07 ->
      New_token
    | x when x >= 0x08 && x <= 0x0f ->
      Stream { off = Bits.test x 2; len = Bits.test x 1; fin = Bits.test x 0 }
    | 0x10 ->
      Max_data
    | 0x11 ->
      Max_stream_data
    | 0x12 ->
      Max_streams Bidirectional
    | 0x13 ->
      Max_streams Unidirectional
    | 0x14 ->
      Data_blocked
    | 0x15 ->
      Stream_data_blocked
    | 0x16 ->
      Streams_blocked Bidirectional
    | 0x17 ->
      Streams_blocked Unidirectional
    | 0x18 ->
      New_connection_id
    | 0x19 ->
      Retire_connection_id
    | 0x1A ->
      Path_challenge
    | 0x1B ->
      Path_response
    | 0x1c ->
      Connection_close_quic
    | 0x1d ->
      Connection_close_app
    | 0x1e ->
      Handshake_done
    | x ->
      Unknown x
end

module Range = struct
  (* From RFC<QUIC-RFC>§19.3.1:
   *   An ACK Range acknowledges all packets between the smallest packet number
   *   and the largest, inclusive. *)
  type t =
    { first : int64
    ; last : int64
    }
end

type t =
  | Padding of int
  | Ping
  | Ack of
      { delay : int
      ; ranges : Range.t list
      ; ecn_counts : (int * int * int) option
      }
  | Reset_stream of
      { stream_id : int
      ; application_protocol_error : int
      ; final_size : int
      }
  | Stop_sending of
      { stream_id : int
      ; application_protocol_error : int
      }
  | Crypto of Ordered_stream.fragment
  | New_token of
      { length : int
      ; data : Bigstringaf.t
      }
  | Stream of
      { id : int
      ; fragment : Ordered_stream.fragment
      ; is_fin : bool
      }
  | Max_data of int
  | Max_stream_data of
      { stream_id : int
      ; max_data : int
      }
  | Max_streams of Direction.t * int
  | Data_blocked of int
  | Stream_data_blocked of
      { stream_id : int
      ; max_data : int
      }
  | Streams_blocked of Direction.t * int
  | New_connection_id of
      { cid : CID.t
      ; stateless_reset_token : string
      ; retire_prior_to : int
      ; sequence_no : int
      }
  | Retire_connection_id of int
  | Path_challenge of Bigstringaf.t
  | Path_response of Bigstringaf.t
  | Connection_close_quic of
      { frame_type : Type.t
      ; reason_phrase : string
      ; error_code : int
      }
  | Connection_close_app of
      { reason_phrase : string
      ; error_code : int
      }
  | Handshake_done
  | Unknown of int

let to_frame_type = function
  | Padding _ ->
    Type.Padding
  | Ping ->
    Ping
  | Ack { ecn_counts; _ } ->
    Ack { ecn_counts = Option.is_some ecn_counts }
  | Reset_stream _ ->
    Reset_stream
  | Stop_sending _ ->
    Stop_sending
  | Crypto _ ->
    Crypto
  | New_token _ ->
    New_token
  | Stream { fragment = { IOVec.len; off; _ }; is_fin; _ } ->
    Stream { off = off <> 0; len = len <> 0; fin = is_fin }
  | Max_data _ ->
    Max_data
  | Max_stream_data _ ->
    Max_stream_data
  | Max_streams (direction, _) ->
    Max_streams direction
  | Data_blocked _ ->
    Data_blocked
  | Stream_data_blocked _ ->
    Stream_data_blocked
  | Streams_blocked (direction, _) ->
    Streams_blocked direction
  | New_connection_id _ ->
    New_connection_id
  | Retire_connection_id _ ->
    Retire_connection_id
  | Path_challenge _ ->
    Path_challenge
  | Path_response _ ->
    Path_response
  | Connection_close_quic _ ->
    Connection_close_quic
  | Connection_close_app _ ->
    Connection_close_app
  | Handshake_done ->
    Handshake_done
  | Unknown x ->
    Unknown x

(* From RFC<QUIC-RFC>§1.2:
 *   Ack-eliciting Packet: A QUIC packet that contains frames other than ACK,
 *                         PADDING, and CONNECTION_CLOSE. *)
let is_ack_eliciting = function
  | Ack _ | Padding _ | Connection_close_quic _ | Connection_close_app _ ->
    false
  | _all_other ->
    true

let is_any_ack_eliciting frames = List.exists is_ack_eliciting frames
