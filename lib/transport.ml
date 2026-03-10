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

module Reader = Fast_parse.Reader
module Writer = Serialize.Writer

module Packet_number = struct
  let max_ack_ranges = 32
  let ack_history_window = 4096L

  type t =
    { mutable sent : int64
    ; mutable received : int64
    ; mutable received_need_ack : Frame.Range.t list
    ; mutable ack_elicited : bool
    }

  let create () =
    { sent = -1L
    ; received = -1L
    ; received_need_ack = []
    ; ack_elicited = false
    }

  let send_next t =
    let next = Int64.add t.sent 1L in
    t.sent <- next;
    next

  let prune_ranges ~cutoff ranges =
    let rec aux acc = function
      | [] -> List.rev acc
      | ({ Frame.Range.first; last } as range) :: rest ->
        if Int64.compare last cutoff < 0
        then List.rev acc
        else if Int64.compare first cutoff < 0
        then List.rev ({ range with first = cutoff } :: acc)
        else aux (range :: acc) rest
    in
    aux [] ranges

  let merge_following_ranges range ranges =
    let rec aux range = function
      | ({ Frame.Range.first; last; _ } as next) :: rest
        when Int64.compare (Int64.add last 1L) range.Frame.Range.first >= 0 ->
        let merged =
          { Frame.Range.first = min range.Frame.Range.first first
          ; last = max range.Frame.Range.last next.last
          }
        in
        aux merged rest
      | rest -> range, rest
    in
    aux range ranges

  let insert_for_acking t packet_number =
    let cutoff = Int64.sub packet_number ack_history_window in
    let pruned = prune_ranges ~cutoff t.received_need_ack in
    let rec insert acc = function
      | [] ->
        List.rev
          ({ Frame.Range.first = packet_number; last = packet_number } :: acc)
      | ({ Frame.Range.first; last; _ } as range) :: rest ->
        if Int64.compare packet_number (Int64.add last 1L) > 0
        then
          List.rev_append
            acc
            ({ Frame.Range.first = packet_number; last = packet_number }
             :: range
             :: rest)
        else if Int64.compare packet_number (Int64.sub first 1L) >= 0
        then (
          let merged =
            { Frame.Range.first = min first packet_number
            ; last = max last packet_number
            }
          in
          let merged, rest = merge_following_ranges merged rest in
          List.rev_append acc (merged :: rest))
        else insert (range :: acc) rest
    in
    t.received_need_ack <- insert [] pruned

  let rec take n acc = function
    | _ when n <= 0 -> List.rev acc
    | [] -> List.rev acc
    | x :: xs -> take (n - 1) (x :: acc) xs

  let compose_ranges t = take max_ack_ranges [] t.received_need_ack

  let compose_ack_frame t =
    let ranges = compose_ranges t in
    Frame.Ack { delay = 0; ranges; ecn_counts = None }
end

type error_handler = int -> unit
type on_error_handler = { on_error : error_handler }
type start_stream = ?error_handler:error_handler -> Direction.t -> Stream.t
type stream_handler = F of (Stream.t -> on_error_handler)

module Connection = struct
  type handler =
    | Uninitialized of
        (cid:string -> start_stream:start_stream -> stream_handler)
    | Initialized of stream_handler

  type t =
    { encdec : Crypto.encdec Encryption_level.t
    ; mode : Crypto.Mode.t
    ; mutable tls_state : Qtls.t
    ; packet_number_spaces : Packet_number.t Spaces.t
    ; source_cid : CID.t
    ; mutable original_dest_cid : CID.t
    ; mutable dest_cid : CID.t
    ; (* From RFC9000§19.6:
       *   There is a separate flow of cryptographic handshake data in each
       *   encryption level, each of which starts at an offset of 0. This implies
       *   that each encryption level is treated as a separate CRYPTO stream of
       *   data. *)
      crypto_streams : Stream.t Spaces.t
    ; mutable peer_address : string
    ; mutable peer_transport_params : Transport_parameters.t
    ; local_initial_max_data : int64
    ; local_initial_max_stream_data_bidi_local : int64
    ; local_initial_max_stream_data_bidi_remote : int64
    ; local_initial_max_stream_data_uni : int64
    ; local_initial_max_streams_bidi : int64
    ; local_initial_max_streams_uni : int64
    ; mutable max_recv_data : int64
    ; recv_stream_max_data : (Stream_id.t, int64) Hashtbl.t
    ; mutable recv_data_bytes : int64
    ; recv_stream_highest_offsets : (Stream_id.t, int64) Hashtbl.t
    ; mutable consumed_data_bytes : int64
    ; recv_stream_consumed_offsets : (Stream_id.t, int64) Hashtbl.t
    ; mutable peer_max_data : int64
    ; peer_stream_max_data : (Stream_id.t, int64) Hashtbl.t
    ; mutable sent_data_bytes : int64
    ; sent_stream_highest_offsets : (Stream_id.t, int64) Hashtbl.t
    ; recovery : Recovery.t
    ; queued_packets : (Writer.header_info * Frame.t list) Queue.t
    ; writer : Writer.t
    ; streams : (Stream_id.t, Stream.t) Hashtbl.t
    ; mutable handler : handler
    ; start_stream : start_stream
    ; wakeup_writer : unit -> unit
    ; shutdown : t -> unit
    ; mutable next_unidirectional_stream_id : Stream_id.t
    ; mutable did_send_connection_close : bool
    ; (* TODO: should be retry or initial? *)
      mutable processed_retry_packet : bool
    ; mutable token_value : string
    ; now_ms : unit -> int64
    }

  let invoke_handler t ~cid ~start_stream stream =
    let stream_handler =
      match t.handler with
      | Uninitialized f ->
        let (F stream_handler as handler_f) = f ~cid ~start_stream in
        t.handler <- Initialized handler_f;
        stream_handler
      | Initialized (F stream_handler) -> stream_handler
    in
    stream_handler stream

  let initialize_handler t ~cid ~start_stream =
    match t.handler with
    | Uninitialized f ->
      let (F _ as handler_f : stream_handler) = f ~cid ~start_stream in
      t.handler <- Initialized handler_f
    | Initialized _ -> ()

  type packet_info =
    { packet_number : int64
    ; header : Packet.Header.t
    ; outgoing_frames : Frame.t list Encryption_level.t
    ; encryption_level : Encryption_level.level
    ; connection : t
    }

  module Table = Hashtbl.MakeSeeded (struct
      type t = CID.t

      let equal = CID.equal
      let hash i k = Hashtbl.seeded_hash i k
      let[@warning "-32"] seeded_hash = hash
    end)

  let wakeup_writer t = t.wakeup_writer ()
  let next_recovery_time_ms t = t.now_ms ()

  let packet_is_in_flight frames =
    Frame.is_any_ack_eliciting frames
    || List.exists (function Frame.Padding _ -> true | _ -> false) frames

  let estimated_in_flight_bytes frames =
    if packet_is_in_flight frames
    then Recovery.Constants.default_max_datagram_size
    else 0

  let writer_pending_bytes writer =
    Faraday.pending_bytes (Writer.faraday writer)

  let on_packet_sent t ~encryption_level ~packet_number ~bytes_sent frames =
    let time_sent_ms = next_recovery_time_ms t in
    Recovery.Debug.record_packet_sent
      t.recovery
      ~encryption_level
      ~packet_number
      ~bytes_sent
      ~time_sent_ms
      frames

  type flush_ret =
    | Didnt_write
    | Wrote
    | Wrote_app_data

  (* Flushes packets into one datagram *)
  let _flush_pending_packets t =
    let rec inner t acc =
      match Queue.peek_opt t.queued_packets with
      | Some
          ( ({ Writer.encryption_level; packet_number; _ } as header_info)
          , frames ) ->
        let estimated_bytes = estimated_in_flight_bytes frames in
        if
          estimated_bytes > 0
          && not (Recovery.can_send t.recovery ~bytes:estimated_bytes)
        then acc
        else (
          ignore
            (Queue.take t.queued_packets : Writer.header_info * Frame.t list);
          let bytes_before = writer_pending_bytes t.writer in
          Writer.write_frames_packet t.writer ~header_info frames;
          let bytes_sent = writer_pending_bytes t.writer - bytes_before in
          on_packet_sent t ~encryption_level ~packet_number ~bytes_sent frames;
          let can_be_followed_by_other_packets =
            encryption_level <> Application_data
          in
          if can_be_followed_by_other_packets
          then inner t Wrote
          else Wrote_app_data)
      | None -> acc
    in
    inner t Didnt_write

  let shutdown_writer t =
    Writer.close t.writer;
    wakeup_writer t

  let shutdown t =
    let shutdown () =
      shutdown_writer t;
      t.shutdown t
    in
    match _flush_pending_packets t with
    | Wrote | Wrote_app_data -> Writer.flush t.writer shutdown
    | Didnt_write ->
      (* TODO: might wanna call Stream.close_reader on all readable streams? *)
      shutdown ()

  let send_frames t ?(encryption_level = t.encdec.current) frames =
    let packet_number =
      Packet_number.send_next
        (Spaces.of_encryption_level t.packet_number_spaces encryption_level)
    in
    let { Crypto.encrypter; _ } =
      Encryption_level.find_exn encryption_level t.encdec
    in
    let header_info =
      Writer.make_header_info
        ~encrypter
        ~packet_number
        ~encryption_level
        ~source_cid:t.source_cid
        ~token:t.token_value
        t.dest_cid
    in
    Queue.add (header_info, frames) t.queued_packets

  let process_ack_frame t ~packet_info ~delay ~ranges =
    let { encryption_level; _ } = packet_info in
    let ack_delay_ms =
      if encryption_level <> Application_data
      then 0L
      else
        let ack_delay_multiplier_us =
          Int64.of_int (max 1 t.peer_transport_params.ack_delay_exponent)
        in
        let ack_delay_us =
          Int64.mul (Int64.of_int delay) ack_delay_multiplier_us
        in
        Int64.div ack_delay_us 1000L
    in
    Recovery.Debug.record_ack_received
      t.recovery
      ~encryption_level
      ~ranges
      ~ack_delay_ms
      ~now_ms:(next_recovery_time_ms t);
    Recovery.drain_lost t.recovery ~encryption_level
    |> List.iter (fun frames -> send_frames t ~encryption_level frames);
    ()

  let report_error ?frame_type ?encryption_level t error =
    if not t.did_send_connection_close
    then (
      Queue.clear t.queued_packets;
      send_frames
        t
        ?encryption_level
        [ Frame.Connection_close_quic
            { frame_type = Option.value ~default:Frame.Type.Padding frame_type
            ; reason_phrase = ""
            ; error_code = error
            }
        ];
      t.did_send_connection_close <- true;
      shutdown t;
      wakeup_writer t)

  let report_application_error t error_code =
    if not t.did_send_connection_close
    then (
      Queue.clear t.queued_packets;
      send_frames
        t
        [ Frame.Connection_close_app { reason_phrase = ""; error_code } ];
      t.did_send_connection_close <- true;
      shutdown t;
      wakeup_writer t)

  let report_tls_failure t failure =
    let _level, alert = Tls.Engine.alert_of_failure failure in
    report_error
      t
      ~frame_type:Frame.Type.Crypto
      (Crypto_error (Tls.Packet.alert_type_to_int alert))

  let apply_peer_transport_params t transport_params =
    t.peer_transport_params <- transport_params;
    t.peer_max_data <-
      (if transport_params.initial_max_data < 0
       then 0L
       else Int64.of_int transport_params.initial_max_data)

  let process_reset_stream_frame
        t
        ~stream_id
        ~final_size:_fsiz
        application_error
    =
    let is_locally_initiated =
      match t.mode with
      | Server -> Stream_id.is_server_initiated stream_id
      | Client -> Stream_id.is_client_initiated stream_id
    in
    let is_send_only_stream =
      Stream_id.is_uni stream_id && is_locally_initiated
    in
    if is_send_only_stream
    then report_error t ~frame_type:Reset_stream Stream_state_error
    else
      match Hashtbl.find_opt t.streams stream_id with
      | Some stream ->
        (match stream.typ, t.mode with
        | Client Unidirectional, Client | Server Unidirectional, Server ->
          (* From RFC9000§19.4:
           *   An endpoint that receives a RESET_STREAM frame for a send-only
           *   stream MUST terminate the connection with error
           *   STREAM_STATE_ERROR.
           *)
          report_error t ~frame_type:Reset_stream Stream_state_error
        | _, _ ->
          (* TODO: stream state transitions 3.1 / 3.2 *)
          stream.error_handler application_error;

          Hashtbl.remove t.streams stream_id)
      | None -> ()

  (* TODO: Receiving a STOP_SENDING frame for a locally initiated stream that *)
  (* has not yet been created MUST be treated as a connection error of type *)
  (* STREAM_STATE_ERROR. *)
  let process_stop_sending_frame t ~stream_id application_protocol_error =
    let is_locally_initiated =
      match t.mode with
      | Server -> Stream_id.is_server_initiated stream_id
      | Client -> Stream_id.is_client_initiated stream_id
    in
    let is_receive_only_stream =
      Stream_id.is_uni stream_id && not is_locally_initiated
    in
    if is_receive_only_stream
    then
      report_error
        t
        ~frame_type:Frame.Type.Stop_sending
        Error.Stream_state_error
    else
      match Hashtbl.find_opt t.streams stream_id with
      | Some stream ->
        (match stream.typ, t.mode with
        | Client Unidirectional, Server | Server Unidirectional, Client ->
          (* From RFC9000§19.5:
           *   An endpoint that receives a STOP_SENDING frame for a receive-only
           *   stream MUST terminate the connection with error
           *   STREAM_STATE_ERROR.
           *)
          report_error
            t
            ~frame_type:Frame.Type.Reset_stream
            Error.Stream_state_error
        | _ ->
          (* A STOP_SENDING frame requests that the receiving endpoint send a
             RESET_STREAM frame. An endpoint that receives a STOP_SENDING frame
             MUST send a RESET_STREAM frame if the stream is in the "Ready" or
             "Send" state. *)
          let final_size = Stream.Send.final_size stream.send in
          send_frames
            t
            [ Frame.Reset_stream
                { stream_id
                ; (* From RFC9000§19.5:
                   *   An endpoint SHOULD copy the error code from the
                   *   STOP_SENDING frame to the RESET_STREAM frame it sends, but
                   *   it can use any application error code. *)
                  application_protocol_error
                ; final_size
                }
            ])
      | None ->
        if is_locally_initiated
        then
          report_error
            t
            ~frame_type:Frame.Type.Stop_sending
            Error.Stream_state_error
        else ()

  let process_tls_result t ~new_tls_state ~tls_packets =
    let drop_initial_and_handshake_keys t =
      Encryption_level.remove Initial t.encdec;
      Encryption_level.remove Handshake t.encdec;
      Recovery.discard_space t.recovery ~encryption_level:Initial;
      Recovery.discard_space t.recovery ~encryption_level:Handshake
    in
    let report_unexpected_tls_message () =
      report_error
        t
        ~frame_type:Frame.Type.Crypto
        (Crypto_error
           (Tls.Packet.alert_type_to_int Tls.Packet.UNEXPECTED_MESSAGE))
    in
    let rec process_packets
              cur_encryption_level
              (packets : Qtls.State.rec_resp list)
      =
      match packets with
      | (`Change_enc _ :: _ | `Change_dec _ :: _)
        when cur_encryption_level = Encryption_level.Application_data
             && not (Tls.Engine.handshake_in_progress t.tls_state) ->
        report_unexpected_tls_message ();
        cur_encryption_level
      | `Change_enc enc :: `Change_dec dec :: xs
      | `Change_dec dec :: `Change_enc enc :: xs ->
        if cur_encryption_level = Encryption_level.Application_data
        then (
          report_unexpected_tls_message ();
          cur_encryption_level)
        else
          let current_cipher = Qtls.current_cipher new_tls_state in
          let next = Encryption_level.next cur_encryption_level in
          t.encdec.current <- next;
          Encryption_level.add
            next
            { Crypto.encrypter =
                Crypto.AEAD.make ~ciphersuite:current_cipher enc.traffic_secret
            ; decrypter =
                Some
                  (Crypto.AEAD.make
                     ~ciphersuite:current_cipher
                     dec.traffic_secret)
            }
            t.encdec;
          process_packets next xs
      | `Change_enc enc :: xs ->
        if cur_encryption_level = Encryption_level.Application_data
        then (
          report_unexpected_tls_message ();
          cur_encryption_level)
        else
          let current_cipher = Qtls.current_cipher new_tls_state in
          let next = Encryption_level.next cur_encryption_level in
          t.encdec.current <- next;
          Encryption_level.add
            next
            { Crypto.encrypter =
                Crypto.AEAD.make ~ciphersuite:current_cipher enc.traffic_secret
            ; decrypter = None
            }
            t.encdec;
          process_packets next xs
      | `Change_dec dec :: xs ->
        let current_cipher = Qtls.current_cipher new_tls_state in
        Encryption_level.update_current
          (function
            | None -> assert false
            | Some encdec ->
              Some
                { encdec with
                  Crypto.decrypter =
                    Some
                      (Crypto.AEAD.make
                         ~ciphersuite:current_cipher
                         dec.traffic_secret)
                })
          t.encdec;
        process_packets cur_encryption_level xs
      | `Record ((ct : Tls.Packet.content_type), cs) :: xs ->
        assert (ct = HANDSHAKE);
        let crypto_stream =
          Spaces.of_encryption_level t.crypto_streams cur_encryption_level
        in
        let _fragment =
          Stream.Send.push
            (Bigstringaf.of_string ~off:0 ~len:(String.length cs) cs)
            crypto_stream.send
        in
        (* Encryption_level.update_exn *)
        (* cur_encryption_level *)
        (* (fun xs -> Some (Frame.Crypto fragment :: xs)) *)
        (* outgoing_frames; *)
        process_packets cur_encryption_level xs
      | [] -> cur_encryption_level
    in
    let _next_enc : Encryption_level.level =
      process_packets t.encdec.current tls_packets
    in
    let is_handshake_done =
      Tls.Engine.handshake_in_progress t.tls_state
      && not (Tls.Engine.handshake_in_progress new_tls_state)
    in
    if is_handshake_done && t.mode = Server
    then (
      (* send the HANDSHAKE_DONE frame if we just completed the handshake.
       *
       * From RFC9000§7.3:
       *   The server uses the HANDSHAKE_DONE frame (type=0x1e) to signal
       *   confirmation of the handshake to the client. *)
      assert (t.encdec.current = Application_data);
      send_frames t [ Frame.Handshake_done ];
      (* From RFC9001§4.9.2:
       *   "An endpoint MUST discard its Handshake keys when the TLS handshake
       *   is confirmed" (and Initial keys at the same time). Per RFC9001§4.1.2,
       *   servers confirm when the handshake completes.
       *)
      drop_initial_and_handshake_keys t);
    t.tls_state <- new_tls_state

  let rec exhaust_crypto_stream t ~packet_info ~(stream : Stream.t) =
    let { encryption_level; _ } = packet_info in
    match Stream.Recv.pop stream.recv with
    | Some { buffer; _ } ->
      let fragment_cstruct = Bigstringaf.to_string buffer in
      (match t.tls_state.handshake.machina with
      | Server Tls.State.AwaitClientHello | Server13 AwaitClientHelloHRR13 ->
        if encryption_level <> Initial
        then ()
        else (
          match
            Qtls.handle_raw_record
              ~embed_quic_transport_params:(fun _raw_transport_params ->
                (* From RFC9000§7.3:
                 *   When the handshake does not include a Retry (Figure 6), the
                 *   server sets original_destination_connection_id to S1 and
                 *   initial_source_connection_id to S3. In this case, the server
                 *   does not include a retry_source_connection_id transport
                 *   parameter. *)
                Some
                  Transport_parameters.(
                    encode
                      [ Encoding.Original_destination_connection_id
                          t.original_dest_cid
                      ; Initial_source_connection_id t.source_cid
                      ; Initial_max_data (Int64.to_int t.local_initial_max_data)
                      ; Initial_max_stream_data_bidi_local
                          (Int64.to_int
                             t.local_initial_max_stream_data_bidi_local)
                      ; Initial_max_stream_data_bidi_remote
                          (Int64.to_int
                             t.local_initial_max_stream_data_bidi_remote)
                      ; Initial_max_stream_data_uni
                          (Int64.to_int t.local_initial_max_stream_data_uni)
                      ; Initial_max_streams_bidi
                          (Int64.to_int t.local_initial_max_streams_bidi)
                      ; Initial_max_streams_uni
                          (Int64.to_int t.local_initial_max_streams_uni)
                      ]))
              t.tls_state
              fragment_cstruct
          with
          | Error e -> report_tls_failure t e
          | Ok (tls_state', tls_packets, (None | Some _)) ->
            (* TODO: send alerts as quic error *)
            (match tls_packets with
            | [] -> t.tls_state <- tls_state'
            | tls_packets ->
              (match Qtls.transport_params tls_state' with
              | Some quic_transport_params ->
                (match
                   Transport_parameters.decode_and_validate
                     ~perspective:Server
                     quic_transport_params
                 with
                | Ok transport_params ->
                  apply_peer_transport_params t transport_params;
                  t.recovery.rtt.max_ack_delay_ms <-
                    Int64.of_int transport_params.max_ack_delay;
                  process_tls_result t ~new_tls_state:tls_state' ~tls_packets
                | Error e -> report_error t ~frame_type:Crypto e)
              | None -> report_error t ~frame_type:Crypto (Crypto_error 0x6d))))
      | Server13
          ( AwaitClientCertificate13 _ | AwaitClientCertificateVerify13 _
          | AwaitClientFinished13 _ ) ->
        if encryption_level <> Handshake
        then ()
        else (
          match Qtls.handle_raw_record t.tls_state fragment_cstruct with
          | Error e -> report_tls_failure t e
          | Ok (tls_state', tls_packets, (None | Some _)) ->
            (* TODO: send alerts as quic error *)
            process_tls_result t ~new_tls_state:tls_state' ~tls_packets)
      | Server13 Established13 ->
        report_error
          t
          ~frame_type:Crypto
          (Crypto_error
             (Tls.Packet.alert_type_to_int Tls.Packet.UNEXPECTED_MESSAGE))
      | Server Established -> report_error t ~frame_type:Crypto Internal_error
      | Client (AwaitServerHello (_, _, _)) ->
        if encryption_level <> Initial
        then ()
        else (
          match Qtls.handle_raw_record t.tls_state fragment_cstruct with
          | Error e -> report_tls_failure t e
          | Ok (tls_state', tls_packets, (None | Some _)) ->
            (* TODO: send alerts as quic error *)
            process_tls_result t ~new_tls_state:tls_state' ~tls_packets)
      | Client13
          ( AwaitServerEncryptedExtensions13 _
          | AwaitServerCertificateRequestOrCertificate13 _
          | AwaitServerCertificate13 _ | AwaitServerCertificateVerify13 _
          | AwaitServerFinished13 _ ) ->
        if encryption_level <> Handshake
        then ()
        else (
          match Qtls.handle_raw_record t.tls_state fragment_cstruct with
          | Error e -> report_tls_failure t e
          | Ok (tls_state', tls_packets, (None | Some _)) ->
            (* TODO: send alerts as quic error *)
            process_tls_result t ~new_tls_state:tls_state' ~tls_packets)
      | Client13 (AwaitServerHello13 _) ->
        if encryption_level <> Initial
        then ()
        else (
          match Qtls.handle_raw_record t.tls_state fragment_cstruct with
          | Error e -> report_tls_failure t e
          | Ok (tls_state', tls_packets, (None | Some _)) ->
            process_tls_result t ~new_tls_state:tls_state' ~tls_packets)
      | Client _ | Client13 _ -> ()
      | Server _ | Server13 _ -> ());
      exhaust_crypto_stream t ~packet_info ~stream
    | None -> ()

  let process_crypto_frame t ~packet_info fragment =
    let { encryption_level; _ } = packet_info in
    let crypto_stream =
      Spaces.of_encryption_level t.crypto_streams encryption_level
    in
    (* From RFC9000§19.6:
     *   The stream does not have an explicit end, so CRYPTO frames do not have a
     *   FIN bit. *)
    Stream.Recv.push fragment ~is_fin:false crypto_stream.recv;
    exhaust_crypto_stream t ~packet_info ~stream:crypto_stream

  let rec process_stream_data t ~stream =
    match Stream.Recv.pop stream with
    | Some _ -> process_stream_data t ~stream
    | None -> ()

  let int64_of_nonnegative n = if n < 0 then 0L else Int64.of_int n

  let int_of_int64_clamped n =
    if Int64.compare n 0L <= 0
    then 0
    else if Int64.compare n (Int64.of_int max_int) >= 0
    then max_int
    else Int64.to_int n

  let is_locally_initiated t stream_id =
    match t.mode with
    | Server -> Stream_id.is_server_initiated stream_id
    | Client -> Stream_id.is_client_initiated stream_id

  let local_stream_recv_window t stream_id =
    let direction = Direction.classify stream_id in
    let locally_initiated = is_locally_initiated t stream_id in
    match direction with
    | Unidirectional ->
      if locally_initiated then None else Some t.local_initial_max_stream_data_uni
    | Bidirectional ->
      if locally_initiated
      then Some t.local_initial_max_stream_data_bidi_local
      else Some t.local_initial_max_stream_data_bidi_remote

  let current_recv_stream_max_data t stream_id =
    match local_stream_recv_window t stream_id with
    | None -> None
    | Some initial ->
      Some
        (Hashtbl.find_opt t.recv_stream_max_data stream_id
         |> Option.value ~default:initial)

  let peer_stream_send_window t stream_id =
    let direction = Direction.classify stream_id in
    let locally_initiated = is_locally_initiated t stream_id in
    match direction with
    | Unidirectional ->
      if locally_initiated
      then Some (int64_of_nonnegative t.peer_transport_params.initial_max_stream_data_uni)
      else None
    | Bidirectional ->
      if locally_initiated
      then
        Some
          (int64_of_nonnegative
             t.peer_transport_params.initial_max_stream_data_bidi_remote)
      else
        Some
          (int64_of_nonnegative
             t.peer_transport_params.initial_max_stream_data_bidi_local)

  let current_peer_stream_max_data t stream_id =
    match peer_stream_send_window t stream_id with
    | None -> None
    | Some initial ->
      Some
        (Hashtbl.find_opt t.peer_stream_max_data stream_id
         |> Option.value ~default:initial)

  let should_grow_window ~advertised ~consumed ~window =
    let threshold = Int64.max 1L (Int64.div window 2L) in
    Int64.compare (Int64.sub advertised consumed) threshold <= 0

  let maybe_replenish_recv_credit t ~stream_id ~bytes_read =
    if bytes_read <= 0
    then ()
    else (
      let bytes_read = Int64.of_int bytes_read in
      let prev_stream_consumed =
        Hashtbl.find_opt t.recv_stream_consumed_offsets stream_id
        |> Option.value ~default:0L
      in
      let new_stream_consumed = Int64.add prev_stream_consumed bytes_read in
      Hashtbl.replace
        t.recv_stream_consumed_offsets
        stream_id
        new_stream_consumed;
      t.consumed_data_bytes <- Int64.add t.consumed_data_bytes bytes_read;

      (match local_stream_recv_window t stream_id with
      | Some stream_window when Int64.compare stream_window 0L > 0 ->
        let advertised =
          Hashtbl.find_opt t.recv_stream_max_data stream_id
          |> Option.value ~default:stream_window
        in
        if
          should_grow_window
            ~advertised
            ~consumed:new_stream_consumed
            ~window:stream_window
        then
          let new_limit = Int64.add new_stream_consumed stream_window in
          if Int64.compare new_limit advertised > 0
          then (
            Hashtbl.replace t.recv_stream_max_data stream_id new_limit;
            send_frames
              t
              [ Frame.Max_stream_data
                  { stream_id; max_data = int_of_int64_clamped new_limit }
              ])
      | Some _ | None -> ());

      if
        Int64.compare t.local_initial_max_data 0L > 0
        && should_grow_window
             ~advertised:t.max_recv_data
             ~consumed:t.consumed_data_bytes
             ~window:t.local_initial_max_data
      then
        let new_limit =
          Int64.add t.consumed_data_bytes t.local_initial_max_data
        in
        if Int64.compare new_limit t.max_recv_data > 0
        then (
          t.max_recv_data <- new_limit;
          send_frames t [ Frame.Max_data (int_of_int64_clamped new_limit) ]))

  let create_stream (c : t) ~typ ~id =
    let stream =
      Stream.create
        ~typ
        ~id
        ~report_application_error:(report_application_error c)
        ~on_bytes_read:(fun bytes_read ->
          maybe_replenish_recv_credit c ~stream_id:id ~bytes_read)
        c.wakeup_writer
    in
    Hashtbl.add c.streams id stream;
    stream

  let process_stream_frame c ~encryption_level ~id ~fragment ~is_fin =
    let stream_frame_type =
      Frame.to_frame_type (Frame.Stream { id; fragment; is_fin })
    in
    let direction = Direction.classify id in
    let is_locally_initiated =
      match c.mode with
      | Server -> Stream_id.is_server_initiated id
      | Client -> Stream_id.is_client_initiated id
    in
    let stream_exists = Hashtbl.mem c.streams id in
    let is_peer_initiated = not is_locally_initiated in
    let stream_count = Int64.add (Int64.shift_right_logical id 2) 1L in
    let max_peer_streams =
      match direction with
      | Bidirectional -> c.local_initial_max_streams_bidi
      | Unidirectional -> c.local_initial_max_streams_uni
    in
    let recv_window = current_recv_stream_max_data c id in
    let stream_final_offset =
      Int64.add (Int64.of_int fragment.IOVec.off) (Int64.of_int fragment.len)
    in
    if is_locally_initiated && not stream_exists
    then
      report_error
        c
        ~frame_type:stream_frame_type
        ~encryption_level
        Stream_state_error
    else if is_peer_initiated && Int64.compare stream_count max_peer_streams > 0
    then
      report_error
        c
        ~frame_type:stream_frame_type
        ~encryption_level
        Stream_limit_error
    else
      match recv_window with
      | None ->
        report_error
          c
          ~frame_type:stream_frame_type
          ~encryption_level
          Stream_state_error
      | Some recv_window ->
        if Int64.compare stream_final_offset recv_window > 0
        then
          report_error
            c
            ~frame_type:stream_frame_type
            ~encryption_level
            Flow_control_error
        else
          let prev_stream_highest =
            Hashtbl.find_opt c.recv_stream_highest_offsets id
            |> Option.value ~default:0L
          in
          let new_stream_highest =
            Int64.max prev_stream_highest stream_final_offset
          in
          let connection_bytes_delta =
            Int64.sub new_stream_highest prev_stream_highest
          in
          let next_recv_data_bytes =
            Int64.add c.recv_data_bytes connection_bytes_delta
          in
          if Int64.compare next_recv_data_bytes c.max_recv_data > 0
          then
            report_error
              c
              ~frame_type:stream_frame_type
              ~encryption_level
              Flow_control_error
          else (
            c.recv_data_bytes <- next_recv_data_bytes;
            Hashtbl.replace c.recv_stream_highest_offsets id new_stream_highest;
            let stream =
              match Hashtbl.find_opt c.streams id with
              | Some stream -> stream
              | None ->
                let stream =
                  create_stream c ~typ:(Stream.Type.classify id) ~id
                in
                let error_handler =
                  invoke_handler
                    c
                    ~cid:(CID.to_string c.source_cid)
                    ~start_stream:c.start_stream
                    stream
                in
                stream.error_handler <- error_handler.on_error;
                stream
            in
            Stream.Recv.push fragment ~is_fin stream.recv;
            process_stream_data c ~stream:stream.recv)

  let process_max_data_frame t max_data =
    let max_data = int64_of_nonnegative max_data in
    if Int64.compare max_data t.peer_max_data > 0
    then (
      t.peer_max_data <- max_data;
      wakeup_writer t)

  let process_max_stream_data_frame t ~stream_id ~max_data =
    let max_data = int64_of_nonnegative max_data in
    let is_locally_initiated =
      match t.mode with
      | Server -> Stream_id.is_server_initiated stream_id
      | Client -> Stream_id.is_client_initiated stream_id
    in
    let is_receive_only_stream =
      Stream_id.is_uni stream_id && not is_locally_initiated
    in
    if is_receive_only_stream
    then
      report_error t ~frame_type:Frame.Type.Max_stream_data Stream_state_error
    else
      match Hashtbl.find_opt t.streams stream_id with
      | None ->
        if is_locally_initiated
        then
          report_error
            t
            ~frame_type:Frame.Type.Max_stream_data
            Stream_state_error
        else ()
      | Some _ ->
        (match current_peer_stream_max_data t stream_id with
        | Some current when Int64.compare max_data current > 0 ->
          Hashtbl.replace t.peer_stream_max_data stream_id max_data;
          wakeup_writer t
        | Some _ | None -> ())

  (* TODO: closing/ draining states, section 10.2 *)
  let process_connection_close_quic_frame
        (t : t)
        ~frame_type
        ~error_code
        reason_phrase
    =
    Format.eprintf
      "close_quic: %d %s %d@."
      (Frame.Type.serialize frame_type)
      reason_phrase
      (Error.serialize error_code);
    shutdown t

  let process_connection_close_app_frame (t : t) ~error_code reason_phrase =
    Format.eprintf "close_app: %s %d@." reason_phrase error_code;
    shutdown t

  let process_handshake_done_frame (t : t) =
    (* From RFC9000§19.20:
     *   A server MUST treat receipt of a HANDSHAKE_DONE frame as a connection
     *   error of type PROTOCOL_VIOLATION. *)
    match t.mode with
    | Server -> report_error t ~frame_type:Handshake_done Protocol_violation
    | Client ->
      (match Qtls.transport_params t.tls_state with
      | None ->
        (* From RFC9001§8.2:
         *   endpoints that receive ClientHello or EncryptedExtensions messages
         *   without the quic_transport_parameters extension MUST close the
         *   connection with an error of type 0x016d (equivalent to a fatal TLS
         *   missing_extension alert, see Section 4.8). *)
        report_error t ~frame_type:Handshake_done (Crypto_error 0x6d)
      | Some transport_params ->
        (match
           Transport_parameters.decode_and_validate
             ~perspective:t.mode
             transport_params
         with
        | Ok transport_params ->
          apply_peer_transport_params t transport_params;
          t.recovery.rtt.max_ack_delay_ms <-
            Int64.of_int transport_params.max_ack_delay;
          (* From RFC9001§4.9.2:
           *   "An endpoint MUST discard its Handshake keys when the TLS
           *   handshake is confirmed" (and Initial keys at the same time). Per
           *   RFC9001§4.1.2, clients confirm on HANDSHAKE_DONE.
           *)
          Encryption_level.remove Initial t.encdec;
          Encryption_level.remove Handshake t.encdec;
          Recovery.discard_space t.recovery ~encryption_level:Initial;
          Recovery.discard_space t.recovery ~encryption_level:Handshake
        | Error err -> report_error t ~frame_type:Handshake_done err))

  let process_path_challenge_frame t buf =
    (* From RFC9000§8.2.2:
     *   On receiving a PATH_CHALLENGE frame, an endpoint MUST respond by
     *   echoing the data contained in the PATH_CHALLENGE frame in a
     *   PATH_RESPONSE frame.
     *
     *)
    send_frames t [ Frame.Path_response buf ]

  let process_max_streams_frame t ~direction max_streams =
    if max_streams > Stream_id.max
    then
      report_error
        t
        ~frame_type:(Frame.Type.Max_streams direction)
        Frame_encoding_error

  let process_streams_blocked_frame t ~direction max_streams =
    if max_streams > Stream_id.max
    then
      report_error
        t
        ~frame_type:(Frame.Type.Streams_blocked direction)
        Frame_encoding_error

  let process_new_connection_id_frame t ~cid ~retire_prior_to ~sequence_no =
    if CID.length cid = 0 || retire_prior_to > sequence_no
    then
      report_error
        t
        ~frame_type:Frame.Type.New_connection_id
        Frame_encoding_error
    else (
      Format.eprintf
        "new conn? %s@."
        (let (`Hex x) = Hex.of_string (CID.to_string cid) in
         x);
      (* Track the latest peer-provided CID for outgoing packets. *)
      t.dest_cid <- cid)

  let frame_handler ~packet_info t frame =
    (* TODO: validate that frame can appear at current encryption level. *)
    if Frame.is_ack_eliciting frame
    then
      (Spaces.of_encryption_level
         t.packet_number_spaces
         packet_info.encryption_level).ack_elicited <-
        true;
    match frame with
    | Frame.Padding _n ->
      (* From RFC9000§19.1:
       *   The PADDING frame (type=0x00) has no semantic value. PADDING frames
       *   can be used to increase the size of a packet. *)
      ()
    | Ping ->
      (* From RFC9000§19.2:
       *   The receiver of a PING frame simply needs to acknowledge the packet
       *   containing this frame. *)
      ()
    | Ack { delay; ranges; _ } ->
      process_ack_frame t ~packet_info ~delay ~ranges
    | Reset_stream { stream_id; application_protocol_error; final_size } ->
      process_reset_stream_frame
        t
        ~stream_id
        ~final_size
        application_protocol_error
    | Stop_sending { stream_id; application_protocol_error } ->
      process_stop_sending_frame t ~stream_id application_protocol_error
    | Crypto fragment -> process_crypto_frame t ~packet_info fragment
    | New_token _ ->
      (match t.mode with
      | Server ->
        report_error t ~frame_type:Frame.Type.New_token Protocol_violation
      | Client -> ())
    | Stream { id; fragment; is_fin } ->
      process_stream_frame
        t
        ~encryption_level:packet_info.encryption_level
        ~id
        ~fragment
        ~is_fin
    | Max_data max_data -> process_max_data_frame t max_data
    | Max_stream_data { stream_id; max_data } ->
      process_max_stream_data_frame t ~stream_id ~max_data
    | Max_streams (direction, max_streams) ->
      process_max_streams_frame t ~direction max_streams
    | Data_blocked _ | Stream_data_blocked _ -> ()
    | Streams_blocked (direction, max_streams) ->
      process_streams_blocked_frame t ~direction max_streams
    | New_connection_id { cid; retire_prior_to; sequence_no; _ } ->
      process_new_connection_id_frame t ~cid ~retire_prior_to ~sequence_no
    | Retire_connection_id _ -> ()
    | Path_challenge buf ->
      if packet_info.encryption_level <> Application_data
      then
        report_error
          t
          ~frame_type:Frame.Type.Path_challenge
          ~encryption_level:packet_info.encryption_level
          Protocol_violation
      else process_path_challenge_frame t buf
    | Path_response _ -> ()
    | Connection_close_quic { frame_type; reason_phrase; error_code } ->
      process_connection_close_quic_frame
        t
        ~frame_type
        ~error_code
        reason_phrase
    | Connection_close_app { reason_phrase; error_code } ->
      process_connection_close_app_frame t ~error_code reason_phrase
    | Handshake_done -> process_handshake_done_frame t
    | Unknown x ->
      report_error t ~frame_type:(Frame.Type.Unknown x) Frame_encoding_error

  let next_unidirectional_stream_id t ~typ =
    let id = Stream.Type.gen_id ~typ t.next_unidirectional_stream_id in
    t.next_unidirectional_stream_id <-
      Int64.succ t.next_unidirectional_stream_id;
    id

  let initialize_crypto_streams () =
    (* From RFC9000§19.6:
     *   The CRYPTO frame (type=0x06) is used to transmit cryptographic handshake
     *   messages. It can be sent in all packet types except 0-RTT. *)
    Spaces.create
      ~initial:(Stream.create_crypto ())
      ~handshake:(Stream.create_crypto ())
      ~application_data:(Stream.create_crypto ())

  let create
        ~mode
        ~peer_address
        ~tls_state
        ~transport_parameters
        ~now_ms
        ~wakeup_writer
        ~shutdown
        ~connection_handler
        connection_id
    =
    let crypto_streams = initialize_crypto_streams () in
    if CID.length connection_id > CID.max_length
    then failwith "invalid source cid";
    let rec t =
      { encdec = Encryption_level.create ~current:Initial
      ; mode
      ; packet_number_spaces =
          Spaces.create
            ~initial:(Packet_number.create ())
            ~handshake:(Packet_number.create ())
            ~application_data:(Packet_number.create ())
      ; crypto_streams
      ; tls_state
      ; source_cid = connection_id
      ; original_dest_cid = CID.empty
      ; dest_cid = CID.empty
      ; peer_address
      ; peer_transport_params = Transport_parameters.default
      ; local_initial_max_data =
          Int64.of_int transport_parameters.Config.initial_max_data
      ; local_initial_max_stream_data_bidi_local =
          Int64.of_int
            transport_parameters.Config.initial_max_stream_data_bidi_local
      ; local_initial_max_stream_data_bidi_remote =
          Int64.of_int
            transport_parameters.Config.initial_max_stream_data_bidi_remote
      ; local_initial_max_stream_data_uni =
          Int64.of_int transport_parameters.Config.initial_max_stream_data_uni
      ; local_initial_max_streams_bidi =
          Int64.of_int transport_parameters.Config.initial_max_streams_bidi
      ; local_initial_max_streams_uni =
          Int64.of_int transport_parameters.Config.initial_max_streams_uni
      ; max_recv_data =
          Int64.of_int transport_parameters.Config.initial_max_data
      ; recv_stream_max_data = Hashtbl.create ~random:true 1024
      ; recv_data_bytes = 0L
      ; recv_stream_highest_offsets = Hashtbl.create ~random:true 1024
      ; consumed_data_bytes = 0L
      ; recv_stream_consumed_offsets = Hashtbl.create ~random:true 1024
      ; peer_max_data = 0L
      ; peer_stream_max_data = Hashtbl.create ~random:true 1024
      ; sent_data_bytes = 0L
      ; sent_stream_highest_offsets = Hashtbl.create ~random:true 1024
      ; recovery = Recovery.create ()
      ; queued_packets = Queue.create ()
      ; writer = Writer.create 0x1000
      ; streams = Hashtbl.create ~random:true 1024
      ; handler = Uninitialized connection_handler
      ; wakeup_writer
      ; shutdown
      ; next_unidirectional_stream_id = 0L
      ; start_stream =
          (fun ?error_handler direction ->
            let typ =
              match mode with
              | Server -> Stream.Type.Server direction
              | Client -> Client direction
            in
            let id = next_unidirectional_stream_id t ~typ in
            let stream = create_stream t ~typ ~id in
            (match error_handler with
            | Some f -> stream.error_handler <- f
            | None -> ());
            stream)
      ; did_send_connection_close = false
      ; processed_retry_packet = false
      ; token_value = ""
      ; now_ms
      }
    in
    t

  let send_handshake_bytes t =
    match t.tls_state.handshake.machina with
    | Client (Tls.State.AwaitServerHello (_, _, [ raw_record ]))
    (* | Client13 (AwaitServerHello13 (_, _, raw)) *) ->
      let current_encryption_level = t.encdec.current in
      assert (current_encryption_level = Initial);
      let crypto_stream =
        Spaces.of_encryption_level t.crypto_streams current_encryption_level
      in
      (match t.processed_retry_packet with
      | false ->
        (* Very first initial packet for the connection, push to the crypto
           stream. *)
        let _fragment =
          Stream.Send.push
            (Bigstringaf.of_string
               ~off:0
               ~len:(String.length raw_record)
               raw_record)
            crypto_stream.send
        in
        ()
      | true ->
        send_frames
          t
          ~encryption_level:current_encryption_level
          [ Frame.Crypto
              (let buffer =
                 Bigstringaf.of_string
                   ~off:0
                   ~len:(String.length raw_record)
                   raw_record
               in
               { IOVec.off = 0; len = Bigstringaf.length buffer; buffer })
          ])
    | Client _ | Client13 _ -> assert false
    | Server _ | Server13 _ -> assert false

  let establish_connection t =
    send_handshake_bytes t;
    wakeup_writer t

  let can_send_stream_fragment t ~stream_id ~fragment =
    let fragment_end =
      Int64.add (Int64.of_int fragment.IOVec.off) (Int64.of_int fragment.len)
    in
    match current_peer_stream_max_data t stream_id with
    | None -> `Blocked
    | Some max_stream_data when Int64.compare fragment_end max_stream_data > 0 ->
      `Blocked
    | Some _ ->
      let prev_stream_highest =
        Hashtbl.find_opt t.sent_stream_highest_offsets stream_id
        |> Option.value ~default:0L
      in
      let new_stream_highest = Int64.max prev_stream_highest fragment_end in
      let connection_delta = Int64.sub new_stream_highest prev_stream_highest in
      let next_sent_data_bytes = Int64.add t.sent_data_bytes connection_delta in
      if Int64.compare next_sent_data_bytes t.peer_max_data > 0
      then `Blocked
      else `Allowed (new_stream_highest, next_sent_data_bytes)

  let available_send_budget t ~stream_id =
    let connection_remaining = Int64.sub t.peer_max_data t.sent_data_bytes in
    if Int64.compare connection_remaining 0L <= 0
    then 0
    else
      match current_peer_stream_max_data t stream_id with
      | None -> 0
      | Some stream_max ->
        let stream_sent =
          Hashtbl.find_opt t.sent_stream_highest_offsets stream_id
          |> Option.value ~default:0L
        in
        let stream_remaining = Int64.sub stream_max stream_sent in
        if Int64.compare stream_remaining 0L <= 0
        then 0
        else int_of_int64_clamped (Int64.min connection_remaining stream_remaining)

  let on_stream_fragment_sent
        t
        ~stream_id
        ~new_stream_highest
        ~new_sent_data_bytes
    =
    Hashtbl.replace t.sent_stream_highest_offsets stream_id new_stream_highest;
    t.sent_data_bytes <- new_sent_data_bytes

  module Streams = struct
    type t =
      [ `Crypto
      | `Data
      ]

    let app_data_payload_budget =
      max 1 (Recovery.Constants.default_max_datagram_size - 64)

    let truncate_fragment ~max_len ({ IOVec.off; len; buffer } as fragment) =
      if len <= max_len
      then fragment, None
      else (
        let head = { fragment with len = max_len } in
        let tail_len = len - max_len in
        let tail =
          { IOVec.off = off + max_len
          ; len = tail_len
          ; buffer = Bigstringaf.sub buffer ~off:max_len ~len:tail_len
          }
        in
        head, Some tail)

    let flush t streams =
      let rec inner acc = function
        | Seq.Cons ((encryption_level, stream_type, stream), xs) ->
          (match t.mode, stream.Stream.typ with
          | Server, Stream.Type.Server Unidirectional
          | Client, Client Unidirectional
          | _, Stream.Type.Server Bidirectional
          | _, Client Bidirectional ->
            let max_flush_bytes =
              match stream_type with
              | `Crypto -> Int.max_int
              | `Data ->
                min
                  (available_send_budget t ~stream_id:stream.id)
                  app_data_payload_budget
            in
            let _flushed =
              Stream.Send.flush ~max_bytes:max_flush_bytes stream.Stream.send
            in
            if
              Stream.Send.has_pending_output stream.send
              && Encryption_level.mem encryption_level t.encdec
            then (
              let estimated_bytes = Recovery.Constants.default_max_datagram_size in
              if not (Recovery.can_send t.recovery ~bytes:estimated_bytes)
              then acc
              else
                let packet_number =
                  Packet_number.send_next
                    (Spaces.of_encryption_level
                       t.packet_number_spaces
                       encryption_level)
                in
                let { Crypto.encrypter; _ } =
                  Encryption_level.find_exn encryption_level t.encdec
                in
                let header_info =
                  Writer.make_header_info
                    ~encrypter
                    ~packet_number
                    ~encryption_level
                    ~source_cid:t.source_cid
                    ~token:t.token_value
                    t.dest_cid
                in
                let fragment, is_fin = Stream.Send.pop_exn stream.send in
                match stream_type with
                | `Crypto ->
                  let frames = [ Frame.Crypto fragment ] in
                  let bytes_before = writer_pending_bytes t.writer in
                  Writer.write_frames_packet t.writer ~header_info frames;
                  let bytes_sent = writer_pending_bytes t.writer - bytes_before in
                  on_packet_sent
                    t
                    ~encryption_level
                    ~packet_number
                    ~bytes_sent
                    frames;
                  let can_be_followed_by_other_packets =
                    encryption_level <> Application_data
                  in
                  if can_be_followed_by_other_packets
                  then inner Wrote (xs ())
                  else Wrote_app_data
                | `Data ->
                  let fragment, deferred_fragment =
                    truncate_fragment ~max_len:app_data_payload_budget fragment
                  in
                  Option.iter
                    (fun fragment -> Stream.Send.requeue fragment stream.send)
                    deferred_fragment;
                  let is_fin = is_fin && Option.is_none deferred_fragment in
                  (match can_send_stream_fragment t ~stream_id:stream.id ~fragment with
                  | `Blocked ->
                    Stream.Send.requeue fragment stream.send;
                    inner acc (xs ())
                  | `Allowed (new_stream_highest, new_sent_data_bytes) ->
                    let frames =
                      [ Frame.Stream { id = stream.id; fragment; is_fin } ]
                    in
                    let bytes_before = writer_pending_bytes t.writer in
                    Writer.write_frames_packet t.writer ~header_info frames;
                    let bytes_sent = writer_pending_bytes t.writer - bytes_before in
                    on_packet_sent
                      t
                      ~encryption_level
                      ~packet_number
                      ~bytes_sent
                      frames;
                    on_stream_fragment_sent
                      t
                      ~stream_id:stream.id
                      ~new_stream_highest
                      ~new_sent_data_bytes;
                    let can_be_followed_by_other_packets =
                      encryption_level <> Application_data
                    in
                    if can_be_followed_by_other_packets
                    then inner Wrote (xs ())
                    else Wrote_app_data))
            else inner acc (xs ())
          | Client, Server Unidirectional | Server, Client Unidirectional ->
            (* Server can't send on unidirectional streams created by the client *)
            inner acc (xs ()))
        | Nil -> acc
      in
      let crypto_streams =
        Spaces.to_list t.crypto_streams
        |> List.map (fun (enc_level, stream) -> enc_level, `Crypto, stream)
        |> List.to_seq
      in
      let all_streams =
        let app_streams =
          Seq.map
            (fun stream -> Encryption_level.Application_data, `Data, stream)
            (Hashtbl.to_seq_values streams)
        in
        Seq.append crypto_streams app_streams
      in

      let ret = inner Didnt_write (all_streams ()) in
      ret
  end
end

type packet_info = Connection.packet_info =
  { packet_number : int64
  ; header : Packet.Header.t
  ; outgoing_frames : Frame.t list Encryption_level.t
  ; encryption_level : Encryption_level.level
  ; connection : Connection.t
  }

type t =
  { reader : Reader.t
  ; mode : Crypto.Mode.t
  ; config : Config.t
  ; connections : Connection.t Connection.Table.t
  ; now_ms : unit -> int64
  ; mutable current_peer_address : string option
  ; mutable wakeup_writer : Optional_thunk.t
  ; mutable writer_wakeup_pending : bool
  ; mutable closed : bool
  ; connection_handler :
      cid:string -> start_stream:start_stream -> stream_handler
  }

let wakeup_writer t =
  let f = t.wakeup_writer in
  t.wakeup_writer <- Optional_thunk.none;
  if Optional_thunk.is_some f
  then Optional_thunk.call_if_some f
  else t.writer_wakeup_pending <- true

let ready_to_write t () = wakeup_writer t
let shutdown_reader t = Reader.force_close t.reader

let shutdown t =
  shutdown_reader t;
  (* shutdown_writer t *)
  t.closed <- true

let register_connection_id t ~cid ~(connection : Connection.t) =
  match Connection.Table.find_opt t.connections cid with
  | None -> Connection.Table.add t.connections cid connection
  | Some existing ->
    if existing == connection then () else failwith "connection id collision"

let deregister_connection_ids t ~(connection : Connection.t) =
  let ids =
    Connection.Table.fold
      (fun cid candidate acc ->
         if candidate == connection then cid :: acc else acc)
      t.connections
      []
  in
  List.iter (fun cid -> Connection.Table.remove t.connections cid) ids

let is_closed t = t.closed

let next_timeout_ms t =
  Connection.Table.fold
    (fun _ (connection : Connection.t) acc ->
       let timeout =
         (Recovery.Debug.snapshot connection.recovery).timer
           .loss_detection_timer_ms
       in
       match timeout, acc with
       | None, _ -> acc
       | Some timeout, None -> Some timeout
       | Some timeout, Some current -> Some (Int64.min timeout current))
    t.connections
    None

let on_timeout t =
  let now_ms = t.now_ms () in
  Connection.Table.iter
    (fun _ (connection : Connection.t) ->
       match
         (Recovery.Debug.snapshot connection.recovery).timer
           .loss_detection_timer_ms
       with
       | Some timeout_ms when Int64.compare timeout_ms now_ms <= 0 ->
         Recovery.Debug.on_loss_detection_timeout
           connection.recovery
           ~now_ms:(connection.now_ms ());
         if Encryption_level.mem connection.encdec.current connection.encdec
         then (
           let remaining_probes = ref 2 in
           let retransmissions_rev = ref [] in
           List.iter
             (fun encryption_level ->
                if
                  !remaining_probes > 0
                  && Encryption_level.mem encryption_level connection.encdec
                then
                  let candidates =
                    Recovery.drain_lost connection.recovery ~encryption_level
                    @ Recovery.pto_probe_packets
                        connection.recovery
                        ~encryption_level
                        ~max_packets:!remaining_probes
                  in
                  List.iter
                    (fun frames ->
                       if !remaining_probes > 0 && frames <> []
                       then (
                         decr remaining_probes;
                         retransmissions_rev :=
                           (encryption_level, frames) :: !retransmissions_rev))
                    candidates)
             [ Initial; Handshake; Application_data ];
           match List.rev !retransmissions_rev with
           | [] ->
             Connection.send_frames
               connection
               ~encryption_level:connection.encdec.current
               [ Frame.Ping ]
           | frames_list ->
             List.iter
               (fun (encryption_level, frames) ->
                  Connection.send_frames connection ~encryption_level frames)
               frames_list);
         Connection.wakeup_writer connection
       | Some _ | None -> ())
    t.connections;
  wakeup_writer t

let send_packets t ~packet_info =
  let { connection = c; outgoing_frames; _ } = packet_info in
  (* From RFC9000§12.2:
   *   Coalescing packets in order of increasing encryption levels (Initial,
   *   0-RTT, Handshake, 1-RTT; see Section 4.1.4 of [QUIC-TLS]) makes it more
   *   likely the receiver will be able to process all the packets in a single
   *   pass. *)
  Encryption_level.ordered_iter
    (fun encryption_level frames ->
       match Encryption_level.mem encryption_level c.encdec with
       | false ->
         (* Don't attempt to send packets if we can't encrypt them yet. *)
         ()
       | true ->
         let pn_space =
           Spaces.of_encryption_level c.packet_number_spaces encryption_level
         in
         let frames =
           if pn_space.ack_elicited
           then Packet_number.compose_ack_frame pn_space :: frames
           else frames
         in
         (* TODO: bundle e.g. a PING frame with a packet that only contains ACK
            frames. *)
         (match frames with
         | [] ->
           (* Don't send invalid (payload-less) frames *)
           ()
         | frames ->
           Connection.send_frames c ~encryption_level (List.rev frames)))
    outgoing_frames;
  wakeup_writer t

let create_outgoing_frames ~current =
  let r = Encryption_level.create ~current in
  List.iter (fun lvl -> Encryption_level.add lvl [] r) Encryption_level.all;
  r

let on_close t (connection : Connection.t) =
  deregister_connection_ids t ~connection

let create_new_connection
      ?src_cid
      ~peer_address
      ~tls_state
      ~connection_handler
      ~encdec
      t
  =
  let src_cid =
    match src_cid with
    | Some src_cid -> src_cid
    | None ->
      let rec generate_unique_cid () =
        let cid = CID.generate () in
        if Connection.Table.mem t.connections cid
        then generate_unique_cid ()
        else cid
      in
      generate_unique_cid ()
  in
  let connection =
    Connection.create
      ~mode:t.mode
      ~peer_address
      ~tls_state
      ~transport_parameters:t.config.transport_parameters
      ~now_ms:t.now_ms
      ~wakeup_writer:(ready_to_write t)
      ~shutdown:(on_close t)
      ~connection_handler
      src_cid
  in
  Encryption_level.add Initial encdec connection.encdec;
  register_connection_id t ~cid:connection.source_cid ~connection;
  connection

let process_retry_packet
      t
      (c : Connection.t)
      ~(header : Packet.Header.t)
      ~token
      ~pseudo
      ~tag
  =
  assert (t.mode = Client);
  match c.processed_retry_packet with
  | true ->
    (* From RFC9000§17.2.5.2:
     *   A client MUST accept and process at most one Retry packet for each
     *   connection attempt. After the client has received and processed an
     *   Initial or Retry packet from the server, it MUST discard any
     *   subsequent Retry packets that it receives.
     *)
    ()
  | false ->
    (match header with
    | Long { source_cid = pkt_src_cid; _ } ->
      if CID.equal pkt_src_cid c.dest_cid
      then
        (* From RFC9000§7.3:
         *   A client MUST discard a Retry packet that contains a Source
         *   Connection ID field that is identical to the Destination Connection
         *   ID field of its Initial packet. *)
        ()
      else
        let connection_id = c.dest_cid in
        let retry_identity_tag =
          Crypto.Retry.calculate_integrity_tag connection_id pseudo
        in
        (match String.equal retry_identity_tag (Bigstringaf.to_string tag) with
        | false ->
          (* From RFC9000§17.2.5.2:
           *   Clients MUST discard Retry packets that have a Retry Integrity Tag
           *   that cannot be validated; [...]. *)
          ()
        | true ->
          (match String.length token with
          | 0 ->
            (* From RFC9000§17.2.5.2:
             *   A client MUST discard a Retry packet with a zero-length Retry
             *   Token field. *)
            ()
          | _ ->
            (* From RFC9000§17.2.5.1:
             *   The client MUST use the value from the Source Connection ID field of
             *   the Retry packet in the Destination Connection ID field of
             *   subsequent packets that it sends. *)
            c.dest_cid <- pkt_src_cid;

            (* From RFC9000§17.2.5.2:
             *   The client responds to a Retry packet with an Initial packet
             *   that includes the provided Retry token to continue connection
             *   establishment. *)
            c.token_value <- token;

            let encdec =
              (* From RFC9000§17.2.5.2:
               *   Changing the Destination Connection ID field also results in
               *   a change to the keys used to protect the Initial packet. *)
              { Crypto.encrypter =
                  Crypto.InitialAEAD.make ~mode:t.mode c.dest_cid
              ; decrypter =
                  Some
                    (Crypto.InitialAEAD.make
                       ~mode:(Crypto.Mode.peer t.mode)
                       c.dest_cid)
              }
            in
            Encryption_level.add Initial encdec c.encdec;
            c.processed_retry_packet <- true;
            Connection.send_handshake_bytes c;
            wakeup_writer t))
    | Initial _ | Short _ -> assert false)

let packet_handler t ?error packet =
  (* TODO: track received packet number. *)
  let connection_id = Packet.destination_cid packet in
  let c_opt =
    match Connection.Table.find_opt t.connections connection_id with
    | Some connection -> Some connection
    | None ->
      (* Has to be a new connection. TODO: assert that. *)
      assert (t.mode = Server);
      let { Config.certificates; alpn_protocols; _ } = t.config in

      let encdec =
        { Crypto.encrypter = Crypto.InitialAEAD.make ~mode:t.mode connection_id
        ; decrypter =
            Some
              (Crypto.InitialAEAD.make
                 ~mode:(Crypto.Mode.peer t.mode)
                 connection_id)
        }
      in
      let tls_state = Qtls.server ~certificates ~alpn_protocols in
      (match t.current_peer_address with
      | None -> None
      | Some peer_address ->
        let connection =
          create_new_connection
            t
            ~peer_address
            ~tls_state
            ~connection_handler:t.connection_handler
            ~encdec
        in
        (* Keep routing the client's original DCID until it switches to our
           SCID. *)
        register_connection_id t ~cid:connection_id ~connection;
        Some connection)
  in
  match c_opt with
  | None -> ()
  | Some c ->
    (match error with
    | Some error ->
      let encryption_level =
        match packet with
        | Packet.Frames { header; _ } ->
          Some (Encryption_level.of_header header)
        | Packet.VersionNegotiation _ | Packet.Retry _ -> None
      in
      Connection.report_error c ?encryption_level error
    | None ->
      if CID.is_empty c.original_dest_cid
      then
        (* From RFC9000§7.3:
         *   Each endpoint includes the value of the Source Connection ID field
         *   from the first Initial packet it sent in the
         *   initial_source_connection_id transport parameter; see Section 18.2. A
         *   server includes the Destination Connection ID field from the first
         *   Initial packet it received from the client in the
         *   original_destination_connection_id transport parameter [...]. *)
        c.original_dest_cid <- Packet.destination_cid packet;

      (match packet with
      | Packet.VersionNegotiation _ -> ()
      | Frames { header; payload; packet_number; _ } ->
        let encryption_level = Encryption_level.of_header header in

        (* (match encryption_level with *)
        (* | Initial -> *)
        (* c.packet_number_spaces.initial.received <- *)
        (* Int64.max c.packet_number_spaces.initial.received packet_number *)
        (* | Handshake -> *)
        (* c.packet_number_spaces.handshake.received <- *)
        (* Int64.max c.packet_number_spaces.handshake.received packet_number *)
        (* | Application_data | Zero_RTT -> *)
        (* c.packet_number_spaces.application_data.received <- *)
        (* Int64.max c.packet_number_spaces.application_data.received
         packet_number); *)
        let pn_space =
          Spaces.of_encryption_level c.packet_number_spaces encryption_level
        in
        pn_space.received <- Int64.max pn_space.received packet_number;

        (match Packet.source_cid packet with
        | Some src_cid ->
          (* From RFC9000§19.6:
           *   Upon receiving a packet, each endpoint sets the Destination
           *   Connection ID it sends to match the value of the Source
           *   Connection ID that it receives. *)
          c.dest_cid <- src_cid
        | None ->
          (* TODO: short packets will fail here? *)
          assert (
            match packet with
            | Frames { header = Packet.Header.Short _; _ } -> true
            | _ -> false));

        let packet_info =
          { header
          ; encryption_level
          ; packet_number
          ; outgoing_frames = create_outgoing_frames ~current:c.encdec.current
          ; connection = c
          }
        in

	        if Packet.Payload.length payload = 0
	        then Connection.report_error c Protocol_violation
	        else (
	          let parse_result =
	            match payload with
	            | Packet.Payload.Bigstring payload ->
	              Fast_parse.Frame.parse_bigstring
	                payload
	                ~handler:(Connection.frame_handler c ~packet_info)
	            | Packet.Payload.String payload ->
	              Fast_parse.Frame.parse_string
	                payload
	                ~handler:(Connection.frame_handler c ~packet_info)
	          in
	          match parse_result with
	          | Ok () ->
	            (* process streams for packets that have been acknowledged. *)
	            let acked_frames =
	              Recovery.drain_acknowledged
                c.recovery
                ~encryption_level:packet_info.encryption_level
            in
            List.iter
              (function
                | Frame.Crypto { IOVec.off; _ } ->
                  let crypto_stream =
                    Spaces.of_encryption_level
                      c.crypto_streams
                      packet_info.encryption_level
                  in
                  Stream.Send.remove off crypto_stream.send
                | Stream { id; fragment = { IOVec.off; _ }; _ } ->
                  (match Hashtbl.find_opt c.streams id with
                  | Some stream -> Stream.Send.remove off stream.send
                  | None -> ())
                | Ack { ranges = _; _ } ->
                  (* TODO: when we track packets that need acknowledgement,
                     update the largest acknowledged here. *)
                  ()
                | _other -> ())
              acked_frames;
	            if c.did_send_connection_close
	            then ()
	            else (
	              (* This packet has been processed, mark it for acknowledgement. *)
	              let pn_space =
	                Spaces.of_encryption_level
	                  c.packet_number_spaces
	                  packet_info.encryption_level
              in
              Packet_number.insert_for_acking pn_space packet_number;
              (* packet_info should now contain frames we need to send in
                 response. *)
	              send_packets t ~packet_info;
	              (* Reset for the next packet. *)
	              pn_space.ack_elicited <- false)
	          | Error e ->
	            Format.eprintf "discarding malformed packet payload: %s@." e)
	      | Retry { header; token; pseudo; tag } ->
	        process_retry_packet t c ~header ~token ~pseudo ~tag))

let create ~mode ~now_ms ~config connection_handler =
  let rec reader_packet_handler t ?error packet =
    packet_handler (Lazy.force t) ?error packet
  and decrypt t ~payload_length ~header ~header_prefix_len bs ~off ~len =
    let t : t = Lazy.force t in
    let connection_id = Packet.Header.destination_cid header in
    if CID.is_empty connection_id
    then None
    else
      let encryption_level = Encryption_level.of_header header in
      match Connection.Table.find_opt t.connections connection_id with
      | Some connection ->
        let pn_space =
          Spaces.of_encryption_level
            connection.packet_number_spaces
            encryption_level
        in
        (match Encryption_level.find encryption_level connection.encdec with
        | Some { decrypter = Some decrypter; _ } ->
          Crypto.AEAD.decrypt_packet_bigstring
            decrypter
            ~payload_length
            ~header_prefix_len
            ~largest_pn:pn_space.received
            bs
            ~off
            ~len
        | Some { decrypter = None; _ } | None ->
          if encryption_level = Handshake && connection.encdec.current = Initial
          then
            (* A Handshake packet before Handshake keys are available is
               invalid; close with PROTOCOL_VIOLATION. *)
            Connection.report_error
              connection
              ~frame_type:Frame.Type.Padding
              Protocol_violation;
          None)
      | None ->
        if encryption_level = Initial
        then
          let decrypter =
            Crypto.InitialAEAD.make
              ~mode:(Crypto.Mode.peer t.mode)
              connection_id
          in
          Crypto.AEAD.decrypt_packet_bigstring
            decrypter
            ~payload_length
            ~header_prefix_len
            ~largest_pn:(-1L)
            bs
            ~off
            ~len
        else None
  and t =
    lazy
      { reader = Reader.packets ~decrypt:(decrypt t) (reader_packet_handler t)
      ; mode
      ; config
      ; connections = Connection.Table.create ~random:true 1024
      ; now_ms
      ; current_peer_address = None
      ; wakeup_writer = Optional_thunk.none
      ; writer_wakeup_pending = false
      ; closed = false
      ; connection_handler
      }
  in
  Lazy.force t

module Server = struct
  let create ~now_ms ~config connection_handler =
    create ~mode:Server ~now_ms ~config connection_handler
end

module Client = struct
  let create ~now_ms ~config connection_handler =
    create ~mode:Client ~now_ms ~config connection_handler
end

let connect t ~address ~host connection_handler =
  let { Config.alpn_protocols; transport_parameters; _ } = t.config in
  let dest_cid = CID.generate () in
  let src_cid = CID.generate () in
  let encdec =
    (* From RFC9001§5.2:
     *   Initial packets apply the packet protection process, but use a secret
     *   derived from the Destination Connection ID field from the client's
     *   first Initial packet. *)
    { Crypto.encrypter = Crypto.InitialAEAD.make ~mode:t.mode dest_cid
    ; decrypter =
        Some (Crypto.InitialAEAD.make ~mode:(Crypto.Mode.peer t.mode) dest_cid)
    }
  in
  Format.eprintf
    "client IDs: %s -> %s@."
    (let (`Hex x) = Hex.of_string (CID.to_string src_cid) in
     x)
    (let (`Hex x) = Hex.of_string (CID.to_string dest_cid) in
     x);
  let transport_params =
    (* TODO 7.3 authenticating connection ids *)
    Transport_parameters.(
      encode
        [ (* Encoding.Original_destination_connection_id dest_cid *)
          (* ; *)
          Encoding.Initial_source_connection_id src_cid
        ; Active_connection_id_limit 2
        ; Initial_max_data transport_parameters.Config.initial_max_data
        ; Initial_max_stream_data_bidi_local
            transport_parameters.Config.initial_max_stream_data_bidi_local
        ; Initial_max_stream_data_bidi_remote
            transport_parameters.Config.initial_max_stream_data_bidi_remote
        ; Initial_max_stream_data_uni
            transport_parameters.Config.initial_max_stream_data_uni
        ; Initial_max_streams_bidi
            transport_parameters.Config.initial_max_streams_bidi
        ; Initial_max_streams_uni
            transport_parameters.Config.initial_max_streams_uni
        ])
  in

  let tls_state =
    Qtls.client
      ~authenticator:Config.null_auth
      ~alpn_protocols
      ~host
      transport_params
  in
  let new_connection =
    create_new_connection
      t
      ~peer_address:address
      ~tls_state
      ~src_cid
      ~connection_handler
      ~encdec
  in
  new_connection.dest_cid <- dest_cid;
  Connection.initialize_handler
    new_connection
    ~cid:(CID.to_string new_connection.source_cid)
    ~start_stream:new_connection.start_stream;
  Connection.establish_connection new_connection

let report_exn _t exn =
  let bt = Printexc.get_raw_backtrace () in
  let bt_s = Printexc.raw_backtrace_to_string bt in
  if String.length bt_s = 0
  then
    Format.eprintf
      "transport exception: %s (no backtrace captured; run with \
       OCAMLRUNPARAM=b)@."
      (Printexc.to_string exn)
  else
    Format.eprintf "transport exception: %s@.%s@." (Printexc.to_string exn) bt_s

let flush_pending_packets t =
  let rec inner t = function
    | Seq.Cons ((connection : Connection.t), xs) ->
      let cid = connection.source_cid in
      (match Writer.next connection.writer with
      | `Write _ ->
        Some (connection.writer, connection.peer_address, CID.to_string cid)
      | `Yield | `Close _ ->
        (match Connection._flush_pending_packets connection with
        | Wrote_app_data ->
          (* Can't write anything else in this datagram. *)
          Some (connection.writer, connection.peer_address, CID.to_string cid)
        | Didnt_write ->
          (match Connection.Streams.flush connection connection.streams with
          | Wrote | Wrote_app_data ->
            Some (connection.writer, connection.peer_address, CID.to_string cid)
          | _ -> inner t (xs ()))
        | Wrote ->
          (* There might be space in this datagram for some application data
           * frames. Send them. *)
          ignore
            (Connection.Streams.flush connection connection.streams
             : Connection.flush_ret);
          Some (connection.writer, connection.peer_address, CID.to_string cid)))
    | Nil -> None
  in
  inner t (Connection.Table.to_seq_values t.connections ())

let next_write_operation (t : t) =
  if t.closed
  then `Close 0
  else
    match flush_pending_packets t with
    | Some (writer, client_address, cid) ->
      (match Writer.next writer with
      | `Write iovecs -> `Writev (iovecs, client_address, cid)
      | `Yield -> `Yield (next_timeout_ms t)
      | `Close n -> `Close n)
    | None -> `Yield (next_timeout_ms t)

let report_write_result t ~cid result =
  match Connection.Table.find_opt t.connections (CID.of_string cid) with
  | Some conn -> Writer.report_result conn.writer result
  | None ->
    Format.eprintf "connection not found: probably already retired?@.";
    ()

let yield_writer t k =
  if t.closed
  then failwith "on_wakeup_writer on closed conn"
  else if Optional_thunk.is_some t.wakeup_writer
  then failwith "on_wakeup: only one callback can be registered at a time"
  else if t.writer_wakeup_pending
  then (
    t.writer_wakeup_pending <- false;
    k ())
  else t.wakeup_writer <- Optional_thunk.some k

let yield_reader _t _k = ()

let read_with_more t bs ~off ~len ~eof =
  Reader.read_with_more t.reader bs ~off ~len ~eof

let read t ~client_address bs ~off ~len =
  (* let hex = Hex.of_string (Bigstringaf.substring bs ~off ~len) in *)
  (* Format.eprintf "wtf(%d): %a@." len Hex.pp hex; *)
  t.current_peer_address <- Some client_address;
  read_with_more t bs ~off ~len ~eof:false

let read_eof t bs ~off ~len = read_with_more t bs ~off ~len ~eof:true

let next_read_operation t =
  match Reader.next t.reader with
  | (`Read | `Close) as operation -> operation
  | `Start -> `Read
  | `Error (`Parse (marks, msg)) ->
    Format.eprintf
      "transport parser error, dropping datagram (marks=%s): %s@."
      (String.concat "," marks)
      msg;
    Reader.recover t.reader;
    `Read
(* `Close *)
