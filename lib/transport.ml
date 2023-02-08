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

module Reader = Parse.Reader
module Writer = Serialize.Writer

module Packet_number = struct
  module PSet = Set.Make (Int64)

  type t =
    { mutable sent : int64
    ; mutable received : int64
    ; mutable received_need_ack : PSet.t
    ; mutable ack_elicited : bool
    }

  let create () =
    { sent = -1L
    ; received = -1L
    ; received_need_ack = PSet.empty
    ; ack_elicited = false
    }

  let send_next t =
    let next = Int64.add t.sent 1L in
    t.sent <- next;
    next

  let insert_for_acking t packet_number =
    t.received_need_ack <- PSet.add packet_number t.received_need_ack

  let compose_ranges t =
    (* list is sorted *)
    let packets = PSet.elements t.received_need_ack in
    (* don't empty the set, the packet containg the ACK frame could be lost. *)
    assert (List.length packets > 0);
    let first = List.hd packets in
    List.fold_left
      (fun acc pn ->
        let cur_range = List.hd acc in
        if Int64.compare (Int64.add cur_range.Frame.Range.last 1L) pn = 0
        then { cur_range with last = pn } :: List.tl acc
        else
          (* start a new range, ther's a gap. *)
          { Frame.Range.first = pn; last = pn } :: acc)
      [ { Frame.Range.first; last = first } ]
      (List.tl packets)

  let compose_ack_frame t =
    let ranges = compose_ranges t in
    Frame.Ack { delay = 0; ranges; ecn_counts = None }
end

type stream_handler = F of (Stream.t -> unit)
type start_stream = direction:Direction.t -> Stream.t

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
    ; mutable source_cid : CID.t
    ; mutable original_dest_cid : CID.t
    ; mutable dest_cid : CID.t
    ; (* From RFC9000§19.6:
       *   There is a separate flow of cryptographic handshake data in each
       *   encryption level, each of which starts at an offset of 0. This implies
       *   that each encryption level is treated as a separate CRYPTO stream of
       *   data. *)
      crypto_streams : Stream.t Spaces.t
    ; mutable peer_address : string
    ; mutable client_transport_params : Transport_parameters.t
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
    }

  let invoke_handler t ~cid ~start_stream stream =
    match t.handler with
    | Uninitialized f ->
      let (F stream_handler as handler_f) = f ~cid ~start_stream in
      t.handler <- Initialized handler_f;
      stream_handler stream
    | Initialized (F stream_handler) -> stream_handler stream

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

  let shutdown_writer t =
    Writer.close t.writer;
    wakeup_writer t

  let shutdown t =
    shutdown_writer t;
    t.shutdown t

  let on_packet_sent t ~encryption_level ~packet_number frames =
    Recovery.on_packet_sent t.recovery ~encryption_level ~packet_number frames

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

  let process_ack_frame t ~packet_info ~ranges =
    let { header; encryption_level; _ } = packet_info in
    Recovery.on_ack_received t.recovery ~encryption_level ~ranges;
    Format.eprintf
      "got ack %a %Ld %Ld %d@."
      Encryption_level.pp_hum
      (Encryption_level.of_header header)
      (List.hd ranges).Frame.Range.last
      (List.hd ranges).Frame.Range.first
      (List.length ranges);
    ()

  let report_error ?frame_type t error =
    if not t.did_send_connection_close
    then (
      t.did_send_connection_close <- true;
      send_frames
        t
        [ Frame.Connection_close_quic
            { frame_type = Option.value ~default:Frame.Type.Padding frame_type
            ; reason_phrase = ""
            ; error_code = error
            }
        ])

  let process_reset_stream_frame t ~stream_id ~final_size:_ _application_error =
    match Hashtbl.find_opt t.streams stream_id with
    | Some stream ->
      (match stream.typ, t.mode with
      | Client Unidirectional, Client | Server Unidirectional, Server ->
        (* From RFC9000§19.4:
         *   An endpoint that receives a RESET_STREAM frame for a send-only
         *   stream MUST terminate the connection with error
         *   STREAM_STATE_ERROR.
         *)
        report_error
          t
          ~frame_type:Frame.Type.Reset_stream
          Error.Stream_state_error
      | _ ->
        (* TODO: stream state transitions 3.1 / 3.2 *)
        Hashtbl.remove t.streams stream_id)
    | None -> ()

  (* TODO: Receiving a STOP_SENDING frame for a locally initiated stream that *)
  (* has not yet been created MUST be treated as a connection error of type *)
  (* STREAM_STATE_ERROR. *)
  let process_stop_sending_frame t ~stream_id application_protocol_error =
    match Hashtbl.find_opt t.streams stream_id with
    | Some stream ->
      (match stream.typ, t.mode with
      | Client Unidirectional, Client | Server Unidirectional, Server ->
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
        send_frames
          t
          [ Frame.Reset_stream
              { stream_id
              ; (* From RFC9000§19.5:
                 *   An endpoint SHOULD copy the error code from the
                 *   STOP_SENDING frame to the RESET_STREAM frame it sends, but
                 *   it can use any application error code. *)
                application_protocol_error
              ; final_size = Stream.Send.final_size stream.send
              }
          ])
    | None -> ()

  let process_tls_result t ~packet_info ~new_tls_state ~tls_packets =
    let { outgoing_frames; _ } = packet_info in
    let current_cipher = Qtls.current_cipher new_tls_state in
    let (_ : Encryption_level.level) =
      List.fold_left
        (fun cur_encryption_level item ->
          match item with
          | `Change_enc { Tls.State.traffic_secret; _ } ->
            let next = Encryption_level.next cur_encryption_level in
            Encryption_level.add
              next
              { Crypto.encrypter =
                  Crypto.AEAD.make ~ciphersuite:current_cipher traffic_secret
              ; decrypter = None
              }
              t.encdec;
            cur_encryption_level
          | `Change_dec { Tls.State.traffic_secret; _ } ->
            (* decryption change signals switching to a new encryption level *)
            let next = Encryption_level.next outgoing_frames.current in
            outgoing_frames.current <- next;
            t.encdec.current <- next;
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
                             traffic_secret)
                    })
              t.encdec;
            (* From RFC9000§7:
             *   The offsets used by CRYPTO frames to ensure ordered delivery
             *   of cryptographic handshake data start from zero in each
             *   packet number space. *)
            next
          | `Record ((ct : Tls.Packet.content_type), cs) ->
            assert (ct = HANDSHAKE);
            let crypto_stream =
              Spaces.of_encryption_level t.crypto_streams cur_encryption_level
            in
            let fragment =
              Stream.Send.push (Cstruct.to_bigarray cs) crypto_stream.send
            in
            Encryption_level.update_exn
              cur_encryption_level
              (fun xs -> Some (Frame.Crypto fragment :: xs))
              outgoing_frames;
            cur_encryption_level)
        outgoing_frames.current
        tls_packets
    in
    if Tls.Engine.handshake_in_progress t.tls_state
       && not (Tls.Engine.handshake_in_progress new_tls_state)
    then (
      (* send the HANDSHAKE_DONE frame if we just completed the handshake.
       *
       * From RFC9000§7.3:
       *   The server uses the HANDSHAKE_DONE frame (type=0x1e) to signal
       *   confirmation of the handshake to the client. *)
      assert (t.encdec.current = Application_data);
      assert (outgoing_frames.current = Application_data);
      assert (Encryption_level.find_current_exn outgoing_frames = []);
      Encryption_level.update_current_exn
        (fun xs -> Some (Frame.Handshake_done :: xs))
        outgoing_frames);
    t.tls_state <- new_tls_state

  let rec exhaust_crypto_stream t ~packet_info ~stream =
    let { encryption_level; _ } = packet_info in
    match Stream.Recv.pop stream with
    | Some { buffer; _ } ->
      let fragment_cstruct = Cstruct.of_bigarray buffer in
      (match t.tls_state.handshake.machina with
      | Server Tls.State.AwaitClientHello | Server13 AwaitClientHelloHRR13 ->
        assert (encryption_level = Initial);
        assert (t.encdec.current = Initial);
        (match
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
                     ; (* TODO: get these from configuration *)
                       Initial_max_data (1 lsl 27)
                     ; Initial_max_stream_data_bidi_local (1 lsl 27)
                     ; Initial_max_stream_data_bidi_remote (1 lsl 27)
                     ; Initial_max_stream_data_uni (1 lsl 27)
                     ; Initial_max_streams_bidi (1 lsl 8)
                     ; Initial_max_streams_uni (1 lsl 8)
                     ]))
             t.tls_state
             fragment_cstruct
         with
        | Error e ->
          let sexp = Tls.State.sexp_of_failure e in
          failwith
            (Format.asprintf "Crypto failure: %a@." Sexplib.Sexp.pp_hum sexp)
        | Ok (tls_state', tls_packets, (`Alert _ | `Eof | `No_err)) ->
          (* TODO: send alerts as quic error *)
          (match Qtls.transport_params tls_state' with
          | Some quic_transport_params ->
            (match
               Transport_parameters.decode_and_validate
                 ~perspective:Server
                 quic_transport_params
             with
            | Ok transport_params ->
              t.client_transport_params <- transport_params;
              process_tls_result
                t
                ~packet_info
                ~new_tls_state:tls_state'
                ~tls_packets
            | Error _ ->
              failwith
                "TODO: send connection error of TRANSPORT_PARAMETER_ERROR")
          | None -> ()))
      | Server13
          ( AwaitClientCertificate13 _ | AwaitClientCertificateVerify13 _
          | AwaitClientFinished13 _ ) ->
        assert (encryption_level = Handshake);
        assert (t.encdec.current = Handshake);
        (match Qtls.handle_raw_record t.tls_state fragment_cstruct with
        | Error e ->
          let sexp = Tls.State.sexp_of_failure e in
          failwith
            (Format.asprintf "Crypto failure: %a@." Sexplib.Sexp.pp_hum sexp)
        | Ok (tls_state', tls_packets, (`Alert _ | `Eof | `No_err)) ->
          (* TODO: send alerts as quic error *)
          process_tls_result
            t
            ~packet_info
            ~new_tls_state:tls_state'
            ~tls_packets)
      | Server13 Established13 -> failwith "handle key updates here"
      | Server Established -> failwith "expected tls 1.3"
      | Client _ | Client13 _ | Server _ | Server13 _ -> assert false);
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
    exhaust_crypto_stream t ~packet_info ~stream:crypto_stream.recv

  let rec process_stream_data t ~stream =
    match Stream.Recv.pop stream with
    | Some _ ->
      (* Stream.Buffer.schedule_bigstring stream.consumer buffer; *)
      (* Stream.Recv.flush_recv stream; *)
      process_stream_data t ~stream
    | None -> ()

  let create_stream (c : t) ~typ ~id =
    let stream = Stream.create ~typ ~id c.wakeup_writer in
    Hashtbl.add c.streams id stream;
    stream

  let process_stream_frame c ~id ~fragment ~is_fin =
    let stream =
      match Hashtbl.find_opt c.streams id with
      | Some stream -> stream
      | None ->
        let direction = Direction.classify id in
        let stream =
          create_stream
            c
            ~typ:
              (match c.mode with
              | Server -> Client direction
              | Client -> Server direction)
            ~id
        in
        invoke_handler
          c
          ~cid:(CID.to_string c.source_cid)
          ~start_stream:c.start_stream
          stream;
        stream
    in
    Stream.Recv.push fragment ~is_fin stream.recv;
    process_stream_data c ~stream:stream.recv

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

  let process_path_challenge_frame t buf =
    (* From RFC9000§8.2.2:
     *   On receiving a PATH_CHALLENGE frame, an endpoint MUST respond by
     *   echoing the data contained in the PATH_CHALLENGE frame in a
     *   PATH_RESPONSE frame.
     *
     *)
    send_frames t [ Frame.Path_response buf ]

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
    | Ack { ranges; _ } -> process_ack_frame t ~packet_info ~ranges
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
      failwith
        (Format.asprintf
           "frame NYI: 0x%x"
           (Frame.Type.serialize (Frame.to_frame_type frame)))
    | Stream { id; fragment; is_fin } ->
      process_stream_frame t ~id ~fragment ~is_fin
    | Max_data _ | Max_stream_data _
    | Max_streams (_, _)
    | Data_blocked _ | Stream_data_blocked _
    | Streams_blocked (_, _) ->
      failwith
        (Format.asprintf
           "frame NYI: 0x%x"
           (Frame.Type.serialize (Frame.to_frame_type frame)))
    | New_connection_id { cid; _ } ->
      Format.eprintf
        "new conn? %s@."
        (let (`Hex x) = Hex.of_string (CID.to_string cid) in
         x)
    | Retire_connection_id _ ->
      failwith
        (Format.asprintf
           "frame NYI: 0x%x"
           (Frame.Type.serialize (Frame.to_frame_type frame)))
    | Path_challenge buf -> process_path_challenge_frame t buf
    | Path_response _ ->
      failwith
        (Format.asprintf
           "frame NYI: 0x%x"
           (Frame.Type.serialize (Frame.to_frame_type frame)))
    | Connection_close_quic { frame_type; reason_phrase; error_code } ->
      process_connection_close_quic_frame
        t
        ~frame_type
        ~error_code
        reason_phrase
    | Connection_close_app { reason_phrase; error_code } ->
      process_connection_close_app_frame t ~error_code reason_phrase
    | Handshake_done | Unknown _ ->
      failwith
        (Format.asprintf
           "frame NYI: 0x%x"
           (Frame.Type.serialize (Frame.to_frame_type frame)))

  let next_unidirectional_stream_id t ~direction =
    let id =
      Stream.Type.gen_id ~typ:(Server direction) t.next_unidirectional_stream_id
    in
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
      ~wakeup_writer
      ~shutdown
      ~connection_handler
      connection_id
    =
    let crypto_streams = initialize_crypto_streams () in
    let source_cid =
      (* let id = *)
      (* (* needs to match CID.src_length. *) *)
      (* Hex.to_string (`Hex "c3eaeabd54582a4ee2cb75bff63b8f0a874a51ad") *)
      (* in *)
      assert (String.length (CID.to_string connection_id) = CID.src_length);
      connection_id
    in
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
      ; source_cid
      ; original_dest_cid = CID.empty
      ; dest_cid = CID.empty
      ; peer_address
      ; client_transport_params = Transport_parameters.default
      ; recovery = Recovery.create ()
      ; queued_packets = Queue.create ()
      ; writer = Writer.create 0x1000
      ; streams = Hashtbl.create ~random:true 1024
      ; handler = Uninitialized connection_handler
      ; wakeup_writer
      ; shutdown
      ; next_unidirectional_stream_id = 0L
      ; start_stream =
          (fun ~direction ->
            let id = next_unidirectional_stream_id t ~direction in
            create_stream t ~typ:(Server direction) ~id)
      ; did_send_connection_close = false
      ; processed_retry_packet = false
      ; token_value = ""
      }
    in
    t

  let send_handshake_bytes t =
    match t.tls_state.handshake.machina with
    | Client (Tls.State.AwaitServerHello (_, _, [ raw_record ]))
    (* | Client13 (AwaitServerHello13 (_, _, raw)) *) ->
      let current_encryption_level = t.encdec.current in
      assert (current_encryption_level = Initial);
      (* [(Packet.HANDSHAKE, raw)] *)
      let crypto_stream =
        Spaces.of_encryption_level t.crypto_streams current_encryption_level
      in
      let fragment =
        Stream.Send.push (Cstruct.to_bigarray raw_record) crypto_stream.send
      in
      send_frames
        t
        ~encryption_level:current_encryption_level
        [ Frame.Crypto fragment ]
    | Client _ | Client13 _ -> assert false
    | Server _ | Server13 _ -> assert false

  let establish_connection t =
    send_handshake_bytes t;
    wakeup_writer t

  type flush_ret =
    | Didnt_write
    | Wrote
    | Wrote_app_data

  (* Flushes packets into one datagram *)
  let _flush_pending_packets t =
    let rec inner t acc =
      match Queue.take_opt t.queued_packets with
      | Some
          ( ({ Writer.encryption_level; packet_number; _ } as header_info)
          , frames ) ->
        Format.eprintf
          "Sending %d frames at encryption level: %a@."
          (List.length frames)
          Encryption_level.pp_hum
          encryption_level;
        Writer.write_frames_packet t.writer ~header_info frames;
        on_packet_sent t ~encryption_level ~packet_number frames;
        let can_be_followed_by_other_packets =
          encryption_level <> Application_data
        in
        if can_be_followed_by_other_packets
        then inner t Wrote
        else Wrote_app_data
      | None -> acc
    in
    inner t Didnt_write

  module Streams = struct
    let flush t streams =
      let rec inner acc = function
        | Seq.Cons (stream, xs) ->
          (match stream.Stream.typ with
          | Stream.Type.Server _ | Client Bidirectional ->
            let _flushed = Stream.Send.flush stream.Stream.send in
            if Stream.Send.has_pending_output stream.send
            then (
              let encryption_level = Encryption_level.Application_data in
              let { Crypto.encrypter; _ } =
                Encryption_level.find_exn encryption_level t.encdec
              in
              let packet_number =
                Packet_number.send_next
                  (Spaces.of_encryption_level
                     t.packet_number_spaces
                     encryption_level)
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
              let frames =
                [ Frame.Stream { id = stream.id; fragment; is_fin } ]
              in
              Writer.write_frames_packet t.writer ~header_info frames;
              on_packet_sent t ~encryption_level ~packet_number frames;
              Wrote_app_data)
            else inner acc (xs ())
          | Client Unidirectional ->
            (* Server can't send on unidirectional streams created by the
               client *)
            inner acc (xs ()))
        | Nil -> acc
      in
      inner Didnt_write (Hashtbl.to_seq_values streams ())
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
  ; mutable current_peer_address : string option
  ; mutable wakeup_writer : Optional_thunk.t
  ; mutable closed : bool
  ; connection_handler :
      cid:string -> start_stream:start_stream -> stream_handler
  }

let wakeup_writer t =
  let f = t.wakeup_writer in
  t.wakeup_writer <- Optional_thunk.none;
  Optional_thunk.call_if_some f

let ready_to_write t () = wakeup_writer t
let shutdown_reader t = Reader.force_close t.reader

let shutdown t =
  shutdown_reader t;
  (* shutdown_writer t *)
  t.closed <- true

let is_closed t = t.closed

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
        | frames -> Connection.send_frames c ~encryption_level (List.rev frames)))
    outgoing_frames;
  wakeup_writer t

let create_outgoing_frames ~current =
  let r = Encryption_level.create ~current in
  List.iter (fun lvl -> Encryption_level.add lvl [] r) Encryption_level.all;
  r

let create_new_connection
    ?(src_cid = CID.generate ())
    ~peer_address
    ~tls_state
    ~connection_handler
    ~encdec
    t
  =
  let shutdown_connection (c : Connection.t) =
    Connection.Table.remove t.connections c.source_cid
  in
  let connection =
    Connection.create
      ~mode:t.mode
      ~peer_address
      ~tls_state
      ~wakeup_writer:(ready_to_write t)
      ~shutdown:shutdown_connection
      ~connection_handler
      src_cid
  in
  Encryption_level.add Initial encdec connection.encdec;

  assert (not (Connection.Table.mem t.connections src_cid));
  Connection.Table.add t.connections connection.source_cid connection;
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
          |> Cstruct.to_bigarray
        in
        (match
           Cstruct.equal
             (Cstruct.of_bigarray retry_identity_tag)
             (Cstruct.of_bigarray tag)
         with
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

            Connection.send_handshake_bytes c;

            c.processed_retry_packet <- true;
            wakeup_writer t))
    | Initial _ | Short _ -> assert false)

let packet_handler t packet =
  (* TODO: track received packet number. *)
  let connection_id = Packet.destination_cid packet in
  let c =
    match Connection.Table.find_opt t.connections connection_id with
    | Some connection -> connection
    | None ->
      (* Has to be a new connection. TODO: assert that. *)
      assert (t.mode = Server);
      let { Config.certificates; alpn_protocols } = t.config in

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
      create_new_connection
        t
        ~peer_address:(Option.get t.current_peer_address)
        ~tls_state
        ~connection_handler:t.connection_handler
        ~encdec
  in
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

  match packet with
  | Packet.VersionNegotiation _ -> failwith "NYI: version negotiation"
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
    (match Packet.source_cid packet with
    | Some src_cid ->
      (* From RFC9000§19.6:
       *   Upon receiving a packet, each endpoint sets the Destination Connection
       *   ID it sends to match the value of the Source Connection ID that it
       *   receives. *)
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

    (match
       Angstrom.parse_bigstring
         ~consume:All
         (Parse.Frame.parser (Connection.frame_handler c ~packet_info))
         payload
     with
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
          | Stream { id = _; fragment = _; _ } -> ()
          | Ack { ranges = _; _ } ->
            (* TODO: when we track packets that need acknowledgement, update the
               largest acknowledged here. *)
            ()
          | _other -> ())
        acked_frames;
      (* This packet has been processed, mark it for acknowledgement. *)
      let pn_space =
        Spaces.of_encryption_level
          c.packet_number_spaces
          packet_info.encryption_level
      in
      Packet_number.insert_for_acking pn_space packet_number;
      (* packet_info should now contain frames we need to send in response. *)
      send_packets t ~packet_info;
      (* Reset for the next packet. *)
      pn_space.ack_elicited <- false
    | Error e -> failwith ("Err: " ^ e))
  | Retry { header; token; pseudo; tag } ->
    process_retry_packet t c ~header ~token ~pseudo ~tag

let create ~mode ~config connection_handler =
  let rec reader_packet_handler t packet = packet_handler (Lazy.force t) packet
  and decrypt t ~payload_length ~header bs ~off ~len =
    let t : t = Lazy.force t in
    let cs = Cstruct.of_bigarray ~off ~len bs in
    let connection_id = Packet.Header.destination_cid header in
    if CID.is_empty connection_id
    then
      (* TODO: section 5.2 says we should keep track of connections *)
      failwith "NYI: empty CID"
    else
      let decrypter, largest_pn =
        match Connection.Table.find_opt t.connections connection_id with
        | Some connection ->
          ( Option.get
              (Encryption_level.find_exn
                 (Encryption_level.of_header header)
                 connection.encdec)
                .decrypter
          , connection.packet_number_spaces.initial.received )
        | None ->
          assert (Encryption_level.of_header header = Initial);
          ( Crypto.InitialAEAD.make ~mode:(Crypto.Mode.peer t.mode) connection_id
          , 0L )
      in
      Crypto.AEAD.decrypt_packet decrypter ~payload_length ~largest_pn cs
  and t =
    lazy
      { reader = Reader.packets ~decrypt:(decrypt t) (reader_packet_handler t)
      ; mode
      ; config
      ; connections = Connection.Table.create ~random:true 1024
      ; current_peer_address = None
      ; wakeup_writer = Optional_thunk.none
      ; closed = false
      ; connection_handler
      }
  in
  Lazy.force t

module Server = struct
  let create ~config connection_handler =
    create ~mode:Server ~config connection_handler
end

module Client = struct
  let create ~config connection_handler =
    create ~mode:Client ~config connection_handler
end

let connect t ~address connection_handler =
  let { Config.alpn_protocols; _ } = t.config in
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
        ])
  in
  let tls_state =
    Qtls.client ~authenticator:Config.null_auth ~alpn_protocols transport_params
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
  Connection.establish_connection new_connection

let report_exn _t _exn = ()

let flush_pending_packets t =
  let rec inner t = function
    | Seq.Cons ((connection : Connection.t), xs) ->
      let cid = connection.source_cid in
      (match Connection._flush_pending_packets connection with
      | Wrote_app_data ->
        (* Can't write anything else in this datagram. *)
        Some (connection.writer, connection.peer_address, CID.to_string cid)
      | Didnt_write ->
        (match Connection.Streams.flush connection connection.streams with
        | Wrote_app_data ->
          Some (connection.writer, connection.peer_address, CID.to_string cid)
        | _ -> inner t (xs ()))
      | Wrote ->
        (* There might be space in this datagram for some application data
         * frames. Send them. *)
        ignore
          (Connection.Streams.flush connection connection.streams
            : Connection.flush_ret);
        Some (connection.writer, connection.peer_address, CID.to_string cid))
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
      | (`Yield | `Close _) as other -> other)
    | None -> `Yield

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
  else t.wakeup_writer <- Optional_thunk.some k

let yield_reader _t _k = ()

let read_with_more t bs ~off ~len more =
  Reader.read_with_more t.reader bs ~off ~len more

let read t ~client_address bs ~off ~len =
  (* let hex = Hex.of_string (Bigstringaf.substring bs ~off ~len) in *)
  (* Format.eprintf "wtf(%d): %a@." len Hex.pp hex; *)
  t.current_client_address <- Some client_address;
  read_with_more t bs ~off ~len Incomplete

let read_eof t bs ~off ~len = read_with_more t bs ~off ~len Complete
let next_read_operation _t = `Read
