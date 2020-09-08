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
        if Int64.compare (Int64.add cur_range.Frame.Range.last 1L) pn = 0 then
          { cur_range with last = pn } :: List.tl acc
        else (* start a new range, ther's a gap. *)
          { Frame.Range.first = pn; last = pn } :: acc)
      [ { Frame.Range.first; last = first } ]
      (List.tl packets)

  let compose_ack_frame t =
    let ranges = compose_ranges t in
    Frame.Ack { delay = 0; ranges; ecn_counts = None }
end

type packet_info =
  { packet_number : int64
  ; header : Packet.Header.t
  ; outgoing_frames : Frame.t list Encryption_level.t
  ; encryption_level : Encryption_level.level
  }

type 'a t =
  { reader : Reader.server
  ; writer : Writer.t
  ; encdec : Crypto.encdec Encryption_level.t
  ; mutable tls_state : Qtls.t
  ; packet_number_spaces : Packet_number.t Spaces.t
  ; mutable source_cid : CID.t
  ; mutable original_dest_cid : CID.t
  ; mutable dest_cid : CID.t
  ; (* From RFC<QUIC-RFC>§19.6:
     *   There is a separate flow of cryptographic handshake data in each
     *   encryption level, each of which starts at an offset of 0. This implies
     *   that each encryption level is treated as a separate CRYPTO stream of
     *   data. *)
    crypto_streams : Ordered_stream.t Spaces.t
  ; mutable client_address : 'a option
  ; mutable client_transport_params : Transport_parameters.t
  ; recovery : Recovery.t
  }

let wakeup_writer t = Writer.wakeup t.writer

let on_packet_sent t ~encryption_level ~packet_number frames =
  Recovery.on_packet_sent t.recovery ~encryption_level ~packet_number frames

let send_packet t ~encryption_level frames =
  Format.eprintf
    "Sending %d frames at encryption level: %a@."
    (List.length frames)
    Encryption_level.pp_hum
    encryption_level;
  let { Crypto.encrypter; _ } =
    Encryption_level.find_exn encryption_level t.encdec
  in
  let packet_number =
    Packet_number.send_next
      (Spaces.of_encryption_level t.packet_number_spaces encryption_level)
  in
  Writer.write_frames_packet
    t.writer
    ~encrypter
    ~encryption_level
    ~header_info:(Writer.make_header_info ~source_cid:t.source_cid t.dest_cid)
    ~packet_number
    frames;
  on_packet_sent t ~encryption_level ~packet_number frames

let send_packets t ~packet_info =
  let { outgoing_frames; _ } = packet_info in
  (* From RFC<QUIC-RFC>§12.2:
   *   Coalescing packets in order of increasing encryption levels (Initial,
   *   0-RTT, Handshake, 1-RTT; see Section 4.1.4 of [QUIC-TLS]) makes it more
   *   likely the receiver will be able to process all the packets in a single
   *   pass. *)
  Encryption_level.ordered_iter
    (fun encryption_level frames ->
      let pn_space =
        Spaces.of_encryption_level t.packet_number_spaces encryption_level
      in
      let frames =
        if pn_space.ack_elicited then
          Packet_number.compose_ack_frame pn_space :: frames
        else
          frames
      in
      send_packet t ~encryption_level (List.rev frames))
    outgoing_frames;
  wakeup_writer t

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

let process_tls_result t ~packet_info ~new_tls_state ~tls_packets =
  let { outgoing_frames; _ } = packet_info in
  let current_cipher = Qtls.current_cipher new_tls_state in
  let (_ : Encryption_level.level * int) =
    List.fold_left
      (fun (cur_encryption_level, off) item ->
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
          cur_encryption_level, off
        | `Change_dec { Tls.State.traffic_secret; _ } ->
          (* decryption change signals switching to a new encryption level *)
          let next = Encryption_level.next outgoing_frames.current in
          outgoing_frames.current <- next;
          t.encdec.current <- next;
          Encryption_level.update_current
            (function
              | None ->
                assert false
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
          (* From RFC<QUIC-RFC>§7:
           *   The offsets used by CRYPTO frames to ensure ordered delivery
           *   of cryptographic handshake data start from zero in each
           *   packet number space. *)
          next, 0
        | `Record ((ct : Tls.Packet.content_type), cs) ->
          assert (ct = HANDSHAKE);
          let len = Cstruct.len cs in
          let off' = off + len in
          let frame =
            Frame.Crypto { IOVec.off; len; buffer = Cstruct.to_bigarray cs }
          in
          Encryption_level.update
            cur_encryption_level
            (function None -> Some [ frame ] | Some xs -> Some (frame :: xs))
            outgoing_frames;
          cur_encryption_level, off')
      (* TODO: it's wrong to start from 0 everytime. Need to keep track of
       * this stream's offset. *)
      (outgoing_frames.current, 0)
      tls_packets
  in
  if
    Tls.Engine.handshake_in_progress t.tls_state
    && not (Tls.Engine.handshake_in_progress new_tls_state)
  then (
    (* send the HANDSHAKE_DONE frame if we just completed the handshake.
     *
     * From RFC<QUIC-RFC>§7.3:
     *   The server uses the HANDSHAKE_DONE frame (type=0x1e) to signal
     *   confirmation of the handshake to the client. *)
    assert (t.encdec.current = Application_data);
    assert (outgoing_frames.current = Application_data);
    assert (Option.is_none (Encryption_level.find_current outgoing_frames));
    let frame = Frame.Handshake_done in
    Encryption_level.update_current
      (function None -> Some [ frame ] | Some xs -> Some (frame :: xs))
      outgoing_frames);
  t.tls_state <- new_tls_state

let rec exhaust_crypto_stream t ~packet_info ~stream =
  let { encryption_level; _ } = packet_info in
  match Ordered_stream.pop stream with
  | Some { buffer; _ } ->
    let fragment_cstruct = Cstruct.of_bigarray buffer in
    (match t.tls_state.handshake.machina with
    | Server Tls.State.AwaitClientHello | Server13 AwaitClientHelloHRR13 ->
      assert (encryption_level = Initial);
      assert (t.encdec.current = Initial);
      (match
         Qtls.handle_raw_record
           ~embed_quic_transport_params:(fun _raw_transport_params ->
             (* From RFC<QUIC-RFC>§7.3:
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
        match Qtls.transport_params tls_state' with
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
            failwith "TODO: send connection error of TRANSPORT_PARAMETER_ERROR")
        | None ->
          ())
    | Server13
        ( AwaitClientCertificate13 _
        | AwaitClientCertificateVerify13 _
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
        process_tls_result t ~packet_info ~new_tls_state:tls_state' ~tls_packets)
    | Server13 Established13 ->
      failwith "handle key updates here"
    | Server Established ->
      failwith "expected tls 1.3"
    | Client _ | Client13 _ | Server _ | Server13 _ ->
      assert false);
    exhaust_crypto_stream t ~packet_info ~stream
  | None ->
    ()

let process_crypto_frame t ~packet_info fragment =
  let { encryption_level; _ } = packet_info in
  let crypto_stream =
    Spaces.of_encryption_level t.crypto_streams encryption_level
  in
  Ordered_stream.add fragment crypto_stream;
  exhaust_crypto_stream t ~packet_info ~stream:crypto_stream

let frame_handler ~packet_info t frame =
  (* TODO: validate that frame can appear at current encryption level. *)
  if Frame.is_ack_eliciting frame then
    (Spaces.of_encryption_level
       t.packet_number_spaces
       packet_info.encryption_level).ack_elicited <-
      true;
  match frame with
  | Frame.Padding _n ->
    (* From RFC<QUIC-RFC>§19.1:
     *   The PADDING frame (type=0x00) has no semantic value. PADDING frames
     *   can be used to increase the size of a packet. *)
    ()
  | Ping ->
    (* From RFC<QUIC-RFC>§19.2:
     *   The receiver of a PING frame simply needs to acknowledge the packet
     *   containing this frame. *)
    ()
  | Ack { ranges; _ } ->
    process_ack_frame t ~packet_info ~ranges
  | Reset_stream _ ->
    failwith
      (Format.asprintf
         "frame NYI: 0x%x"
         (Frame.Type.serialize (Frame.to_frame_type frame)))
  | Stop_sending _ ->
    failwith
      (Format.asprintf
         "frame NYI: 0x%x"
         (Frame.Type.serialize (Frame.to_frame_type frame)))
  | Crypto fragment ->
    process_crypto_frame t ~packet_info fragment
  | New_token _
  | Stream _
  | Max_data _
  | Max_stream_data _
  | Max_streams (_, _)
  | Data_blocked _
  | Stream_data_blocked _
  | Streams_blocked (_, _)
  | New_connection_id _
  | Retire_connection_id _
  | Path_challenge _
  | Path_response _
  | Connection_close_quic _
  | Connection_close_app _
  | Handshake_done
  | Unknown _ ->
    failwith
      (Format.asprintf
         "frame NYI: 0x%x"
         (Frame.Type.serialize (Frame.to_frame_type frame)))

let packet_handler t packet =
  if CID.is_empty t.original_dest_cid then
    (* From RFC<QUIC-RFC>§7.3:
     *   Each endpoint includes the value of the Source Connection ID field
     *   from the first Initial packet it sent in the
     *   initial_source_connection_id transport parameter; see Section 18.2. A
     *   server includes the Destination Connection ID field from the first
     *   Initial packet it received from the client in the
     *   original_destination_connection_id transport parameter [...]. *)
    t.original_dest_cid <- Packet.destination_cid packet;
  if CID.is_empty t.dest_cid then
    (* From RFC<QUIC-RFC>§19.6:
     *   Upon receiving a packet, each endpoint sets the Destination Connection
     *   ID it sends to match the value of the Source Connection ID that it
     *   receives. *)
    t.dest_cid <- Option.get (Packet.source_cid packet);
  match packet with
  | Packet.VersionNegotiation _ ->
    failwith "NYI: version negotiation"
  | Frames { header; payload; packet_number; _ } ->
    let packet_info =
      { header
      ; encryption_level = Encryption_level.of_header header
      ; packet_number
      ; outgoing_frames = Encryption_level.create ~current:t.encdec.current ()
      }
    in
    (match
       Angstrom.parse_bigstring
         ~consume:All
         (Parse.Frame.parser (frame_handler t ~packet_info))
         payload
     with
    | Ok () ->
      (* process streams for packets that have been acknowledged. *)
      let acked_frames =
        Recovery.drain_acknowledged
          t.recovery
          ~encryption_level:packet_info.encryption_level
      in
      List.iter
        (function
          | Frame.Crypto { IOVec.off = _; _ } ->
            ()
          | Stream { id = _; fragment = _; _ } ->
            ()
          | Ack { ranges = _; _ } ->
            (* TODO: when we track packets that need acknowledgement, update the
               largest acknowledged here. *)
            ()
          | _other ->
            ())
        acked_frames;
      (* This packet has been processed, mark it for acknowledgement. *)
      let pn_space =
        Spaces.of_encryption_level
          t.packet_number_spaces
          packet_info.encryption_level
      in
      Packet_number.insert_for_acking pn_space packet_number;
      (* packet_info should now contain frames we need to send in response. *)
      send_packets t ~packet_info;
      (* Reset for the next packet. *)
      pn_space.ack_elicited <- false
    | Error e ->
      failwith ("Err: " ^ e))
  | Retry _ ->
    failwith "NYI: retry"

let initialize_crypto_streams () =
  (* From RFC<QUIC-RFC>§19.6:
   *   The CRYPTO frame (type=0x06) is used to transmit cryptographic handshake
   *   messages. It can be sent in all packet types except 0-RTT. *)
  Spaces.create
    ~initial:(Ordered_stream.create ())
    ~handshake:(Ordered_stream.create ())
    ~application_data:(Ordered_stream.create ())

let create () =
  let cert = "./certificates/server.pem" in
  let priv_key = "./certificates/server.key" in
  let crypto_streams = initialize_crypto_streams () in
  let rec handler t packet = packet_handler (Lazy.force t) packet
  and decrypt t ~header bs ~off ~len =
    let t = Lazy.force t in
    let cs = Cstruct.of_bigarray ~off ~len bs in
    (match header with
    | Packet.Header.Initial { dest_cid; _ } ->
      (match Encryption_level.find Initial t.encdec with
      | None ->
        let encdec =
          { Crypto.encrypter = Crypto.InitialAEAD.make ~mode:Server dest_cid.id
          ; decrypter = Some (Crypto.InitialAEAD.make ~mode:Client dest_cid.id)
          }
        in
        Encryption_level.add Initial encdec t.encdec
      | Some _ ->
        ())
    | _ ->
      ());
    Format.eprintf
      "decrypt me %d@."
      (Encryption_level.of_header header |> Encryption_level.Ord.to_int);
    Crypto.AEAD.decrypt_packet
      (Option.get
         (Encryption_level.find_exn
            (Encryption_level.of_header header)
            t.encdec)
           .decrypter)
      ~largest_pn:t.packet_number_spaces.initial.received
      cs
  and t =
    lazy
      { reader = Reader.packets ~decrypt:(decrypt t) (handler t)
      ; writer = Writer.create 0x1000
      ; encdec = Encryption_level.create ()
      ; packet_number_spaces =
          Spaces.create
            ~initial:(Packet_number.create ())
            ~handshake:(Packet_number.create ())
            ~application_data:(Packet_number.create ())
      ; crypto_streams
      ; tls_state = Qtls.server ~cert ~priv_key
      ; source_cid =
          (let id =
             (* needs to match CID.length. *)
             Hex.to_string (`Hex "c3eaeabd54582a4ee2cb75bff63b8f0a874a51ad")
           in
           { CID.id; length = String.length id })
      ; original_dest_cid = CID.empty
      ; dest_cid = CID.empty
      ; client_address = None
      ; client_transport_params = Transport_parameters.default
      ; recovery = Recovery.create ()
      }
  in
  Lazy.force t

let shutdown _t = ()

let is_closed _t = false

let report_exn _t _exn = ()

let next_write_operation t =
  match Writer.next t.writer with
  | `Write iovecs ->
    `Write (iovecs, Option.get t.client_address)
  | (`Yield | `Close _) as other ->
    other

let report_write_result t result = Writer.report_result t.writer result

let yield_writer t k = Writer.on_wakeup_writer t.writer k

let yield_reader _t _k = ()

let read_with_more t ?client_address bs ~off ~len more =
  t.client_address <- client_address;
  let consumed = Reader.read_with_more t.reader bs ~off ~len more in
  consumed

let read t ?client_address bs ~off ~len =
  (* let hex = Hex.of_string (Bigstringaf.substring bs ~off ~len) in *)
  (* Format.eprintf "wtf: %a@." Hex.pp hex; *)
  read_with_more t ?client_address bs ~off ~len Incomplete

let read_eof t bs ~off ~len = read_with_more t bs ~off ~len Complete

let next_read_operation _t = `Read
