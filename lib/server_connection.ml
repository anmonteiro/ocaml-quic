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
  type t =
    { mutable sent : int64
    ; mutable received : int64
    }

  let create () = { sent = -1L; received = -1L }

  let send_next t =
    let next = Int64.add t.sent 1L in
    t.sent <- next;
    next
end

module Spaces = struct
  (* From RFC<QUIC-RFC>§12.3:
   *   Packet numbers are divided into 3 spaces in QUIC:
   *
   *   Initial space: All Initial packets (Section 17.2.2) are in this space.
   *
   *   Handshake space: All Handshake packets (Section 17.2.4) are in this
   *                    space.
   *
   *   Application data space: All 0-RTT and 1-RTT encrypted packets (Section
   *                           12.1) are in this space. *)
  type 'a t =
    { initial : 'a
    ; handshake : 'a
    ; application_data : 'a
    }

  let of_encryption_level t = function
    | Encryption_level.Initial ->
      t.initial
    | Handshake ->
      t.handshake
    | Zero_RTT | Application_data ->
      t.application_data
end

type packet_info =
  { mutable ack_eliciting : bool
  ; packet_number : int64
  ; header : Packet.Header.t
  ; outgoing_frames : Frame.t list Encryption_level.t
  }

type 'a t =
  { reader : Reader.server
  ; writer : Writer.t
  ; encdec : Crypto.encdec Encryption_level.t
  ; mutable tls_state : Qtls.t
  ; packet_numbers : Packet_number.t Spaces.t
  ; mutable source_cid : CID.t
  ; mutable original_dest_cid : CID.t
  ; mutable dest_cid : CID.t
  ; (* From RFC<QUIC-RFC>§19.6:
     *   There is a separate flow of cryptographic handshake data in each
     *   encryption level, each of which starts at an offset of 0. This implies
     *   that each encryption level is treated as a separate CRYPTO stream of
     *   data. *)
    crypto_streams : Ordered_stream.t Encryption_level.t
  ; mutable client_address : 'a option
  ; mutable ae_pkts_since_last_ack : int
        (* ack-eliciting packets since we last acknowledged *)
  ; mutable client_transport_params : Transport_parameters.t
  }

let wakeup_writer t = Writer.wakeup t.writer

let send_packet t ~encryption_level frames =
  Format.eprintf
    "Sending %d frames at encryption level: %a@."
    (List.length frames)
    Encryption_level.pp_hum
    encryption_level;
  let { Crypto.encrypter; _ } =
    Encryption_level.find_exn encryption_level t.encdec
  in
  Writer.write_frames_packet
    t.writer
    ~encrypter
    ~encryption_level
    ~header_info:(Writer.make_header_info ~source_cid:t.source_cid t.dest_cid)
    ~packet_number:
      (Packet_number.send_next
         (Spaces.of_encryption_level t.packet_numbers encryption_level))
    frames;
  wakeup_writer t

let send_packets t ~packet_info =
  let { outgoing_frames; packet_number; header; _ } = packet_info in
  let incoming_packet_enclevel = Encryption_level.of_header header in
  Encryption_level.ordered_iter
    (fun encryption_level frames ->
      let frames =
        if
          packet_info.ack_eliciting
          && Encryption_level.Ord.equal
               incoming_packet_enclevel
               encryption_level
        then
          Frame.Ack
            { delay = 0
            ; ranges =
                [ { Frame.Range.first = Int64.to_int packet_number
                  ; last = Int64.to_int packet_number
                  }
                ]
            ; ecn_counts = None
            }
          :: frames
        else
          frames
      in
      send_packet t ~encryption_level (List.rev frames))
    outgoing_frames

let process_ack_frame _t ~packet_info ~ranges =
  let { header; _ } = packet_info in
  Format.eprintf
    "got ack %a %d %d %d@."
    Encryption_level.pp_hum
    (Encryption_level.of_header header)
    (List.hd ranges).Frame.Range.last
    (List.hd ranges).Frame.Range.first
    (List.length ranges);
  ()

let process_tls_result t ~packet_info ~new_tls_state ~tls_packets =
  let { outgoing_frames; _ } = packet_info in
  let current_cipher = Qtls.current_cipher new_tls_state in
  (* TODO: send alert as quic error *)
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
  t.tls_state <- new_tls_state

let process_crypto_frame t ~packet_info fragment =
  let { header; _ } = packet_info in
  let enclevel = Encryption_level.of_header header in
  let crypto_stream = Encryption_level.find_exn enclevel t.crypto_streams in
  Ordered_stream.add fragment crypto_stream;
  (* TODO: there might be many fragments *)
  match Ordered_stream.pop crypto_stream with
  | Some { buffer; _ } ->
    let fragment_cstruct = Cstruct.of_bigarray buffer in
    (match t.tls_state.handshake.machina with
    | Server Tls.State.AwaitClientHello | Server13 AwaitClientHelloHRR13 ->
      assert (Encryption_level.of_header header = Initial);
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
      assert (Encryption_level.of_header header = Handshake);
      assert (t.encdec.current = Handshake);
      (match Qtls.handle_raw_record t.tls_state fragment_cstruct with
      | Error e ->
        let sexp = Tls.State.sexp_of_failure e in
        failwith
          (Format.asprintf "Crypto failure: %a@." Sexplib.Sexp.pp_hum sexp)
      | Ok (tls_state', tls_packets, (`Alert _ | `Eof | `No_err)) ->
        process_tls_result t ~packet_info ~new_tls_state:tls_state' ~tls_packets)
    | Server13 Established13 ->
      failwith "handle key updates here"
    | Server Established ->
      failwith "expected tls 1.3"
    | Client _ | Client13 _ | Server _ | Server13 _ ->
      assert false)
  | None ->
    Format.eprintf "NOPE@.";
    ()

let frame_handler ~packet_info t frame =
  if Frame.is_ack_eliciting frame then packet_info.ack_eliciting <- true;
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
      ; packet_number
      ; ack_eliciting = false
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
      (* packet_info should now contain frames we need to send in response. *)
      send_packets t ~packet_info
    | Error e ->
      failwith ("Err: " ^ e))
  | Retry _ ->
    failwith "NYI: retry"

let initialize_crypto_streams () =
  let streams = Encryption_level.create () in
  Encryption_level.add Initial (Ordered_stream.create ()) streams;
  Encryption_level.add Zero_RTT (Ordered_stream.create ()) streams;
  Encryption_level.add Handshake (Ordered_stream.create ()) streams;
  Encryption_level.add Application_data (Ordered_stream.create ()) streams;
  streams

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
    Format.eprintf "decrypt me @.";
    Crypto.AEAD.decrypt_packet
      (Option.get
         (Encryption_level.find_exn
            (Encryption_level.of_header header)
            t.encdec)
           .decrypter)
      ~largest_pn:t.packet_numbers.initial.received
      cs
  and t =
    lazy
      { reader = Reader.packets ~decrypt:(decrypt t) (handler t)
      ; writer = Writer.create 0x1000
      ; encdec = Encryption_level.create ()
      ; packet_numbers =
          { initial = Packet_number.create ()
          ; handshake = Packet_number.create ()
          ; application_data = Packet_number.create ()
          }
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
      ; ae_pkts_since_last_ack = 0
      ; client_transport_params = Transport_parameters.default
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
  let hex = Hex.of_string (Bigstringaf.substring bs ~off ~len) in
  Format.eprintf "wtf: %a@." Hex.pp hex;
  read_with_more t ?client_address bs ~off ~len Incomplete

let read_eof t bs ~off ~len = read_with_more t bs ~off ~len Complete

let next_read_operation _t = `Read
