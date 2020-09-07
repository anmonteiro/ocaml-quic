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
  }

let wakeup_writer t = Writer.wakeup t.writer

(* TODO: outstanding acks (replace packet_number_to_ack) *)
let send_packet t ~encryption_level ?packet_number_to_ack frames =
  let frames =
    List.rev
      ((if packet_number_to_ack <> None then
          [ Frame.Ack
              { largest = Int64.to_int (Option.get packet_number_to_ack)
              ; delay = 0
              ; first_range = 0
              ; ranges = []
              ; ecn_counts = None
              }
          ]
       else
         [])
      @ frames)
  in
  Format.eprintf
    "Sending %d frames at encryption level: %a@."
    (List.length frames)
    Encryption_level.pp_hum
    encryption_level;
  Writer.write_frames_packet
    t.writer
    ~encdec:(Encryption_level.find_exn encryption_level t.encdec)
    ~encryption_level
    ~header_info:(Writer.make_header_info ~source_cid:t.source_cid t.dest_cid)
    ~packet_number:
      (Packet_number.send_next
         (Spaces.of_encryption_level t.packet_numbers encryption_level))
    frames;
  wakeup_writer t

let process_ack_frame _t ~header ~largest ~first_range ~ranges =
  Format.eprintf
    "got ack %a %d %d %d@."
    Encryption_level.pp_hum
    (Encryption_level.of_header header)
    largest
    first_range
    (List.length ranges);
  ()

let process_tls_result ~new_tls_state ~tls_packets ~packet_number t =
  let current_cipher = Qtls.current_cipher new_tls_state in
  let current_enclevel = t.encdec.current in
  (* TODO: send alert as quic error *)
  let frames_by_enc_level =
    Encryption_level.create ~current:t.encdec.current ()
  in
  let _off =
    List.fold_left
      (fun off item ->
        match item with
        | `Change_enc { Tls.State.traffic_secret; _ } ->
          let next = Encryption_level.next frames_by_enc_level.current in
          Encryption_level.add
            next
            { Crypto.encrypter =
                Crypto.AEAD.make ~ciphersuite:current_cipher traffic_secret
            ; decrypter = None
            }
            t.encdec;
          off
        | `Change_dec { Tls.State.traffic_secret; _ } ->
          (* decryption change signals switching to a new encryption level *)
          let next = Encryption_level.next frames_by_enc_level.current in
          t.encdec.current <- next;
          frames_by_enc_level.current <- next;
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
          0
        | `Record (_ct, cs) ->
          let len = Cstruct.len cs in
          let off' = off + len in
          let frame =
            Frame.Crypto { IOVec.off; len; buffer = Cstruct.to_bigarray cs }
          in
          Encryption_level.update_current
            (function None -> Some [ frame ] | Some xs -> Some (frame :: xs))
            frames_by_enc_level;
          off')
      (* TODO: it's wrong to start from 0 everytime. Need to keep track of
       * this stream's offset. *)
      0
      tls_packets
  in
  (match Encryption_level.find current_enclevel frames_by_enc_level with
  | Some frames ->
    send_packet
      t
      ~encryption_level:current_enclevel
      ~packet_number_to_ack:packet_number
      frames;
    Encryption_level.remove current_enclevel frames_by_enc_level
  | None ->
    ());
  Encryption_level.ordered_iter
    (fun encryption_level frames -> send_packet t ~encryption_level frames)
    frames_by_enc_level;
  t.tls_state <- new_tls_state

let process_crypto_frame t ~header ~packet_number fragment =
  let enclevel = Encryption_level.of_header header in
  let crypto_stream = Encryption_level.find_exn enclevel t.crypto_streams in
  Ordered_stream.add fragment crypto_stream;
  (* TODO: there might be many fragments *)
  match Ordered_stream.pop crypto_stream with
  | Some { IOVec.off; len; buffer } ->
    let fragment_cstruct = Cstruct.of_bigarray buffer in
    Format.eprintf "Crypto! %d %d@." off len;
    (match t.tls_state.handshake.machina with
    | Server Tls.State.AwaitClientHello | Server13 AwaitClientHelloHRR13 ->
      assert (Encryption_level.of_header header = Initial);
      assert (t.encdec.current = Initial);
      (match
         Qtls.handle_raw_record
           ~embed_quic_transport_params:(fun _raw_transport_params ->
             (* We're gonna validate and act on these later. Just need to
                extract the client's *)
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
          | Ok _ ->
            process_tls_result
              ~new_tls_state:tls_state'
              ~tls_packets
              ~packet_number
              t
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
        process_tls_result
          ~new_tls_state:tls_state'
          ~tls_packets
          ~packet_number
          t)
    | Server13 Established13 ->
      failwith "handle key updates here"
    | Server Established ->
      failwith "expected tls 1.3"
    | Client _ | Client13 _ | Server _ | Server13 _ ->
      assert false)
  | None ->
    Format.eprintf "NOPE@.";
    ()

let frame_handler ~header ~packet_number t frame =
  Format.eprintf
    "Frame! %d %Ld@."
    (Frame.Type.serialize (Frame.to_frame_type frame))
    packet_number;
  match frame with
  | Frame.Padding n ->
    (* From RFC<QUIC-RFC>§19.1:
     *   The PADDING frame (type=0x00) has no semantic value. PADDING frames
     *   can be used to increase the size of a packet. *)
    Format.eprintf "how much padding: %d@." n;
    ()
  | Ping ->
    (* From RFC<QUIC-RFC>§19.2:
     *   The receiver of a PING frame simply needs to acknowledge the packet
     *   containing this frame. *)
    ()
  | Ack { largest; first_range; ranges; _ } ->
    process_ack_frame t ~header ~largest ~first_range ~ranges
  | Reset_stream _ ->
    failwith
      (Format.asprintf
         "frame NYI: %d"
         (Frame.Type.serialize (Frame.to_frame_type frame)))
  | Stop_sending _ ->
    failwith
      (Format.asprintf
         "frame NYI: %d"
         (Frame.Type.serialize (Frame.to_frame_type frame)))
  | Crypto fragment ->
    process_crypto_frame t ~header ~packet_number fragment
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
         "frame NYI: %d"
         (Frame.Type.serialize (Frame.to_frame_type frame)))

let packet_handler t packet =
  (* From RFC<QUIC-RFC>§19.6:
   *   Upon receiving a packet, each endpoint sets the Destination Connection
   *   ID it sends to match the value of the Source Connection ID that it
   *   receives. *)
  if CID.is_empty t.original_dest_cid then
    (* From RFC<QUIC-RFC>§7.2:
     *   Upon first receiving an Initial or Retry packet from the server, the
     *   client uses the Source Connection ID supplied by the server as the
     *   Destination Connection ID for subsequent packets, including any 0-RTT
     *   packets. This means that a client might have to change the connection
     *   ID it sets in the Destination Connection ID field twice during
     *   connection establishment: once in response to a Retry, and once in
     *   response to an Initial packet from the server. *)
    t.original_dest_cid <- Packet.destination_cid packet;
  if CID.is_empty t.dest_cid then
    (* From RFC<QUIC-RFC>§12.3:
     *   Each endpoint uses the Source Connection ID field to specify the
     *   connection ID that is used in the Destination Connection ID field of
     *   packets being sent to them. *)
    t.dest_cid <- Option.get (Packet.source_cid packet);
  match packet with
  | Packet.VersionNegotiation _ ->
    failwith "NYI: version negotiation"
  | Frames { header; payload; packet_number; _ } ->
    (match
       Angstrom.parse_bigstring
         ~consume:All
         (Parse.Frame.parser (frame_handler t ~header ~packet_number))
         payload
     with
    | Ok () ->
      ()
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
