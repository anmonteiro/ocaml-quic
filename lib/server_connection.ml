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

  let create () = { sent = 0L; received = 0L }
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
end

type 'a t =
  { reader : Reader.server
  ; writer : Writer.t
  ; encdec : Crypto.encdec Encryption_level.t
  ; mutable tls_state : Qtls.t
  ; packet_numbers : Packet_number.t Spaces.t
  ; mutable source_cid : CID.t
  ; mutable dest_cid : CID.t
  ; (* From RFC<QUIC-RFC>§19.6:
     *   There is a separate flow of cryptographic handshake data in each
     *   encryption level, each of which starts at an offset of 0. This implies
     *   that each encryption level is treated as a separate CRYPTO stream of
     *   data. *)
    crypto_streams : Ordered_stream.t Encryption_level.t
  ; mutable client_address : 'a option
  }

let wakeup_writer t = Writer.wakeup t.writer

let process_crypto_frame t ~header ~packet_number fragment =
  let enclevel = Encryption_level.of_header header in
  let crypto_stream = Encryption_level.find_exn enclevel t.crypto_streams in
  Ordered_stream.add fragment crypto_stream;
  match Ordered_stream.pop crypto_stream with
  | Some { IOVec.off; len; buffer } ->
    Format.eprintf "Crypto! %d %d@." off len;
    let r = Qtls.handle_raw_record t.tls_state (Cstruct.of_bigarray buffer) in
    (match r with
    | Error e ->
      let sexp = Tls.State.sexp_of_failure e in
      Format.eprintf "Crypto failure: %a@." Sexplib.Sexp.pp_hum sexp
    | Ok (new_tls_state, recs, (`Alert _ | `Eof | `No_err)) ->
      (* TODO: send alert as quic error *)
      let _, _frames =
        List.fold_left
          (fun (off, acc) (_ct, cs) ->
            let len = Cstruct.len cs in
            let off' = off + len in
            ( off'
            , Frame.Crypto { IOVec.off; len; buffer = Cstruct.to_bigarray cs }
              :: acc ))
          (0, [])
          recs
      in
      let frames =
        let _, cs = List.hd recs in
        [ Frame.Crypto
            { IOVec.off = 0
            ; len = Cstruct.len cs
            ; buffer = Cstruct.to_bigarray cs
            }
        ; Ack
            { largest = Int64.to_int packet_number
            ; delay = 0
            ; first_range = 0
            ; ranges = []
            ; ecn_counts = None
            }
        ]
      in
      Format.eprintf
        "src? cid: %a@."
        Hex.pp
        (Hex.of_string (Packet.Header.source_cid header |> Option.get).id);
      Writer.write_frames_packet
        t.writer
        ~encdec:(Encryption_level.find_current t.encdec)
        ~encryption_level:t.encdec.current
        ~header_info:
          (Writer.make_header_info ~source_cid:t.source_cid t.dest_cid)
        ~packet_number:1L
        (List.rev frames);
      wakeup_writer t;
      t.tls_state <- new_tls_state)
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
    failwith
      (Format.asprintf
         "frame NYI: %d"
         (Frame.Type.serialize (Frame.to_frame_type frame)))
  | Ack _ ->
    failwith
      (Format.asprintf
         "frame NYI: %d"
         (Frame.Type.serialize (Frame.to_frame_type frame)))
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
  if CID.is_empty t.source_cid then
    (* From RFC<QUIC-RFC>§12.3:
     *   Upon first receiving an Initial or Retry packet from the server, the
     *   client uses the Source Connection ID supplied by the server as the
     *   Destination Connection ID for subsequent packets, including any 0-RTT
     *   packets. This means that a client might have to change the connection
     *   ID it sets in the Destination Connection ID field twice during
     *   connection establishment: once in response to a Retry, and once in
     *   response to an Initial packet from the server.
     *
     * NOTE: set the server's source connection ID to match what the client
     *       already generated, to avoid cycling initial encryption keys. *)
    t.source_cid <- Packet.destination_cid packet;
  if CID.is_empty t.dest_cid then
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
          ; decrypter = Crypto.InitialAEAD.make ~mode:Client dest_cid.id
          }
        in
        Encryption_level.add Initial encdec t.encdec
      | Some _ ->
        ())
    | _ ->
      ());
    Format.eprintf "decrypt me @.";
    Crypto.AEAD.decrypt_packet
      (Option.get t.decrypter)
      ~largest_pn:t.largest_pn
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
      ; source_cid = CID.empty
      ; dest_cid = CID.empty
      ; client_address = None
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
