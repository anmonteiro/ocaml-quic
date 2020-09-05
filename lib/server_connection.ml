module Result = Stdlib.Result
module Reader = Parse.Reader

type t =
  { reader : Reader.server
  ; mutable encrypter : Crypto.AEAD.t option
  ; mutable decrypter : Crypto.AEAD.t option
  ; mutable largest_pn : int64
  ; mutable tls_state : Qtls.t
  }

let process_crypto_frame t ~off:_ ~len:_ data =
  let r = Qtls.handle_raw_record t.tls_state (Cstruct.of_bigarray data) in
  match r with
  | Error e ->
    let sexp = Tls.State.sexp_of_failure e in
    Format.eprintf "Crypto failure: %a@." Sexplib.Sexp.pp_hum sexp
  | Ok (new_tls_state, recs, (`Alert _ | `Eof | `No_err)) ->
    (* TODO: send alert as quic error *)
    t.tls_state <- new_tls_state;
    List.iter
      (fun (content_type, data) ->
        assert (content_type = Tls.Packet.HANDSHAKE);
        let x = Tls.Reader.parse_handshake data in
        let sexp = Tls.Core.sexp_of_tls_handshake (Result.get_ok x) in
        Format.eprintf
          "reccy %d  %a@."
          (Cstruct.len data)
          Sexplib.Sexp.pp_hum
          sexp)
      recs

let frame_handler ~header:_ ~packet_number t frame =
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
  | Crypto { offset = off; length = len; data } ->
    process_crypto_frame t ~off ~len data
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

let create () =
  let cert = "./certificates/server.pem" in
  let priv_key = "./certificates/server.key" in
  let rec handler t packet = packet_handler (Lazy.force t) packet
  and decrypt t ~header bs ~off ~len =
    let t = Lazy.force t in
    let cs = Cstruct.of_bigarray ~off ~len bs in
    (match t.encrypter, t.decrypter, header with
    | None, None, Packet.Header.Initial { dest_cid; _ } ->
      t.encrypter <- Some (Crypto.InitialAEAD.make ~mode:Server dest_cid.id);
      t.decrypter <- Some (Crypto.InitialAEAD.make ~mode:Client dest_cid.id)
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
      ; encrypter = None
      ; decrypter = None
      ; largest_pn = 0L
      ; tls_state = Qtls.server ~cert ~priv_key
      }
  in
  Lazy.force t

let shutdown _t = ()

let is_closed _t = false

let report_exn _t _exn = ()

let yield_writer _t _k = ()

let report_write_result _t _ = ()

let next_write_operation _t = `Yield

let yield_reader _t _k = ()

let read_with_more t bs ~off ~len more =
  let consumed = Reader.read_with_more t.reader bs ~off ~len more in
  consumed

let read t bs ~off ~len =
  let hex = Hex.of_string (Bigstringaf.substring bs ~off ~len) in
  Format.eprintf "wtf: %a@." Hex.pp hex;
  read_with_more t bs ~off ~len Incomplete

let read_eof t bs ~off ~len = read_with_more t bs ~off ~len Complete

let next_read_operation _t = `Read
