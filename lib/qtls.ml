open Tls
open Utils
open State

type t = State.state =
  { handshake : State.handshake_state
  ; decryptor : State.crypto_state
  ; encryptor : State.crypto_state
  ; fragment : Cstruct.t
  }

let ( <+> ) = Cs.( <+> )

module Alert = struct
  open Packet

  let make ?level typ = ALERT, Writer.assemble_alert ?level typ

  let close_notify = make ~level:WARNING CLOSE_NOTIFY

  let handle buf =
    match Reader.parse_alert buf with
    | Ok (_, a_type) ->
      let err = match a_type with CLOSE_NOTIFY -> `Eof | _ -> `Alert a_type in
      return (err, [ `Record close_notify ])
    | Error re ->
      fail (`Fatal (`ReaderError re))
end

let rec separate_handshakes buf =
  match Reader.parse_handshake_frame buf with
  | None, rest ->
    return ([], rest)
  | Some hs, rest ->
    separate_handshakes rest >|= fun (rt, frag) -> hs :: rt, frag

let handle_change_cipher_spec = function
  | Client cs ->
    Handshake_client.handle_change_cipher_spec cs
  | Server ss ->
    Handshake_server.handle_change_cipher_spec ss
  (* D.4: the client may send a CCS before its second flight (before second
     ClientHello or encrypted handshake flight) the server may send it
     immediately after its first handshake message (ServerHello or
     HelloRetryRequest) *)
  | Client13 (AwaitServerEncryptedExtensions13 _)
  | Client13 (AwaitServerHello13 _)
  | Server13 AwaitClientHelloHRR13
  | Server13 (AwaitClientCertificate13 _)
  | Server13 (AwaitClientFinished13 _) ->
    fun s _ -> return (s, [])
  | _ ->
    fun _ _ -> fail (`Fatal `UnexpectedCCS)

and handle_handshake ?embed_quic_transport_params = function
  | Client cs ->
    Handshake_client.handle_handshake cs
  | Server ss ->
    Handshake_server.handle_handshake ?embed_quic_transport_params ss
  | Client13 cs ->
    Handshake_client13.handle_handshake cs
  | Server13 ss ->
    Handshake_server13.handle_handshake ?embed_quic_transport_params ss

let handle_handshake_packet hs ?embed_quic_transport_params buf =
  separate_handshakes (hs.hs_fragment <+> buf) >>= fun (hss, hs_fragment) ->
  let hs = { hs with hs_fragment } in
  foldM
    (fun (hs, items) raw ->
      handle_handshake ?embed_quic_transport_params hs.machina hs raw
      >|= fun (hs', items') -> hs', items @ items')
    (hs, [])
    hss
  >|= fun (hs, items) -> hs, items, `No_err

let early_data s =
  match s.machina with
  | Server13 AwaitClientHelloHRR13
  | Server13 (AwaitEndOfEarlyData13 _)
  | Server13 (AwaitClientFinished13 _)
  | Server13 (AwaitClientCertificate13 _)
  | Server13 (AwaitClientCertificateVerify13 _) ->
    true
  | _ ->
    false

let decrement_early_data hs ty buf =
  let bytes left cipher =
    let count =
      Cstruct.len buf - fst (Ciphersuite.kn_13 (Ciphersuite.privprot13 cipher))
    in
    let left' = Int32.sub left (Int32.of_int count) in
    if left' < 0l then Error (`Fatal `Toomany0rttbytes) else Ok left'
  in
  if ty = Packet.APPLICATION_DATA && early_data hs then
    let cipher =
      match hs.session with
      | `TLS13 sd :: _ ->
        sd.ciphersuite13
      | _ ->
        `AES_128_GCM_SHA256
      (* TODO assert and ensure that all early_data states have a cipher *)
    in
    bytes hs.early_data_left cipher >|= fun early_data_left ->
    { hs with early_data_left }
  else
    Ok hs

let trace_handshake ?(s = "in") buf =
  let open Reader in
  match parse_handshake buf with
  | Ok handshake ->
    Format.eprintf
      "handshake-%s: %a@."
      s
      Sexplib.Sexp.pp_hum
      (Core.sexp_of_tls_handshake handshake)
  | Error e ->
    Format.eprintf
      "READER ERR: %a@."
      Sexplib.Sexp.pp_hum
      (Reader.sexp_of_error e);
    assert false

let trace recs =
  List.iter
    (function
      | `Change_enc _ | `Change_dec _ ->
        ()
      | `Record (content_type, data) ->
        assert (content_type = Packet.HANDSHAKE);
        trace_handshake ~s:"out" data)
    recs

let handle_raw_record ?embed_quic_transport_params state buf =
  (* trace_handshake buf; *)
  (* From RFC<QUIC-TLS-RFC>§4.1.3:
   *   QUIC is only capable of conveying TLS handshake records in CRYPTO
   *   frames. *)
  let hdr = { Core.content_type = Packet.HANDSHAKE; version = `TLS_1_2 } in
  let hs = state.handshake in
  let version = hs.protocol_version in
  (match hs.machina, version with
  | Client (AwaitServerHello _), _ ->
    return ()
  | Server AwaitClientHello, _ ->
    return ()
  | Server13 AwaitClientHelloHRR13, _ ->
    return ()
  | _, `TLS_1_3 ->
    guard (hdr.version = `TLS_1_2) (`Fatal (`BadRecordVersion hdr.version))
  | _, v ->
    guard
      (Core.version_eq hdr.version v)
      (`Fatal (`BadRecordVersion hdr.version)))
  >>= fun () ->
  let ty = hdr.content_type in
  decrement_early_data hs ty buf >>= fun handshake ->
  handle_handshake_packet handshake ?embed_quic_transport_params buf
  >|= fun (handshake, items, err) ->
  (* trace items; *)
  { state with handshake }, items, err

(* From RFC<QUIC-TLS-RFC>§5.3:
 *   QUIC can use any of the ciphersuites defined in [TLS13] with the exception
 *   of TLS_AES_128_CCM_8_SHA256. *)
let ciphersuites =
  [ `AES_128_GCM_SHA256
  ; `AES_256_GCM_SHA384
  ; `CHACHA20_POLY1305_SHA256
  ; `AES_128_CCM_SHA256
  ]

let server ~certificates ~alpn_protocols =
  let server =
    Engine.server
      (Config.server
         ~ciphers:ciphersuites
         ~certificates
         ~version:(`TLS_1_3, `TLS_1_3)
         ~alpn_protocols
         ())
  in
  (server : t)

let current_cipher t : Tls.Ciphersuite.ciphersuite13 =
  match Tls.Engine.epoch t with
  | `InitialEpoch ->
    failwith "don't call before handshake bytes"
  | `Epoch { ciphersuite; _ } ->
    match ciphersuite with
    | #Tls.Ciphersuite.ciphersuite13 as cs13 ->
      cs13
    | _ ->
      assert false

let transport_params t =
  match Tls.Engine.epoch t with
  | `InitialEpoch ->
    failwith "don't call before handshake bytes"
  | `Epoch { quic_transport_parameters; _ } ->
    quic_transport_parameters
