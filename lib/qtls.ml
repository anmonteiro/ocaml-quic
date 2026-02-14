module State = Tls.State

type t = State.state =
  { handshake : State.handshake_state
  ; decryptor : State.crypto_state
  ; encryptor : State.crypto_state
  ; fragment : string
  ; read_closed : bool
  ; write_closed : bool
  }

let ( <+> ) = Stdlib.( ^ )
let ( let* ) = Result.bind

module Alert = struct
  open Tls.Packet

  let make ?level typ = ALERT, Tls.Writer.assemble_alert ?level typ
  let close_notify = make ~level:WARNING CLOSE_NOTIFY

  let handle buf =
    match Tls.Reader.parse_alert buf with
    | Ok (_, a_type) ->
      let err = match a_type with CLOSE_NOTIFY -> `Eof | _ -> `Alert a_type in
      Ok (err, [ `Record close_notify ])
    | Error re -> Error (`Fatal (`ReaderError re))
end

let rec separate_handshakes buf =
  match Tls.Reader.parse_handshake_frame buf with
  | None, rest -> [], rest
  | Some hs, rest ->
    let rt, frag = separate_handshakes rest in
    hs :: rt, frag

let handle_change_cipher_spec = function
  | Tls.State.Client cs -> Tls.Handshake_client.handle_change_cipher_spec cs
  | Server ss -> Tls.Handshake_server.handle_change_cipher_spec ss
  (* D.4: the client may send a CCS before its second flight (before second
     ClientHello or encrypted handshake flight) the server may send it
     immediately after its first handshake message (ServerHello or
     HelloRetryRequest) *)
  | Client13 (AwaitServerEncryptedExtensions13 _)
  | Client13 (AwaitServerHello13 _)
  | Server13 AwaitClientHelloHRR13
  | Server13 (AwaitClientCertificate13 _)
  | Server13 (AwaitClientFinished13 _) ->
    fun s _ -> Ok (s, [])
  | _ -> fun _ _ -> Error (`Fatal (`Unexpected (`Message "change cipher spec")))

and handle_handshake ?embed_quic_transport_params = function
  | Tls.State.Client cs -> Tls.Handshake_client.handle_handshake cs
  | Server ss ->
    Tls.Handshake_server.handle_handshake ?embed_quic_transport_params ss
  | Client13 cs -> Tls.Handshake_client13.handle_handshake cs
  | Server13 ss ->
    Tls.Handshake_server13.handle_handshake ?embed_quic_transport_params ss

let handle_handshake_packet
      (hs : Tls.State.handshake_state)
      ?embed_quic_transport_params
      buf
  =
  let hss, hs_fragment = separate_handshakes (hs.hs_fragment ^ buf) in
  let hs = { hs with hs_fragment } in
  let* hs, items =
    List.fold_left
      (fun (acc :
             (State.handshake_state * State.rec_resp list, State.failure) result)
        raw ->
         let* hs, items = acc in
         let* hs', items' =
           handle_handshake ?embed_quic_transport_params hs.machina hs raw
         in
         Ok (hs', items @ items'))
      (Ok (hs, []))
      hss
  in
  Ok (hs, items, None, false)

let early_data (s : Tls.State.handshake_state) =
  match s.machina with
  | Server13 AwaitClientHelloHRR13
  | Server13 (AwaitEndOfEarlyData13 _)
  | Server13 (AwaitClientFinished13 _)
  | Server13 (AwaitClientCertificate13 _)
  | Server13 (AwaitClientCertificateVerify13 _) ->
    true
  | _ -> false

let decrement_early_data hs ty buf =
  let bytes left cipher =
    let count =
      String.length buf
      - fst (Tls.Ciphersuite.kn_13 (Tls.Ciphersuite.privprot13 cipher))
    in
    let left' = Int32.sub left (Int32.of_int count) in
    if left' < 0l
    then Error (`Fatal (`Unexpected (`Message "too many 0RTT bytes")))
    else Ok left'
  in
  if ty = Tls.Packet.APPLICATION_DATA && early_data hs
  then
    let cipher =
      match hs.session with
      | `TLS13 sd :: _ -> sd.ciphersuite13
      | _ -> `AES_128_GCM_SHA256
      (* TODO assert and ensure that all early_data states have a cipher *)
    in
    let* early_data_left = bytes hs.early_data_left cipher in
    Ok { hs with early_data_left }
  else Ok hs

let trace_handshake ?(s = "in") buf =
  let open Tls.Reader in
  match parse_handshake buf with
  | Ok handshake ->
    Format.eprintf "handshake-%s: %a@." s Tls.Core.pp_handshake handshake
  | Error (`Decode e) ->
    Format.eprintf "READER ERR: %s@." e;
    assert false

let trace recs =
  List.iter
    (function
      | `Change_enc _ | `Change_dec _ -> ()
      | `Record (content_type, data) ->
        assert (content_type = Tls.Packet.HANDSHAKE);
        trace_handshake ~s:"out" data)
    recs

let guard p e = if p then Ok () else Error e

let handle_raw_record ?embed_quic_transport_params state buf =
  (* trace_handshake buf; *)
  (* From RFC<QUIC-TLS-RFC>§4.1.3:
   *   QUIC is only capable of conveying TLS handshake records in CRYPTO
   *   frames. *)
  let hdr =
    { Tls.Core.content_type = Tls.Packet.HANDSHAKE; version = `TLS_1_2 }
  in
  let hs = state.handshake in
  let version = hs.protocol_version in
  let* () =
    match hs.machina, version with
    | Client (AwaitServerHello _), _ -> Ok ()
    | Server AwaitClientHello, _ -> Ok ()
    | Server13 AwaitClientHelloHRR13, _ -> Ok ()
    | _, `TLS_1_3 ->
      guard
        (hdr.version = `TLS_1_2)
        (`Fatal (`Protocol_version (`Bad_record hdr.version)))
    | _, v ->
      guard
        (Tls.Core.version_eq hdr.version v)
        (`Fatal (`Protocol_version (`Bad_record hdr.version)))
  in
  let ty = hdr.content_type in
  let* handshake = decrement_early_data hs ty buf in
  let* handshake, items, data, read_closed =
    handle_handshake_packet handshake ?embed_quic_transport_params buf
  in
  let read_closed = read_closed || state.read_closed in
  (* trace items; *)
  Ok ({ state with handshake; read_closed }, items, data)

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
    Tls.Engine.server
      (Tls.Config.server
         ~ciphers:ciphersuites
         ~certificates
         ~version:(`TLS_1_3, `TLS_1_3)
         ~alpn_protocols
         ()
      |> Result.get_ok)
  in
  (server : t)

let client ~authenticator ~alpn_protocols ~host quic_transport_parameters =
  let client, _nonce =
    Tls.Engine.client
      ~quic_transport_parameters
      (Tls.Config.client
         ~authenticator
         ~ciphers:ciphersuites
         ~version:(`TLS_1_3, `TLS_1_3)
         ~alpn_protocols
         ~peer_name:
           (Domain_name.of_string host |> Result.get_ok |> Domain_name.host_exn)
         ()
      |> Result.get_ok)
  in
  (client : t)

let current_cipher t : Tls.Ciphersuite.ciphersuite13 =
  match Tls.Engine.epoch t with
  | Error () ->
    (match t.handshake.machina with
    | Client13
        ( AwaitServerEncryptedExtensions13 (session, _, _, _)
        (* | AwaitServerFinished13 (session, _, _, _, _) *)
        | AwaitServerCertificateRequestOrCertificate13 (session, _, _, _) ) ->
      session.ciphersuite13
    | _ -> failwith "don't call before handshake bytes")
  | Ok { ciphersuite; _ } ->
    (match ciphersuite with
    | #Tls.Ciphersuite.ciphersuite13 as cs13 -> cs13
    | _ -> assert false)

let transport_params t =
  match Tls.Engine.epoch t with
  | Error () -> failwith "don't call before handshake bytes"
  | Ok { quic_transport_parameters; _ } -> quic_transport_parameters

let alpn_protocol t =
  match Tls.Engine.epoch t with
  | Error () -> failwith "don't call before handshake bytes"
  | Ok { alpn_protocol; _ } -> alpn_protocol
