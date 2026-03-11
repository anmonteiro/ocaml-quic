module State = struct
  type encryption_level =
    | Initial
    | Zero_RTT
    | Handshake
    | Application_data

  type crypto_state = { traffic_secret : string }

  type rec_resp =
    [ `Change_enc of crypto_state
    | `Change_dec of crypto_state
    | `Record of Tls.Packet.content_type * string
    | `Level_change_enc of encryption_level * crypto_state
    | `Level_change_dec of encryption_level * crypto_state
    | `Level_record of encryption_level * string
    ]
end

module TState = Tls.State

type t = TState.state =
  { handshake : TState.handshake_state
  ; decryptor : TState.crypto_state
  ; encryptor : TState.crypto_state
  ; fragment : string
  ; read_closed : bool
  ; write_closed : bool
  }

type failure = Tls.State.failure

type handled =
  { tls_state : t
  ; tls_packets : State.rec_resp list
  ; was_handshake_in_progress : bool
  }

let ( let* ) = Result.bind

let rec separate_handshakes buf =
  match Tls.Reader.parse_handshake_frame buf with
  | None, rest -> [], rest
  | Some hs, rest ->
    let rt, frag = separate_handshakes rest in
    hs :: rt, frag

let handle_handshake ?embed_quic_transport_params = function
  | TState.Client cs -> Tls.Handshake_client.handle_handshake cs
  | Server ss ->
    Tls.Handshake_server.handle_handshake ?embed_quic_transport_params ss
  | Client13 cs -> Tls.Handshake_client13.handle_handshake cs
  | Server13 ss ->
    Tls.Handshake_server13.handle_handshake ?embed_quic_transport_params ss

let handle_handshake_packet
      (hs : TState.handshake_state)
      ?embed_quic_transport_params
      buf
  =
  let hss, hs_fragment = separate_handshakes (hs.hs_fragment ^ buf) in
  let hs = { hs with hs_fragment } in
  let* hs, items =
    List.fold_left
      (fun (acc :
             ( TState.handshake_state * TState.rec_resp list
             , TState.failure )
             result)
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

let early_data (s : TState.handshake_state) =
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
    in
    let* early_data_left = bytes hs.early_data_left cipher in
    Ok { hs with early_data_left }
  else Ok hs

let guard p e = if p then Ok () else Error e

let to_crypto_state (state : Tls.State.crypto_context) =
  State.{ traffic_secret = state.traffic_secret }

let to_rec_resp : Tls.State.rec_resp -> State.rec_resp = function
  | `Change_enc enc -> `Change_enc (to_crypto_state enc)
  | `Change_dec dec -> `Change_dec (to_crypto_state dec)
  | `Record record -> `Record record

let handle_raw_record ?embed_quic_transport_params state buf =
  let hdr = { Tls.Core.content_type = Tls.Packet.HANDSHAKE; version = `TLS_1_2 } in
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
  let* handshake, items, _data, read_closed =
    handle_handshake_packet handshake ?embed_quic_transport_params buf
  in
  let read_closed = read_closed || state.read_closed in
  let tls_state = { state with handshake; read_closed } in
  Ok
    { tls_state
    ; tls_packets = List.map to_rec_resp items
    ; was_handshake_in_progress = Tls.Engine.handshake_in_progress state
    }

let ciphersuites =
  [ `AES_128_GCM_SHA256
  ; `AES_256_GCM_SHA384
  ; `CHACHA20_POLY1305_SHA256
  ; `AES_128_CCM_SHA256
  ]

let server ~certificates ~alpn_protocols =
  Tls.Engine.server
    (Tls.Config.server
       ~ciphers:ciphersuites
       ~certificates
       ~version:(`TLS_1_3, `TLS_1_3)
       ~alpn_protocols
       ()
    |> Result.get_ok)

let client ?authenticator ~alpn_protocols ~host quic_transport_parameters =
  let authenticator =
    match authenticator with
    | Some authenticator -> authenticator
    | None -> fun ?ip:_ ~host:_ _ -> Ok None
  in
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
  client

let current_cipher t : Tls.Ciphersuite.ciphersuite13 =
  match Tls.Engine.epoch t with
  | Error () ->
    (match t.handshake.machina with
    | Client13
        ( AwaitServerEncryptedExtensions13 (session, _, _, _)
        | AwaitServerCertificateRequestOrCertificate13 (session, _, _, _) ) ->
      session.ciphersuite13
    | _ -> failwith "don't call before handshake bytes")
  | Ok { ciphersuite; _ } ->
    (match ciphersuite with
    | #Tls.Ciphersuite.ciphersuite13 as cs13 -> cs13
    | _ -> assert false)

let transport_params t =
  match Tls.Engine.epoch t with
  | Error () -> None
  | Ok { quic_transport_parameters; _ } -> quic_transport_parameters

let alpn_protocol t =
  match Tls.Engine.epoch t with
  | Error () -> None
  | Ok { alpn_protocol; _ } -> alpn_protocol

let handshake_in_progress = Tls.Engine.handshake_in_progress

let initial_packets t =
  let tls_packets =
    match t.handshake.machina with
    | Client (Tls.State.AwaitServerHello (_, _, [ raw_record ])) ->
      [ `Record (Tls.Packet.HANDSHAKE, raw_record) ]
    | _ -> []
  in
  { tls_state = t; tls_packets; was_handshake_in_progress = handshake_in_progress t }

let alert_of_failure _ failure =
  let _level, alert = Tls.Engine.alert_of_failure failure in
  Tls.Packet.alert_type_to_int alert
