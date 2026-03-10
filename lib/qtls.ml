module State = struct
  type crypto_state = { traffic_secret : string }

  type rec_resp =
    [ `Change_enc of crypto_state
    | `Change_dec of crypto_state
    | `Record of Tls.Packet.content_type * string
    | `Level_change_enc of Encryption_level.level * crypto_state
    | `Level_change_dec of Encryption_level.level * crypto_state
    | `Level_record of Encryption_level.level * string
    ]
end

type backend =
  [ `OpenSSL
  | `Ocaml_tls
  ]

(* let backend : backend ref = ref `OpenSSL *)
let backend : backend ref = ref `Ocaml_tls

type openssl_failure =
  { alert : int option
  ; message : string
  }

type failure =
  [ `Ocaml_tls of Tls.State.failure
  | `OpenSSL of openssl_failure
  ]

module Ocaml_tls_backend = struct
  module TState = Tls.State

  type t = TState.state =
    { handshake : TState.handshake_state
    ; decryptor : TState.crypto_state
    ; encryptor : TState.crypto_state
    ; fragment : string
    ; read_closed : bool
    ; write_closed : bool
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
    let* handshake, items, _data, read_closed =
      handle_handshake_packet handshake ?embed_quic_transport_params buf
    in
    let read_closed = read_closed || state.read_closed in
    let tls_state = { state with handshake; read_closed } in
    Ok
      ( tls_state
      , List.map to_rec_resp items
      , Tls.Engine.handshake_in_progress state )

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
             (Domain_name.of_string host
             |> Result.get_ok
             |> Domain_name.host_exn)
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
    t, tls_packets, handshake_in_progress t

  let alert_of_failure failure =
    let _level, alert = Tls.Engine.alert_of_failure failure in
    Tls.Packet.alert_type_to_int alert
end

module OpenSSL_backend = struct
  type t =
    { ssl : Ssl.socket
    ; mutable peer_transport_params : string option
    ; mutable local_transport_params_set : bool
    }

  let make_failure t exn =
    let alert = Ssl.quic_take_alert t.ssl in
    let message =
      match exn with
      | Ssl.Connection_error _ | Ssl.Accept_error _ | Ssl.Read_error _ ->
        let err = Ssl.Error.peek_error () in
        let lib = Option.value ~default:"ssl" err.Ssl.Error.lib in
        let reason = Option.value ~default:"unknown" err.Ssl.Error.reason in
        lib ^ ": " ^ reason
      | _ -> Printexc.to_string exn
    in
    { alert; message }

  let current_cipher t : Tls.Ciphersuite.ciphersuite13 =
    match Ssl.get_cipher t.ssl |> Ssl.get_cipher_name with
    | "TLS_AES_128_GCM_SHA256" -> `AES_128_GCM_SHA256
    | "TLS_AES_256_GCM_SHA384" -> `AES_256_GCM_SHA384
    | "TLS_CHACHA20_POLY1305_SHA256" -> `CHACHA20_POLY1305_SHA256
    | "TLS_AES_128_CCM_SHA256" -> `AES_128_CCM_SHA256
    | cipher -> failwith ("unsupported TLS 1.3 cipher: " ^ cipher)

  let encryption_level_of_ossl = function
    | 0 -> Encryption_level.Initial
    | 1 -> Encryption_level.Zero_RTT
    | 2 -> Encryption_level.Handshake
    | 3 -> Encryption_level.Application_data
    | level ->
      failwith ("unknown OpenSSL QUIC protection level: " ^ string_of_int level)

  let drain_packets t =
    Ssl.quic_drain_events t.ssl
    |> List.map (fun (kind, level, is_write, payload) ->
      let level = encryption_level_of_ossl level in
      match kind with
      | 0 -> `Level_record (level, payload)
      | 1 ->
        let secret = State.{ traffic_secret = payload } in
        if is_write
        then `Level_change_enc (level, secret)
        else `Level_change_dec (level, secret)
      | _ -> failwith "unknown QUIC TLS event")

  let make_context context_type =
    let ctx = Ssl.create_context Ssl.TLSv1_3 context_type in
    Ssl.set_min_protocol_version ctx Ssl.TLSv1_3;
    Ssl.set_max_protocol_version ctx Ssl.TLSv1_3;
    ctx

  let rec first_supported ~available = function
    | [] -> None
    | proto :: rest ->
      if List.mem proto available
      then Some proto
      else first_supported ~available rest

  let rec configure_certificates ctx : Tls.Config.own_cert -> unit = function
    | `None -> invalid_arg "Qtls.server requires certificates"
    | `Single (chain, priv) ->
      (match chain with
      | [] -> invalid_arg "Qtls.server requires a non-empty certificate chain"
      | cert :: extras ->
        Ssl.use_certificate_from_string
          ctx
          (X509.Certificate.encode_pem cert)
          (X509.Private_key.encode_pem priv);
        List.iter
          (fun certificate ->
             Ssl.add_extra_chain_cert
               ctx
               (X509.Certificate.encode_pem certificate))
          extras)
    | `Multiple ((chain, priv) :: _) ->
      configure_certificates ctx (`Single (chain, priv))
    | `Multiple [] -> invalid_arg "Qtls.server requires certificates"
    | `Multiple_default ((chain, priv), _) ->
      configure_certificates ctx (`Single (chain, priv))

  let create_socket ctx =
    let ssl = Ssl.create_socket ctx in
    Ssl.quic_configure ssl;
    { ssl; peer_transport_params = None; local_transport_params_set = false }

  let ensure_local_transport_params ?embed_quic_transport_params t =
    if not t.local_transport_params_set
    then
      match embed_quic_transport_params with
      | None -> ()
      | Some f ->
        (match f t.peer_transport_params with
        | None -> ()
        | Some params ->
          Ssl.quic_set_transport_params t.ssl params;
          t.local_transport_params_set <- true)

  let consume_result t ~was_handshake_in_progress =
    t.peer_transport_params <- Ssl.quic_get_peer_transport_params t.ssl;
    t, drain_packets t, was_handshake_in_progress

  let handshake_in_progress t = Ssl.quic_handshake_in_progress t.ssl

  let run_step t =
    if handshake_in_progress t
    then ignore (Ssl.quic_do_handshake t.ssl)
    else ignore (Ssl.quic_process_post_handshake t.ssl)

  let server ~certificates ~alpn_protocols =
    let ctx = make_context Ssl.Server_context in
    configure_certificates ctx certificates;
    Ssl.set_context_alpn_select_callback ctx (fun available ->
      first_supported ~available alpn_protocols);
    let t = create_socket ctx in
    Ssl.set_accept_state t.ssl;
    t

  let client ~authenticator:_ ~alpn_protocols ~host quic_transport_parameters =
    let ctx = make_context Ssl.Client_context in
    let t = create_socket ctx in
    Ssl.set_alpn_protos t.ssl alpn_protocols;
    Ssl.set_client_SNI_hostname t.ssl host;
    Ssl.quic_set_transport_params t.ssl quic_transport_parameters;
    t.local_transport_params_set <- true;
    Ssl.set_connect_state t.ssl;
    (try run_step t with exn -> raise (Failure (make_failure t exn).message));
    t

  let handle_raw_record ?embed_quic_transport_params t buf =
    let was_handshake_in_progress = handshake_in_progress t in
    ensure_local_transport_params ?embed_quic_transport_params t;
    Ssl.quic_provide_crypto_data t.ssl buf;
    try
      run_step t;
      Ok (consume_result t ~was_handshake_in_progress)
    with
    | exn -> Error (`OpenSSL (make_failure t exn))

  let initial_packets t =
    let was_handshake_in_progress = handshake_in_progress t in
    consume_result t ~was_handshake_in_progress

  let transport_params t = t.peer_transport_params
  let alpn_protocol t = Ssl.get_negotiated_alpn_protocol t.ssl

  let alert_of_failure t failure =
    match failure.alert with
    | Some alert -> alert
    | None ->
      (match Ssl.quic_take_alert t.ssl with
      | Some alert -> alert
      | None -> Tls.Packet.alert_type_to_int (Tls.Packet.UNKNOWN 80))
end

type t =
  | OpenSSL of OpenSSL_backend.t
  | Ocaml_tls of Ocaml_tls_backend.t

type handled =
  { tls_state : t
  ; tls_packets : State.rec_resp list
  ; was_handshake_in_progress : bool
  }

let server ~certificates ~alpn_protocols =
  match !backend with
  | `OpenSSL -> OpenSSL (OpenSSL_backend.server ~certificates ~alpn_protocols)
  | `Ocaml_tls ->
    Ocaml_tls (Ocaml_tls_backend.server ~certificates ~alpn_protocols)

let client ~authenticator ~alpn_protocols ~host quic_transport_parameters =
  match !backend with
  | `OpenSSL ->
    OpenSSL
      (OpenSSL_backend.client
         ~authenticator
         ~alpn_protocols
         ~host
         quic_transport_parameters)
  | `Ocaml_tls ->
    Ocaml_tls
      (Ocaml_tls_backend.client
         ~authenticator
         ~alpn_protocols
         ~host
         quic_transport_parameters)

let handle_raw_record ?embed_quic_transport_params t buf =
  match t with
  | OpenSSL t ->
    (match
       OpenSSL_backend.handle_raw_record ?embed_quic_transport_params t buf
     with
    | Ok (tls_state, tls_packets, was_handshake_in_progress) ->
      Ok
        { tls_state = OpenSSL tls_state
        ; tls_packets
        ; was_handshake_in_progress
        }
    | Error _ as err -> err)
  | Ocaml_tls t ->
    (match
       Ocaml_tls_backend.handle_raw_record ?embed_quic_transport_params t buf
     with
    | Ok (tls_state, tls_packets, was_handshake_in_progress) ->
      Ok
        { tls_state = Ocaml_tls tls_state
        ; tls_packets
        ; was_handshake_in_progress
        }
    | Error failure -> Error (`Ocaml_tls failure))

let current_cipher = function
  | OpenSSL t -> OpenSSL_backend.current_cipher t
  | Ocaml_tls t -> Ocaml_tls_backend.current_cipher t

let transport_params = function
  | OpenSSL t -> OpenSSL_backend.transport_params t
  | Ocaml_tls t -> Ocaml_tls_backend.transport_params t

let alpn_protocol = function
  | OpenSSL t -> OpenSSL_backend.alpn_protocol t
  | Ocaml_tls t -> Ocaml_tls_backend.alpn_protocol t

let handshake_in_progress = function
  | OpenSSL t -> OpenSSL_backend.handshake_in_progress t
  | Ocaml_tls t -> Ocaml_tls_backend.handshake_in_progress t

let initial_packets = function
  | OpenSSL t ->
    let tls_state, tls_packets, was_handshake_in_progress =
      OpenSSL_backend.initial_packets t
    in
    { tls_state = OpenSSL tls_state; tls_packets; was_handshake_in_progress }
  | Ocaml_tls t ->
    let tls_state, tls_packets, was_handshake_in_progress =
      Ocaml_tls_backend.initial_packets t
    in
    { tls_state = Ocaml_tls tls_state; tls_packets; was_handshake_in_progress }

let alert_of_failure t = function
  | `Ocaml_tls failure -> Ocaml_tls_backend.alert_of_failure failure
  | `OpenSSL failure ->
    (match t with
    | OpenSSL t -> OpenSSL_backend.alert_of_failure t failure
    | Ocaml_tls _ -> Tls.Packet.alert_type_to_int (Tls.Packet.UNKNOWN 80))
