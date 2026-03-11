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

type t =
  { ssl : Ssl.socket
  ; mutable peer_transport_params : string option
  ; mutable local_transport_params_set : bool
  }

type failure =
  { alert : int option
  ; message : string
  }

type handled =
  { tls_state : t
  ; tls_packets : State.rec_resp list
  ; was_handshake_in_progress : bool
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
  | 0 -> State.Initial
  | 1 -> State.Zero_RTT
  | 2 -> State.Handshake
  | 3 -> State.Application_data
  | level -> failwith ("unknown OpenSSL QUIC protection level: " ^ string_of_int level)

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
  | proto :: rest -> if List.mem proto available then Some proto else first_supported ~available rest

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
           Ssl.add_extra_chain_cert ctx (X509.Certificate.encode_pem certificate))
        extras)
  | `Multiple ((chain, priv) :: _) -> configure_certificates ctx (`Single (chain, priv))
  | `Multiple [] -> invalid_arg "Qtls.server requires certificates"
  | `Multiple_default ((chain, priv), _) -> configure_certificates ctx (`Single (chain, priv))

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
  { tls_state = t; tls_packets = drain_packets t; was_handshake_in_progress }

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

let client ?authenticator:_ ~alpn_protocols ~host quic_transport_parameters =
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
  try Ok (consume_result t ~was_handshake_in_progress:(run_step t; was_handshake_in_progress)) with
  | exn -> Error (make_failure t exn)

let transport_params t = t.peer_transport_params
let alpn_protocol t = Ssl.get_negotiated_alpn_protocol t.ssl
let initial_packets t = consume_result t ~was_handshake_in_progress:(handshake_in_progress t)

let alert_of_failure t failure =
  match failure.alert with
  | Some alert -> alert
  | None ->
    (match Ssl.quic_take_alert t.ssl with
    | Some alert -> alert
    | None -> Tls.Packet.alert_type_to_int (Tls.Packet.UNKNOWN 80))
