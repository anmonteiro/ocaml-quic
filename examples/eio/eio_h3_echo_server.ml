open H3

let set_interval ~clock ~f s =
  Eio.Time.sleep clock s;
  f ()

let connection_handler clock =
  let request_handler reqd =
    let request = Reqd.request reqd in
    Format.eprintf "Request: %a@." Request.pp_hum request;
    let response = Response.create `OK in
    match request.Request.target with
    | "/streaming" ->
      let response_body = Reqd.respond_with_streaming reqd response in
      Body.Writer.write_string response_body "hello, ";
      set_interval ~clock 1. ~f:(fun () ->
        Body.Writer.write_string response_body "world.";
        Body.Writer.flush response_body (fun () ->
          Body.Writer.close response_body))
    | _ -> Reqd.respond_with_string reqd response "hello"
  in
  H3.Server_connection.create request_handler

let () =
  Printexc.record_backtrace true;
  Mirage_crypto_rng_unix.use_default ();
  Sys.(set_signal sigpipe Signal_ignore);
  let port = ref 4433 in
  let drop_recv_pct = ref 0.0 in
  let drop_send_pct = ref 0.0 in
  let drop_handshake = ref false in
  let drop_seed = ref 42 in
  Arg.parse
    [ "-p", Arg.Set_int port, " Listening port number (4433 by default)"
    ; ( "-drop-recv-pct"
      , Arg.Set_float drop_recv_pct
      , " Drop percentage for received UDP datagrams (0.0-100.0, default 0.0)"
      )
    ; ( "-drop-handshake"
      , Arg.Set drop_handshake
      , " Also drop Initial/Handshake packets (default: false)"
      )
    ; ( "-drop-send-pct"
      , Arg.Set_float drop_send_pct
      , " Drop percentage for sent UDP datagrams (0.0-100.0, default 0.0)"
      )
    ; "-drop-seed", Arg.Set_int drop_seed, " RNG seed for drop decisions (default 42)"
    ]
    ignore
    "Echoes POST requests. Runs forever.";
  if !drop_recv_pct < 0.0 || !drop_recv_pct > 100.0
  then failwith "-drop-recv-pct must be between 0.0 and 100.0";
  if !drop_send_pct < 0.0 || !drop_send_pct > 100.0
  then failwith "-drop-send-pct must be between 0.0 and 100.0";
  let listen_address = `Udp (Eio.Net.Ipaddr.V4.any, !port) in
  let certificates =
    let cert = "./certificates/server.pem" in
    let priv_key = "./certificates/server.key" in
    `Single (Qx509.private_of_pems ~cert ~priv_key)
  in
  let config = { Quic.Config.certificates; alpn_protocols = [ "h3" ] } in
  let rng = Random.State.make [| !drop_seed |] in
  let should_drop ~direction ~packet_kind ~seq_no ~len =
    let pct =
      match direction with
      | `Receive -> !drop_recv_pct
      | `Send -> !drop_send_pct
    in
    let can_drop =
      match packet_kind with
      | (`Initial | `Handshake) when not !drop_handshake -> false
      | _ -> true
    in
    let drop = can_drop && Random.State.float rng 100.0 < pct in
    (match direction with
    | `Receive ->
      if drop
      then
        Format.eprintf
          "dropping recv datagram seq=%d len=%d kind=%s@."
          seq_no
          len
          (match packet_kind with
          | `Initial -> "initial"
          | `Zero_rtt -> "0rtt"
          | `Handshake -> "handshake"
          | `Retry -> "retry"
          | `Short -> "short"
          | `Unknown -> "unknown");
      drop
    | `Send ->
      if drop
      then
        Format.eprintf
          "dropping send datagram seq=%d len=%d kind=%s@."
          seq_no
          len
          (match packet_kind with
          | `Initial -> "initial"
          | `Zero_rtt -> "0rtt"
          | `Handshake -> "handshake"
          | `Retry -> "retry"
          | `Short -> "short"
          | `Unknown -> "unknown");
      drop)
  in
  Format.eprintf
    "listening on UDP %d (drop_recv_pct=%.2f drop_send_pct=%.2f drop_handshake=%b seed=%d)@."
    !port
    !drop_recv_pct
    !drop_send_pct
    !drop_handshake
    !drop_seed;
  Eio_main.run (fun env ->
    Eio.Switch.run (fun sw ->
      let handler = connection_handler (Eio.Stdenv.clock env) in
      Eio.Fiber.both
        (fun () ->
           Quic_eio.Server.establish_server
             env
             ~sw
             ~should_drop
             ~config
             listen_address
             handler)
        (fun () ->
           let listen_address_v6 = `Udp (Eio.Net.Ipaddr.V6.any, !port) in
           try
             Quic_eio.Server.establish_server
               env
               ~sw
               ~should_drop
               ~config
               listen_address_v6
               handler
           with exn ->
             Format.eprintf "IPv6 listener disabled: %s@." (Printexc.to_string exn))))
