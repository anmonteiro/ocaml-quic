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
  Mirage_crypto_rng_unix.initialize ();
  Sys.(set_signal sigpipe Signal_ignore);
  let port = ref 4433 in
  Arg.parse
    [ "-p", Arg.Set_int port, " Listening port number (4433 by default)" ]
    ignore
    "Echoes POST requests. Runs forever.";
  let listen_address = `Udp (Eio.Net.Ipaddr.V4.any, !port) in
  let certificates =
    let cert = "./certificates/server.pem" in
    let priv_key = "./certificates/server.key" in
    `Single (Qx509.private_of_pems ~cert ~priv_key)
  in
  let config = { Quic.Config.certificates; alpn_protocols = [ "h3" ] } in
  Eio_main.run (fun env ->
      Eio.Switch.run (fun sw ->
          (* let forever, _ = Eio.Promise.create () in *)
          Quic_eio.Server.establish_server
            env
            ~sw
            ~config
            listen_address
            (connection_handler (Eio.Stdenv.clock env))))
