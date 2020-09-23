open Lwt.Infix
open H3

let set_interval s f =
  let timeout = Lwt_timeout.create s f in
  Lwt_timeout.start timeout

let connection_handler =
  let request_handler reqd =
    let request = Reqd.request reqd in
    Format.eprintf "Request: %a@." Request.pp_hum request;
    let response = Response.create `OK in
    match request.Request.target with
    | "/streaming" ->
      let response_body = Reqd.respond_with_streaming reqd response in
      Body.write_string response_body "hello, ";
      set_interval 1 (fun () ->
          Body.write_string response_body "world.";
          Body.flush response_body (fun () -> Body.close_writer response_body))
    | _ ->
      Reqd.respond_with_string reqd response "hello"
  in
  H3.Server_connection.create request_handler

let () =
  Mirage_crypto_rng_unix.initialize ();
  Sys.(set_signal sigpipe Signal_ignore);
  let port = ref 8080 in
  Arg.parse
    [ "-p", Arg.Set_int port, " Listening port number (8080 by default)" ]
    ignore
    "Echoes POST requests. Runs forever.";
  let listen_address = Unix.(ADDR_INET (inet_addr_loopback, !port)) in
  let certificates =
    let cert = "./certificates/server.pem" in
    let priv_key = "./certificates/server.key" in
    `Single (Qx509.private_of_pems ~cert ~priv_key)
  in
  let config =
    { Quic.Config.certificates; alpn_protocols = [ "h3"; "h3-30"; "h3-29" ] }
  in
  Lwt.async (fun () ->
      Quic_lwt.Server.establish_server ~config listen_address connection_handler
      >>= fun () ->
      Printf.printf "Listening on port %i and echoing POST requests.\n" !port;
      flush stdout;
      Lwt.return_unit);
  let forever, _ = Lwt.wait () in
  Lwt_main.run forever
