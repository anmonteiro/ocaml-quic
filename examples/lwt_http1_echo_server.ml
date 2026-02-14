open Lwt.Infix

let stream_handler ~cid:_ ~start_stream:_ =
  Quic.Transport.F
    (fun stream ->
      let rec on_read bs ~off ~len =
        Format.eprintf "GOT DATA: %S@." (Bigstringaf.substring bs ~off ~len);
        Quic.Stream.schedule_read stream ~on_read ~on_eof
      and on_eof () =
        Format.eprintf "Got EOF@.";
        Quic.Stream.write_string stream "HTTP/0.9 200 OK\r\n";
        Quic.Stream.close_writer stream
      in
      Quic.Stream.schedule_read stream ~on_read ~on_eof;
      { Quic.Transport.on_error = ignore })

let () =
  Mirage_crypto_rng_unix.use_default ();
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
  let config = { Quic.Config.certificates; alpn_protocols = [ "http/0.9" ] } in
  Lwt.async (fun () ->
    Quic_lwt.Server.establish_server ~config listen_address stream_handler
    >>= fun () ->
    Printf.printf "Listening on port %i and echoing POST requests.\n" !port;
    flush stdout;
    Lwt.return_unit);
  let forever, _ = Lwt.wait () in
  Lwt_main.run forever
