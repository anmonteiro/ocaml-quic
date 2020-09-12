open Lwt.Infix

let stream_handler stream =
  let rec on_read bs ~off ~len =
    Format.eprintf "GOT DATA: %S@." (Bigstringaf.substring bs ~off ~len);
    Quic.Stream.schedule_read stream ~on_read ~on_eof
  and on_eof () =
    Format.eprintf "Got EOF@.";
    Quic.Stream.write_string stream "HTTP/0.9 200 OK\r\n";
    Quic.Stream.close_writer stream
  in
  Quic.Stream.schedule_read stream ~on_read ~on_eof

let () =
  Mirage_crypto_rng_unix.initialize ();
  Sys.(set_signal sigpipe Signal_ignore);
  let port = ref 8080 in
  Arg.parse
    [ "-p", Arg.Set_int port, " Listening port number (8080 by default)" ]
    ignore
    "Echoes POST requests. Runs forever.";
  let listen_address = Unix.(ADDR_INET (inet_addr_loopback, !port)) in
  Lwt.async (fun () ->
      Quic_lwt.Server.establish_server listen_address stream_handler
      >>= fun () ->
      Printf.printf "Listening on port %i and echoing POST requests.\n" !port;
      flush stdout;
      Lwt.return_unit);
  let forever, _ = Lwt.wait () in
  Lwt_main.run forever
