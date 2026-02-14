open Eio.Std
open H3

let set_interval ~clock ~f s =
  Eio.Time.sleep clock s;
  f ()

let error_handler : H3.Client_connection.error_handler = function
  | `Protocol_error (_e, msg) -> Format.eprintf "error: %s@." msg
  | _ -> assert false

let response_handler ~on_eof response response_body =
  Format.eprintf "Response: %a@." Response.pp_hum response;

  let rec read_response () =
    Body.Reader.schedule_read
      response_body
      ~on_eof
      ~on_read:(fun bigstring ~off ~len ->
        let response_fragment = Bytes.create len in
        Bigstringaf.blit_to_bytes
          bigstring
          ~src_off:off
          response_fragment
          ~dst_off:0
          ~len;
        Format.printf "%s@." (Bytes.to_string response_fragment);
        read_response ())
  in
  read_response ()

let () =
  Mirage_crypto_rng_unix.use_default ();
  Sys.(set_signal sigpipe Signal_ignore);
  let host = ref None in
  let port = ref 4433 in
  Arg.parse
    [ "-p", Set_int port, " Port number (4433 by default)" ]
    (fun host_argument -> host := Some host_argument)
    "eio_h3_client.exe [-p N] HOST";
  let host =
    match !host with
    | None -> failwith "No hostname provided"
    | Some host -> host
  in
  let certificates =
    let cert = "./certificates/server.pem" in
    let priv_key = "./certificates/server.key" in
    `Single (Qx509.private_of_pems ~cert ~priv_key)
  in
  let config = { Quic.Config.certificates; alpn_protocols = [ "h3" ] } in
  Eio_main.run (fun env ->
    Eio.Switch.run (fun sw ->
      let addrs =
        let addrs =
          Eio_unix.run_in_systhread (fun () ->
            Unix.getaddrinfo
              host
              (string_of_int !port)
              [ Unix.(AI_FAMILY PF_INET) ])
        in
        List.filter_map
          (fun (addr : Unix.addr_info) ->
             match addr.ai_addr with
             | Unix.ADDR_UNIX _ -> None
             | ADDR_INET (addr, port) -> Some (addr, port))
          addrs
      in
      let address =
        let inet, port = List.hd addrs in
        `Udp (Eio_unix.Net.Ipaddr.of_unix inet, port)
      in

      let client_p, client_u = Eio.Promise.create () in
      let t =
        Quic_eio.Client.create env ~sw ~config (fun ~cid:_ ~start_stream:_ ->
          ();
          F (fun _stream -> assert false))
      in
      Quic_eio.connect t ~address ~host (fun ~cid ~start_stream ->
        let conn, stream_handler =
          H3.Client_connection.create ~error_handler ~cid ~start_stream
        in
        Promise.resolve client_u conn;
        stream_handler);
      let client = Eio.Promise.await client_p in
      let request =
        H3.Request.create
          ~scheme:"https"
          ~headers:Headers.(add_list empty [ ":authority", host ])
          `GET
          "/"
      in
      let _request_body =
        H3.Client_connection.request
          client
          request
          ~error_handler
          ~response_handler:
            (response_handler ~on_eof:(fun () ->
               Format.eprintf "eof@.";
               Quic_eio.shutdown t))
      in
      (* Body.Writer.close request_body *)
      ()))
