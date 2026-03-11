open Eio.Std
open H3

let now_s () = Unix.gettimeofday ()
let max_data_chunk_size = 1024

let print_transfer_stats ~label ~bytes ~started_at =
  let duration_s = max 1e-6 (now_s () -. started_at) in
  let mib_per_s = (Int64.to_float bytes /. (1024. *. 1024.)) /. duration_s in
  let mbps = (Int64.to_float bytes *. 8. /. 1_000_000.) /. duration_s in
  Format.eprintf
    "%s: bytes=%Ld duration=%.3fs throughput=%.2f MiB/s (%.2f Mbit/s)@."
    label
    bytes
    duration_s
    mib_per_s
    mbps

type mode =
  | Print
  | Download of string
  | Upload of string

let error_handler : H3.Client_connection.error_handler = function
  | `Protocol_error (_e, msg) -> Format.eprintf "error: %s@." msg
  | _ -> assert false

let response_handler
      ~mode
      ~upload_started_at
      ~upload_size
      ~done_u
      ~shutdown
      response
      response_body
  =
  Format.eprintf "Response: %a@." Response.pp_hum response;
  match mode with
  | Upload _ ->
    (match !upload_started_at with
    | Some started_at ->
      print_transfer_stats
        ~label:"client upload e2e"
        ~bytes:!upload_size
        ~started_at
    | None -> ());
    Eio.Promise.resolve done_u ();
    shutdown ()
  | Print | Download _ ->
  let started_at = now_s () in
  let received = ref 0L in
  let expected_len =
    match Response.body_length response with
    | `Fixed len -> Some len
    | `Unknown | `Error _ -> None
  in
  let oc =
    match mode with
    | Download out_path -> Some (open_out_bin out_path)
    | Print | Upload _ -> None
  in
  let finished = ref false in
  let finalize () =
    if not !finished
    then (
      finished := true;
      Option.iter close_out_noerr oc;
      print_transfer_stats
        ~label:"client recv response"
        ~bytes:!received
        ~started_at;
      Eio.Promise.resolve done_u ();
      shutdown ())
  in
  let rec read_response () =
    Body.Reader.schedule_read
      response_body
      ~on_eof:(fun () -> finalize ())
      ~on_read:(fun bigstring ~off ~len ->
        (match oc with
        | Some oc ->
          output_string oc (Bigstringaf.substring bigstring ~off ~len)
        | None ->
          let response_fragment = Bytes.create len in
          Bigstringaf.blit_to_bytes
            bigstring
            ~src_off:off
            response_fragment
            ~dst_off:0
            ~len;
          Format.printf "%s@." (Bytes.to_string response_fragment));
        received := Int64.add !received (Int64.of_int len);
        match expected_len with
        | Some expected when Int64.compare !received expected >= 0 ->
          finalize ()
        | _ -> read_response ())
  in
  read_response ()

let () =
  Mirage_crypto_rng_unix.use_default ();
  Sys.(set_signal sigpipe Signal_ignore);
  let host = ref None in
  let port = ref 4433 in
  let download = ref None in
  let upload = ref None in
  let path = ref None in
  let chunk_size = ref max_data_chunk_size in
  Arg.parse
    [ "-p", Arg.Set_int port, " Port number (4433 by default)"
    ; ( "-download"
      , Arg.String (fun p -> download := Some p)
      , " Download response body to this file"
      )
    ; ( "-upload"
      , Arg.String (fun p -> upload := Some p)
      , " Upload this file as POST body"
      )
    ; "-path", Arg.String (fun p -> path := Some p), " Request path"
    ; ( "-chunk-size"
      , Arg.Set_int chunk_size
      , Printf.sprintf
          " File transfer chunk size in bytes (max %d)"
          max_data_chunk_size
      )
    ]
    (fun host_argument -> host := Some host_argument)
    "eio_h3_client.exe [-p N] [-download OUT | -upload FILE] [-path PATH] HOST";
  if !chunk_size <= 0 || !chunk_size > max_data_chunk_size
  then
    failwith
      (Printf.sprintf
         "-chunk-size must be in 1..%d to fit within QUIC datagrams"
         max_data_chunk_size);
  let host =
    match !host with
    | None -> failwith "No hostname provided"
    | Some host -> host
  in
  let mode =
    match !download, !upload with
    | Some _, Some _ -> failwith "Use only one of -download or -upload"
    | Some out_path, None -> Download out_path
    | None, Some in_path -> Upload in_path
    | None, None -> Print
  in
  let target =
    match !path with
    | Some p -> p
    | None ->
      (match mode with
      | Download _ -> "/file"
      | Upload _ -> "/upload"
      | Print -> "/")
  in
  let certificates =
    let cert = "./certificates/server.pem" in
    let priv_key = "./certificates/server.key" in
    `Single (Qx509.private_of_pems ~cert ~priv_key)
  in
  let config =
    { Quic.Config.certificates
    ; alpn_protocols = [ "h3" ]
    ; transport_parameters = Quic.Config.default_transport_parameters
    }
  in
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
          F (fun _stream -> assert false))
      in
      Quic_eio.connect t ~address ~host (fun ~cid ~start_stream ->
        let conn, stream_handler =
          H3.Client_connection.create ~error_handler ~cid ~start_stream
        in
        Promise.resolve client_u conn;
        stream_handler);
      let client = Eio.Promise.await client_p in
      let done_p, done_u = Eio.Promise.create () in
      let upload_started_at = ref None in
      let upload_size = ref 0L in

      let request_method = match mode with Upload _ -> `POST | _ -> `GET in
      let headers =
        match mode with
        | Upload input_path ->
          let stat = Unix.stat input_path in
          Headers.add_list
            Headers.empty
            [ "content-type", "application/octet-stream"
            ; "content-length", string_of_int stat.Unix.st_size
            ; ":authority", host
            ]
        | Print | Download _ ->
          Headers.add_list Headers.empty [ ":authority", host ]
      in
      let request =
        H3.Request.create ~scheme:"https" ~headers request_method target
      in
      let request_body =
        H3.Client_connection.request
          client
          request
          ~error_handler
          ~response_handler:
            (response_handler
               ~mode
               ~upload_started_at
               ~upload_size
               ~done_u
               ~shutdown:(fun () -> Quic_eio.shutdown t))
      in

      (match mode with
      | Upload input_path ->
        upload_started_at := Some (now_s ());
        upload_size := Int64.of_int (Unix.stat input_path).Unix.st_size;
        let started_at = now_s () in
        let sent = ref 0L in
        let ic = open_in_bin input_path in
        Fun.protect
          ~finally:(fun () ->
            close_in_noerr ic;
            Body.Writer.close request_body;
            print_transfer_stats
              ~label:("client queued upload " ^ Filename.basename input_path)
              ~bytes:!sent
              ~started_at)
          (fun () ->
            let buf = Bytes.create !chunk_size in
            let chunks_since_flush = ref 0 in
            let rec loop () =
              let n = input ic buf 0 (Bytes.length buf) in
              if n > 0
              then (
                Body.Writer.write_string
                  request_body
                  ~off:0
                  ~len:n
                  (Bytes.unsafe_to_string buf);
                incr chunks_since_flush;
                if !chunks_since_flush >= 32
                then (
                  Body.Writer.flush request_body ignore;
                  chunks_since_flush := 0);
                sent := Int64.add !sent (Int64.of_int n);
                loop ())
            in
            loop ();
            if !chunks_since_flush > 0 then Body.Writer.flush request_body ignore)
      | Print | Download _ -> Body.Writer.close request_body);
      Eio.Promise.await done_p))
