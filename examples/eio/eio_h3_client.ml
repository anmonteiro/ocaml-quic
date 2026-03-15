open Eio.Std
open H3

let now_s () = Unix.gettimeofday ()
let max_data_chunk_size = 16384
let flush_batch_bytes = 256 * 1024

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

let stream_in_channel_to_body ~label ~chunk_size ~ic body =
  let started_at = now_s () in
  let transferred = ref 0L in
  let buf = Bytes.create chunk_size in
  let finished = ref false in
  let finalize () =
    if not !finished
    then (
      finished := true;
      close_in_noerr ic;
      Body.Writer.close body;
      print_transfer_stats ~label ~bytes:!transferred ~started_at)
  in
  let rec pump () =
    let rec fill_batch batched_bytes =
      match input ic buf 0 (Bytes.length buf) with
      | 0 -> `Eof batched_bytes
      | n ->
        Body.Writer.write_string
          body
          ~off:0
          ~len:n
          (Bytes.unsafe_to_string buf);
        transferred := Int64.add !transferred (Int64.of_int n);
        let batched_bytes = batched_bytes + n in
        if batched_bytes >= flush_batch_bytes
        then `Flushed batched_bytes
        else fill_batch batched_bytes
      | exception exn ->
        finalize ();
        raise exn
    in
    match fill_batch 0 with
    | `Eof 0 -> finalize ()
    | `Eof _ -> Body.Writer.flush body finalize
    | `Flushed _ -> Body.Writer.flush body pump
  in
  pump ()

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
  let max_dgram_size = ref Quic.Config.default_max_datagram_size in
  let udp_connect = ref true in
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
    ; ( "-max-dgram-size"
      , Arg.Set_int max_dgram_size
      , " Max QUIC datagram size override for benchmarking (default 1200)" )
    ; "-udp-connect", Arg.Set udp_connect, " Connect the underlying UDP socket to the peer"
    ; ( "-no-udp-connect"
      , Arg.Clear udp_connect
      , " Do not connect the underlying UDP socket to the peer" )
    ]
    (fun host_argument -> host := Some host_argument)
    "eio_h3_client.exe [-p N] [-download OUT | -upload FILE] [-path PATH] HOST";
  if !chunk_size <= 0 || !chunk_size > max_data_chunk_size
  then
    failwith
      (Printf.sprintf
         "-chunk-size must be in 1..%d to fit within QUIC datagrams"
         max_data_chunk_size);
  if !max_dgram_size < Quic.Config.default_max_datagram_size
  then failwith "-max-dgram-size must be >= 1200";
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
    ; max_datagram_size = !max_dgram_size
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
        Quic_eio.Client.create
          env
          ~sw
          ~udp_connect:!udp_connect
          ~config
          (fun ~cid:_ ~start_stream:_ ->
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
        let ic = open_in_bin input_path in
        stream_in_channel_to_body
          ~label:("client queued upload " ^ Filename.basename input_path)
          ~chunk_size:!chunk_size
          ~ic
          request_body
      | Print | Download _ -> Body.Writer.close request_body);

      Eio.Promise.await done_p))
