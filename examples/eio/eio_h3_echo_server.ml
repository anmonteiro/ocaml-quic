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

let set_interval ~clock ~f s =
  Eio.Time.sleep clock s;
  f ()

let connection_handler clock ~serve_file ~upload_out ~chunk_size =
  let request_handler reqd =
    let request = Reqd.request reqd in
    Format.eprintf "Request: %a@." Request.pp_hum request;
    match request.Request.meth, request.Request.target with
    | `GET, "/file" ->
      (match serve_file with
      | None ->
        Reqd.respond_with_string
          reqd
          (Response.create `Not_found)
          "server was not started with -serve-file"
      | Some path ->
        let stat = Unix.stat path in
        let headers =
          Headers.add_list
            Headers.empty
            [ "content-type", "application/octet-stream"
            ; "content-length", string_of_int stat.Unix.st_size
            ]
        in
        let response = Response.create ~headers `OK in
        let response_body = Reqd.respond_with_streaming reqd response in
        let started_at = now_s () in
        let sent_bytes = ref 0L in
        let ic = open_in_bin path in
        Fun.protect
          ~finally:(fun () ->
            close_in_noerr ic;
            Body.Writer.close response_body;
            print_transfer_stats
              ~label:("server send " ^ Filename.basename path)
              ~bytes:!sent_bytes
              ~started_at)
          (fun () ->
            let buf = Bytes.create chunk_size in
            let chunks_since_flush = ref 0 in
            let rec loop () =
              let n = input ic buf 0 (Bytes.length buf) in
              if n > 0
              then (
                let chunk = Bytes.sub_string buf 0 n in
                let b = Bigstringaf.of_string ~off:0 ~len:n chunk in
                Body.Writer.schedule_bigstring response_body b;
                incr chunks_since_flush;
                if !chunks_since_flush >= 32
                then (
                  Body.Writer.flush response_body ignore;
                  chunks_since_flush := 0);
                sent_bytes := Int64.add !sent_bytes (Int64.of_int n);
                loop ())
            in
            loop ();
            if !chunks_since_flush > 0 then Body.Writer.flush response_body ignore))
    | `POST, "/upload" ->
      let request_body = Reqd.request_body reqd in
      let expected_len =
        match Request.body_length request with
        | `Fixed len -> Some len
        | `Unknown | `Error _ -> None
      in
      let started_at = now_s () in
      let received_bytes = ref 0L in
      let progress_step_pct = 5 in
      let next_progress_pct = ref progress_step_pct in
      let oc = Option.map open_out_bin upload_out in
      let finished = ref false in
      let report_progress () =
        match expected_len with
        | Some expected when expected > 0L ->
          let pct =
            min 100 (Int64.to_int (Int64.div (Int64.mul !received_bytes 100L) expected))
          in
          while !next_progress_pct <= pct do
            Format.eprintf
              "upload progress: %d%% (%Ld/%Ld bytes)@."
              !next_progress_pct
              !received_bytes
              expected;
            next_progress_pct := !next_progress_pct + progress_step_pct
          done
        | _ -> ()
      in
      let finalize () =
        if not !finished
        then (
          finished := true;
          report_progress ();
          Option.iter close_out_noerr oc;
          Body.Reader.close request_body;
          print_transfer_stats
            ~label:"server recv upload"
            ~bytes:!received_bytes
            ~started_at;
          let response = Response.create `OK in
          Reqd.respond_with_string
            reqd
            response
            (Printf.sprintf "received %Ld bytes" !received_bytes))
      in
      let rec read_body () =
        Body.Reader.schedule_read
          request_body
          ~on_eof:(fun () ->
            finalize ())
          ~on_read:(fun bigstring ~off ~len ->
            (match oc with
            | Some oc ->
              output_string oc (Bigstringaf.substring bigstring ~off ~len)
            | None -> ());
            received_bytes :=
              Int64.add !received_bytes (Int64.of_int len);
            report_progress ();
            (match expected_len with
            | Some expected when Int64.compare !received_bytes expected >= 0 ->
              finalize ()
            | _ -> read_body ()))
      in
      read_body ()
    | _, "/streaming" ->
      let response = Response.create `OK in
      let response_body = Reqd.respond_with_streaming reqd response in
      Body.Writer.write_string response_body "hello, ";
      set_interval ~clock 1. ~f:(fun () ->
        Body.Writer.write_string response_body "world.";
        Body.Writer.flush response_body (fun () ->
          Body.Writer.close response_body))
    | _ ->
      let response = Response.create `OK in
      Reqd.respond_with_string reqd response "hello"
  in
  H3.Server_connection.create request_handler

let () =
  Printexc.record_backtrace true;
  Mirage_crypto_rng_unix.use_default ();
  Sys.(set_signal sigpipe Signal_ignore);
  let port = ref 4433 in
  let serve_file = ref None in
  let upload_out = ref None in
  let chunk_size = ref max_data_chunk_size in
  let drop_recv_pct = ref 0.0 in
  let drop_send_pct = ref 0.0 in
  let drop_handshake = ref false in
  let drop_seed = ref 42 in
  Arg.parse
    [ "-p", Arg.Set_int port, " Listening port number (4433 by default)"
    ; ( "-serve-file"
      , Arg.String (fun path -> serve_file := Some path)
      , " Serve this file on GET /file"
      )
    ; ( "-upload-out"
      , Arg.String (fun path -> upload_out := Some path)
      , " Save uploaded bytes from POST /upload to this file"
      )
    ; ( "-chunk-size"
      , Arg.Set_int chunk_size
      , Printf.sprintf
          " File transfer chunk size in bytes (max %d)"
          max_data_chunk_size
      )
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
    "Echo server + file benchmarking endpoints. Runs forever.";
  if !chunk_size <= 0 || !chunk_size > max_data_chunk_size
  then
    failwith
      (Printf.sprintf
         "-chunk-size must be in 1..%d to fit within QUIC datagrams"
         max_data_chunk_size);
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
  let transport_parameters =
    Quic.Config.
      { initial_max_data = 1 lsl 26
      ; initial_max_stream_data_bidi_local = 1 lsl 26
      ; initial_max_stream_data_bidi_remote = 1 lsl 26
      ; initial_max_stream_data_uni = 1 lsl 26
      ; initial_max_streams_bidi = 1 lsl 8
      ; initial_max_streams_uni = 1 lsl 8
      }
  in
  let config =
    { Quic.Config.certificates
    ; alpn_protocols = [ "h3" ]
    ; transport_parameters
    }
  in
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
    "listening on UDP %d (drop_recv_pct=%.2f drop_send_pct=%.2f drop_handshake=%b seed=%d serve_file=%s upload_out=%s chunk_size=%d)@."
    !port
    !drop_recv_pct
    !drop_send_pct
    !drop_handshake
    !drop_seed
    (Option.value !serve_file ~default:"<none>")
    (Option.value !upload_out ~default:"<discard>")
    !chunk_size;
  Eio_main.run (fun env ->
    Eio.Switch.run (fun sw ->
      let handler =
        connection_handler
          (Eio.Stdenv.clock env)
          ~serve_file:!serve_file
          ~upload_out:!upload_out
          ~chunk_size:!chunk_size
      in
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
