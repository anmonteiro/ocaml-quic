(* open Eio.Std *)

module Line_channel = struct
  type t =
    { stream : Quic.Stream.t
    ; lines : string option Eio.Stream.t
    }

  let write_line_raw stream line =
    let payload = line ^ "\n" in
    let bs = Bigstringaf.of_string ~off:0 ~len:(String.length payload) payload in
    Quic.Stream.schedule_bigstring stream bs;
    Quic.Stream.flush stream ignore

  let write_line t line = write_line_raw t.stream line

  let drain_lines buf push =
    let data = Buffer.contents buf in
    let n = String.length data in
    let rec loop start =
      match String.index_from_opt data start '\n' with
      | None ->
        Buffer.clear buf;
        Buffer.add_substring buf data start (n - start)
      | Some i ->
        let raw = String.sub data start (i - start) in
        let line =
          if raw <> "" && raw.[String.length raw - 1] = '\r'
          then String.sub raw 0 (String.length raw - 1)
          else raw
        in
        push line;
        loop (i + 1)
    in
    loop 0

  let of_stream stream =
    let lines = Eio.Stream.create max_int in
    let buf = Buffer.create 4096 in
    let rec pump () =
      Quic.Stream.schedule_read
        stream
        ~on_eof:(fun () ->
          drain_lines buf (fun line -> Eio.Stream.add lines (Some line));
          Eio.Stream.add lines None)
        ~on_read:(fun bs ~off ~len ->
          Buffer.add_string buf (Bigstringaf.substring bs ~off ~len);
          drain_lines buf (fun line -> Eio.Stream.add lines (Some line));
          pump ())
    in
    pump ();
    { stream; lines }

  let read_line t = Eio.Stream.take t.lines
end

type role =
  | Sender
  | Receiver

let role_of_string = function
  | "sender" -> Some Sender
  | "receiver" -> Some Receiver
  | _ -> None

let split_words s =
  String.split_on_char ' ' (String.trim s) |> List.filter (fun x -> x <> "")

let parse_int64 s =
  try Int64.of_string s with
  | _ -> failwith ("invalid int64: " ^ s)

module Stats = struct
  type t =
    { label : string
    ; started_at : float
    ; mutable first_byte_at : float option
    ; mutable bytes : int64
    }

  let create label =
    { label; started_at = Unix.gettimeofday (); first_byte_at = None; bytes = 0L }

  let on_bytes t n =
    if n > 0
    then (
      if Option.is_none t.first_byte_at then t.first_byte_at <- Some (Unix.gettimeofday ());
      t.bytes <- Int64.add t.bytes (Int64.of_int n))

  let report t =
    let duration_s = max 1e-6 (Unix.gettimeofday () -. t.started_at) in
    let mib_per_s = (Int64.to_float t.bytes /. (1024. *. 1024.)) /. duration_s in
    let mbps = (Int64.to_float t.bytes *. 8. /. 1_000_000.) /. duration_s in
    Printf.printf
      "%s: bytes=%Ld duration=%.3fs throughput=%.2f MiB/s (%.2f Mbit/s)\n%!"
      t.label
      t.bytes
      duration_s
      mib_per_s
      mbps
end

let transport_parameters =
  { Quic.Config.default_transport_parameters with
    initial_max_data = 1 lsl 26
  ; initial_max_stream_data_bidi_local = 1 lsl 26
  ; initial_max_stream_data_bidi_remote = 1 lsl 26
  ; initial_max_stream_data_uni = 1 lsl 26
  ; initial_max_streams_bidi = 64
  ; initial_max_streams_uni = 64
  }

let config ?(max_datagram_size = Quic.Config.default_max_datagram_size) alpn =
  let cert = "./certificates/server.pem" in
  let priv_key = "./certificates/server.key" in
  let certificates = `Single (Qx509.private_of_pems ~cert ~priv_key) in
  { Quic.Config.certificates
  ; alpn_protocols = [ alpn ]
  ; transport_parameters
  ; max_datagram_size
  }

let resolve_udp_address host port =
  let addrs =
    Eio_unix.run_in_systhread (fun () ->
      Unix.getaddrinfo host (string_of_int port) [ Unix.(AI_FAMILY PF_INET) ])
  in
  match addrs with
  | { Unix.ai_addr = Unix.ADDR_INET (inet, p); _ } :: _ ->
    `Udp (Eio_unix.Net.Ipaddr.of_unix inet, p)
  | _ -> failwith ("could not resolve host: " ^ host)

type relay_peer =
  { start_stream : Quic.Transport.start_stream
  ; mutable control_stream : Quic.Stream.t option
  ; mutable role : role option
  ; mutable total_bytes : int64 option
  }

type relay_state =
  { mutable sender : relay_peer option
  ; mutable receiver : relay_peer option
  }

type direct_state =
  { mutable start_stream : Quic.Transport.start_stream option
  ; mutable control_stream : Quic.Stream.t option
  ; mutable total_bytes : int64 option
  ; stats : Stats.t
  }

let send_peer (peer : relay_peer) line =
  match peer.control_stream with
  | Some stream -> Line_channel.write_line_raw stream line
  | None -> ()

let send_direct (state : direct_state) line =
  match state.control_stream with
  | Some stream -> Line_channel.write_line_raw stream line
  | None -> ()

let maybe_ready state =
  match state.sender, state.receiver with
  | Some sender, Some receiver ->
    (match sender.total_bytes with
     | Some total ->
       send_peer sender (Printf.sprintf "READY %Ld" total);
       send_peer receiver (Printf.sprintf "READY %Ld" total)
     | None -> ())
  | _ -> ()

let relay_proxy ~src ~dst ~sender ~receiver =
  let stats = Stats.create "bench relay" in
  let pending = Buffer.create (256 * 1024) in
  let pending_bytes = ref 0 in
  let flush_pending k =
    if !pending_bytes = 0
    then k ()
    else (
      let chunk = Buffer.contents pending in
      Buffer.clear pending;
      pending_bytes := 0;
      Quic.Stream.write_string dst chunk;
      Quic.Stream.flush dst k)
  in
  let rec pump () =
    Quic.Stream.schedule_read
      src
      ~on_eof:(fun () ->
        flush_pending (fun () ->
          Quic.Stream.close_writer dst;
          send_peer sender "DONE";
          send_peer receiver "DONE";
          Stats.report stats))
      ~on_read:(fun bs ~off ~len ->
        Stats.on_bytes stats len;
        Buffer.add_string pending (Bigstringaf.substring bs ~off ~len);
        pending_bytes := !pending_bytes + len;
        if !pending_bytes >= 256 * 1024 then flush_pending pump else pump ())
  in
  pump ()

let relay_connection_handler state ~cid:_ ~start_stream =
  let peer = { start_stream; control_stream = None; role = None; total_bytes = None } in
  let rec handle_line line =
    match split_words line with
    | [ "ROLE"; role_s; total_s ] ->
      let role =
        match role_of_string role_s with
        | Some role -> role
        | None -> failwith "invalid role"
      in
      peer.role <- Some role;
      peer.total_bytes <- Some (parse_int64 total_s);
      (match role with
       | Sender -> state.sender <- Some peer
       | Receiver -> state.receiver <- Some peer);
      send_peer peer "JOINED";
      maybe_ready state
    | _ -> send_peer peer "ERROR"
  in
  let attach_parser stream =
    peer.control_stream <- Some stream;
    let buf = Buffer.create 4096 in
    let rec pump () =
      Quic.Stream.schedule_read
        stream
        ~on_eof:(fun () -> Line_channel.drain_lines buf handle_line)
        ~on_read:(fun bs ~off ~len ->
          Buffer.add_string buf (Bigstringaf.substring bs ~off ~len);
          Line_channel.drain_lines buf handle_line;
          pump ())
    in
    pump ()
  in
  let handle_stream stream =
    match peer.control_stream, Quic.Stream.direction stream, peer.role, state.receiver with
    | None, Quic.Direction.Bidirectional, _, _ -> attach_parser stream
    | Some _, Quic.Direction.Unidirectional, Some Sender, Some receiver ->
      let dst = receiver.start_stream Quic.Direction.Unidirectional in
      relay_proxy ~src:stream ~dst ~sender:peer ~receiver
    | _ -> Quic.Stream.close_reader stream
  in
  Quic.Transport.F (fun stream ->
    handle_stream stream;
    { on_error = ignore })

let run_relay env ~sw ~port ~max_datagram_size =
  let state = { sender = None; receiver = None } in
  Printf.printf "relay bench listening on udp port %d\n%!" port;
  Quic_eio.Server.establish_server
    env
    ~sw
    ~config:(config ~max_datagram_size "wormhole-relay-bench-v1")
    (`Udp (Eio.Net.Ipaddr.V4.any, port))
    (relay_connection_handler state)

let direct_connection_handler state ~cid:_ ~start_stream =
  state.start_stream <- Some start_stream;
  let rec handle_line line =
    match split_words line with
    | [ "ROLE"; "sender"; total_s ] ->
      let total = parse_int64 total_s in
      state.total_bytes <- Some total;
      send_direct state (Printf.sprintf "READY %Ld" total)
    | _ -> send_direct state "ERROR"
  in
  let attach_parser stream =
    state.control_stream <- Some stream;
    let buf = Buffer.create 4096 in
    let rec pump () =
      Quic.Stream.schedule_read
        stream
        ~on_eof:(fun () -> Line_channel.drain_lines buf handle_line)
        ~on_read:(fun bs ~off ~len ->
          Buffer.add_string buf (Bigstringaf.substring bs ~off ~len);
          Line_channel.drain_lines buf handle_line;
          pump ())
    in
    pump ()
  in
  let rec drain_stream stream =
    Quic.Stream.schedule_read
      stream
      ~on_eof:(fun () ->
        Stats.report state.stats;
        send_direct state "DONE")
      ~on_read:(fun _bs ~off:_ ~len ->
        Stats.on_bytes state.stats len;
        drain_stream stream)
  in
  let handle_stream stream =
    match state.control_stream, Quic.Stream.direction stream with
    | None, Quic.Direction.Bidirectional -> attach_parser stream
    | Some _, Quic.Direction.Unidirectional -> drain_stream stream
    | _ -> Quic.Stream.close_reader stream
  in
  Quic.Transport.F (fun stream ->
    handle_stream stream;
    { on_error = ignore })

let run_direct_server env ~sw ~port ~max_datagram_size =
  let state =
    { start_stream = None
    ; control_stream = None
    ; total_bytes = None
    ; stats = Stats.create "bench direct recv"
    }
  in
  Printf.printf "direct bench listening on udp port %d\n%!" port;
  Quic_eio.Server.establish_server
    env
    ~sw
    ~config:(config ~max_datagram_size "wormhole-relay-bench-v1")
    (`Udp (Eio.Net.Ipaddr.V4.any, port))
    (direct_connection_handler state)

type conn =
  { transport : Quic_eio.t
  ; control_stream : Quic.Stream.t
  ; start_stream : Quic.Transport.start_stream
  ; incoming_streams : Quic.Stream.t Eio.Stream.t
  }

let connect env ~sw ~host ~port ~max_datagram_size =
  let on_connect_p, on_connect_u = Eio.Promise.create () in
  let incoming_streams = Eio.Stream.create max_int in
  let stream_handler =
    Quic.Transport.F (fun stream ->
      Eio.Stream.add incoming_streams stream;
      { on_error = ignore })
  in
  let transport =
    Quic_eio.Client.create
      env
      ~sw
      ~config:(config ~max_datagram_size "wormhole-relay-bench-v1")
      (fun ~cid:_ ~start_stream:_ -> stream_handler)
  in
  let address = resolve_udp_address host port in
  let tls_host =
    try
      let _ = Unix.inet_addr_of_string host in
      "localhost"
    with
    | Failure _ -> host
  in
  Quic_eio.connect transport ~address ~host:tls_host (fun ~cid:_ ~start_stream ->
    Eio.Promise.resolve on_connect_u start_stream;
    stream_handler);
  let start_stream = Eio.Promise.await on_connect_p in
  { transport = transport
  ; control_stream = start_stream Quic.Direction.Bidirectional
  ; start_stream
  ; incoming_streams
  }

let with_conn env ~sw ~host ~port ~max_datagram_size f =
  let conn = connect env ~sw ~host ~port ~max_datagram_size in
  Fun.protect ~finally:(fun () -> Quic_eio.shutdown conn.transport) (fun () -> f conn)

let wait_ready ch =
  let rec loop () =
    match Line_channel.read_line ch with
    | Some line ->
      (match split_words line with
       | [ "READY"; total_s ] -> parse_int64 total_s
       | _ -> loop ())
    | None -> failwith "relay closed"
  in
  loop ()

let wait_done ch =
  let rec loop () =
    match Line_channel.read_line ch with
    | Some "DONE" -> ()
    | Some _ -> loop ()
    | None -> failwith "relay closed before done"
  in
  loop ()

let run_sender env ~sw ~host ~port ~bytes ~max_datagram_size =
  with_conn env ~sw ~host ~port ~max_datagram_size (fun conn ->
    let ch = Line_channel.of_stream conn.control_stream in
    Line_channel.write_line ch (Printf.sprintf "ROLE sender %Ld" bytes);
    let total = wait_ready ch in
    let stats = Stats.create "bench send" in
    let stream = conn.start_stream Quic.Direction.Unidirectional in
    let chunk = String.make (256 * 1024) 'x' in
    let done_p, done_u = Eio.Promise.create () in
    let rec pump remaining =
      if Int64.compare remaining 0L <= 0
      then Quic.Stream.flush stream (fun () ->
        Quic.Stream.close_writer stream;
        Eio.Promise.resolve done_u ())
      else
        let len =
          min
            (String.length chunk)
            (Int64.to_int (Int64.min remaining (Int64.of_int (String.length chunk))))
        in
        Quic.Stream.write_string stream ~off:0 ~len chunk;
        Stats.on_bytes stats len;
        if len >= 256 * 1024
        then Quic.Stream.flush stream (fun () -> pump (Int64.sub remaining (Int64.of_int len)))
        else pump (Int64.sub remaining (Int64.of_int len))
    in
    pump total;
    Eio.Promise.await done_p;
    wait_done ch;
    Stats.report stats)

let run_receiver env ~sw ~host ~port ~bytes ~max_datagram_size =
  with_conn env ~sw ~host ~port ~max_datagram_size (fun conn ->
    let ch = Line_channel.of_stream conn.control_stream in
    Line_channel.write_line ch (Printf.sprintf "ROLE receiver %Ld" bytes);
    ignore (wait_ready ch);
    let stream =
      let rec await () =
        match Eio.Stream.take conn.incoming_streams with
        | stream when Quic.Stream.direction stream = Quic.Direction.Unidirectional -> stream
        | _ -> await ()
      in
      await ()
    in
    let stats = Stats.create "bench recv" in
    let done_p, done_u = Eio.Promise.create () in
    let rec drain () =
      Quic.Stream.schedule_read
        stream
        ~on_eof:(fun () -> Eio.Promise.resolve done_u ())
        ~on_read:(fun _bs ~off:_ ~len ->
          Stats.on_bytes stats len;
          drain ())
    in
    drain ();
    Eio.Promise.await done_p;
    Stats.report stats)

let run_direct_sender env ~sw ~host ~port ~bytes ~max_datagram_size =
  with_conn env ~sw ~host ~port ~max_datagram_size (fun conn ->
    let ch = Line_channel.of_stream conn.control_stream in
    Line_channel.write_line ch (Printf.sprintf "ROLE sender %Ld" bytes);
    let total = wait_ready ch in
    let stats = Stats.create "bench direct send" in
    let stream = conn.start_stream Quic.Direction.Unidirectional in
    let chunk = String.make (256 * 1024) 'x' in
    let done_p, done_u = Eio.Promise.create () in
    let rec pump remaining =
      if Int64.compare remaining 0L <= 0
      then Quic.Stream.flush stream (fun () ->
        Quic.Stream.close_writer stream;
        Eio.Promise.resolve done_u ())
      else
        let len =
          min
            (String.length chunk)
            (Int64.to_int (Int64.min remaining (Int64.of_int (String.length chunk))))
        in
        Quic.Stream.write_string stream ~off:0 ~len chunk;
        Stats.on_bytes stats len;
        if len >= 256 * 1024
        then Quic.Stream.flush stream (fun () -> pump (Int64.sub remaining (Int64.of_int len)))
        else pump (Int64.sub remaining (Int64.of_int len))
    in
    pump total;
    Eio.Promise.await done_p;
    wait_done ch;
    Stats.report stats)

let usage () =
  prerr_endline
    "Usage:\n\
    \  wormhole_relay_bench relay [-p PORT] [-max-dgram-size N]\n\
    \  wormhole_relay_bench direct-server [-p PORT] [-max-dgram-size N]\n\
    \  wormhole_relay_bench send [-host HOST] [-p PORT] [-bytes N] [-max-dgram-size N]\n\
    \  wormhole_relay_bench recv [-host HOST] [-p PORT] [-bytes N] [-max-dgram-size N]\n\
    \  wormhole_relay_bench direct-send [-host HOST] [-p PORT] [-bytes N] [-max-dgram-size N]";
  exit 2

let () =
  Mirage_crypto_rng_unix.use_default ();
  Sys.(set_signal sigpipe Signal_ignore);
  if Array.length Sys.argv < 2 then usage ();
  let host = ref "127.0.0.1" in
  let port = ref 4701 in
  let bytes = ref (Int64.mul 64L (Int64.mul 1024L 1024L)) in
  let max_datagram_size = ref Quic.Config.default_max_datagram_size in
  let speclist =
    [ "-host", Arg.Set_string host, "relay host"
    ; "-p", Arg.Set_int port, "udp port"
    ; "-bytes", Arg.String (fun v -> bytes := parse_int64 v), "bytes to transfer"
    ; "-max-dgram-size", Arg.Set_int max_datagram_size, "max datagram size"
    ]
  in
  let subcommand = Sys.argv.(1) in
  let argv =
    Array.init (Array.length Sys.argv - 1) (fun i ->
      if i = 0 then Sys.argv.(0) else Sys.argv.(i + 1))
  in
  Arg.parse_argv ~current:(ref 0) argv speclist (fun _ -> ()) "wormhole_relay_bench";
  match subcommand with
  | "relay" ->
    Eio_main.run (fun env ->
      Eio.Switch.run (fun sw ->
        run_relay env ~sw ~port:!port ~max_datagram_size:!max_datagram_size))
  | "direct-server" ->
    Eio_main.run (fun env ->
      Eio.Switch.run (fun sw ->
        run_direct_server env ~sw ~port:!port ~max_datagram_size:!max_datagram_size))
  | "send" ->
    Eio_main.run (fun env ->
      Eio.Switch.run (fun sw ->
        run_sender
          env
          ~sw
          ~host:!host
          ~port:!port
          ~bytes:!bytes
          ~max_datagram_size:!max_datagram_size))
  | "recv" ->
    Eio_main.run (fun env ->
      Eio.Switch.run (fun sw ->
        run_receiver
          env
          ~sw
          ~host:!host
          ~port:!port
          ~bytes:!bytes
          ~max_datagram_size:!max_datagram_size))
  | "direct-send" ->
    Eio_main.run (fun env ->
      Eio.Switch.run (fun sw ->
        run_direct_sender
          env
          ~sw
          ~host:!host
          ~port:!port
          ~bytes:!bytes
          ~max_datagram_size:!max_datagram_size))
  | _ -> usage ()
