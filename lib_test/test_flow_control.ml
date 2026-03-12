module Quic = Quic__
open Quic

let read_file path =
  let ic = open_in_bin path in
  Fun.protect
    ~finally:(fun () -> close_in_noerr ic)
    (fun () ->
       let n = in_channel_length ic in
       really_input_string ic n)

let server_certificates () =
  let cert = "./certificates/server.pem" in
  let priv_key = "./certificates/server.key" in
  let certchain =
    let pem = read_file cert in
    match X509.Certificate.decode_pem_multiple pem with
    | Ok certchain -> certchain
    | Error (`Msg m) -> failwith m
  in
  let priv_key =
    let pem = read_file priv_key in
    match X509.Private_key.decode_pem pem with
    | Ok x -> x
    | Error (`Msg m) -> failwith m
  in
  `Single (certchain, priv_key)

let copy_iovecs_to_bigstring iovecs =
  let len = IOVec.lengthv iovecs in
  let bs = Bigstringaf.create len in
  let dst_off = ref 0 in
  List.iter
    (fun { IOVec.buffer; off = src_off; len } ->
       Bigstringaf.blit
         buffer
         ~src_off
         bs
         ~dst_off:!dst_off
         ~len;
       dst_off := !dst_off + len)
    iovecs;
  bs

let make_config ~transport_parameters =
  { Quic.Config.certificates = server_certificates ()
  ; alpn_protocols = [ "h3" ]
  ; transport_parameters
  ; max_datagram_size = Quic.Config.default_max_datagram_size
  }

let pump_write ~src ~dst ~client_address =
  match Transport.next_write_operation src with
  | `Writev (iovecs, _peer_address, cid) ->
    let bs = copy_iovecs_to_bigstring iovecs in
    let len = Bigstringaf.length bs in
    ignore (Transport.read dst ~client_address bs ~off:0 ~len);
    Transport.report_write_result src ~cid (`Ok len);
    true
  | `Yield _ | `Close _ -> false

let schedule_consume_all stream on_chunk =
  let rec loop () =
    Stream.schedule_read
      stream
      ~on_eof:(fun () -> ())
      ~on_read:(fun _buffer ~off:_ ~len ->
        on_chunk len;
        loop ())
  in
  loop ()

let write_payload stream ~total_len =
  let chunk_len = 1024 in
  let chunk =
    let s = Bytes.make chunk_len '\xAA' in
    Bigstringaf.of_string ~off:0 ~len:chunk_len (Bytes.unsafe_to_string s)
  in
  let remaining = ref total_len in
  while !remaining > 0 do
    let to_write = min chunk_len !remaining in
    if to_write = chunk_len
    then Stream.schedule_bigstring stream chunk
    else
      Stream.schedule_bigstring stream ~off:0 ~len:to_write chunk;
    remaining := !remaining - to_write
  done;
  Stream.close_writer stream;
  Stream.flush stream ignore

let test_dynamic_flow_control_allows_large_upload () =
  let transport_parameters =
    Quic.Config.
      { initial_max_data = 4096
      ; initial_max_stream_data_bidi_local = 4096
      ; initial_max_stream_data_bidi_remote = 4096
      ; initial_max_stream_data_uni = 4096
      ; initial_max_streams_bidi = 8
      ; initial_max_streams_uni = 8
      }
  in
  let config = make_config ~transport_parameters in
  let now = ref 0L in
  let now_ms () = !now in
  let server_received = ref 0 in
  let client_start_stream = ref None in
  let payload_len = 256 * 1024 in
  let upload_started = ref false in

  let server =
    Transport.Server.create
      ~now_ms
      ~config
      (fun ~cid:_ ~start_stream:_ ->
        Transport.F
          (fun stream ->
             schedule_consume_all stream (fun len -> server_received := !server_received + len);
             { Transport.on_error = (fun _ -> ()) }))
  in
  let client_handler ~cid:_ ~start_stream =
    client_start_stream := Some start_stream;
    Transport.F (fun _stream -> { Transport.on_error = (fun _ -> ()) })
  in
  let client = Transport.Client.create ~now_ms ~config client_handler in
  Transport.connect client ~address:"server-address" ~host:"localhost" client_handler;

  let max_steps = 200_000 in
  let rec loop step =
    if !server_received >= payload_len
    then true
    else if step > max_steps
    then false
    else (
      if not !upload_started
      then
        match !client_start_stream with
        | None -> ()
        | Some start_stream ->
          upload_started := true;
          let stream = start_stream Direction.Bidirectional in
          write_payload stream ~total_len:payload_len
      else ();
      let client_to_server =
        pump_write ~src:client ~dst:server ~client_address:"client-address"
      in
      let server_to_client =
        pump_write ~src:server ~dst:client ~client_address:"server-address"
      in
      if not (client_to_server || server_to_client)
      then (
        now := Int64.add !now 1L;
        Transport.on_timeout client;
        Transport.on_timeout server);
      loop (step + 1))
  in
  let completed = loop 0 in
  Alcotest.(check bool)
    "upload completed before timeout"
    true
    completed;
  Alcotest.(check int) "server received full payload" payload_len !server_received

let test_replenished_flow_control_wakes_writer () =
  let transport_parameters =
    Quic.Config.
      { initial_max_data = 4096
      ; initial_max_stream_data_bidi_local = 4096
      ; initial_max_stream_data_bidi_remote = 4096
      ; initial_max_stream_data_uni = 4096
      ; initial_max_streams_bidi = 8
      ; initial_max_streams_uni = 8
      }
  in
  let config = make_config ~transport_parameters in
  let now = ref 0L in
  let now_ms () = !now in
  let client_start_stream = ref None in
  let server_stream = ref None in
  let payload_len = 16 * 1024 in
  let upload_started = ref false in

  let server =
    Transport.Server.create
      ~now_ms
      ~config
      (fun ~cid:_ ~start_stream:_ ->
         Transport.F
           (fun stream ->
              server_stream := Some stream;
              { Transport.on_error = (fun _ -> ()) }))
  in
  let client_handler ~cid:_ ~start_stream =
    client_start_stream := Some start_stream;
    Transport.F (fun _stream -> { Transport.on_error = (fun _ -> ()) })
  in
  let client = Transport.Client.create ~now_ms ~config client_handler in
  Transport.connect client ~address:"server-address" ~host:"localhost" client_handler;
  let rec drive_until_quiescent idle_steps step =
    if idle_steps >= 8 || step > 50_000
    then ()
    else (
      if not !upload_started
      then
        match !client_start_stream with
        | None -> ()
        | Some start_stream ->
          upload_started := true;
          let stream = start_stream Direction.Bidirectional in
          write_payload stream ~total_len:payload_len
      else ();
      let client_to_server =
        pump_write ~src:client ~dst:server ~client_address:"client-address"
      in
      let server_to_client =
        pump_write ~src:server ~dst:client ~client_address:"server-address"
      in
      let idle_steps =
        if client_to_server || server_to_client then 0 else idle_steps + 1
      in
      if not (client_to_server || server_to_client)
      then (
        now := Int64.add !now 1L;
        Transport.on_timeout client;
        Transport.on_timeout server);
      drive_until_quiescent idle_steps (step + 1))
  in
  drive_until_quiescent 0 0;
  let stream =
    match !server_stream with
    | Some stream -> stream
    | None -> Alcotest.fail "server stream was not created"
  in
  (match Transport.next_write_operation server with
   | `Yield _ -> ()
   | `Writev _ ->
     Alcotest.fail "server unexpectedly still had pending writes before consume"
   | `Close _ -> Alcotest.fail "server unexpectedly closed");
  let woke_writer = ref false in
  let consumed = ref 0 in
  Transport.yield_writer server (fun () -> woke_writer := true);
  schedule_consume_all stream (fun len -> consumed := !consumed + len);
  Stream.Recv.flush stream.recv;
  Alcotest.(check bool)
    "replenishing flow control wakes the writer"
    true
    !woke_writer;
  Alcotest.(check bool)
    "server consumed buffered stream data"
    true
    (!consumed > 0);
  Alcotest.(check bool)
    "server has MAX_DATA/MAX_STREAM_DATA to send"
    true
    (pump_write ~src:server ~dst:client ~client_address:"server-address")

let test_zero_length_fin_closes_reader () =
  let stream =
    Stream.create
      ~typ:(Stream.Type.Client Direction.Bidirectional)
      ~id:0L
      ~report_application_error:(fun _ -> ())
      ignore
  in
  let saw_eof = ref false in
  Stream.schedule_read
    stream
    ~on_eof:(fun () -> saw_eof := true)
    ~on_read:(fun _buffer ~off:_ ~len:_ -> Alcotest.fail "unexpected payload");
  Stream.Recv.push
    ~is_fin:true
    { Frame.off = 0; len = 0; payload = ""; payload_off = 0 }
    stream.recv;
  ignore (Stream.Recv.pop stream.recv);
  Alcotest.(check bool)
    "zero-length FIN closes the reader at the final offset"
    true
    !saw_eof

let () =
  Mirage_crypto_rng_unix.use_default ();
  Alcotest.run
    "flow-control"
    [ ( "flow-control"
      , [ ( "dynamic MAX_DATA/MAX_STREAM_DATA replenishment permits transfer \
             beyond initial window"
          , `Quick
          , test_dynamic_flow_control_allows_large_upload )
        ; ( "replenishing flow control wakes the writer"
          , `Quick
          , test_replenished_flow_control_wakes_writer )
        ; ( "zero-length FIN closes the stream reader"
          , `Quick
          , test_zero_length_fin_closes_reader )
        ] ) ]
