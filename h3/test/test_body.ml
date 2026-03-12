open Quic
open H3

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

let config =
  { Quic.Config.certificates = server_certificates ()
  ; alpn_protocols = [ "h3" ]
  ; transport_parameters = Quic.Config.default_transport_parameters
  }

let copy_iovecs_to_bigstring iovecs =
  let len = IOVec.lengthv iovecs in
  let bs = Bigstringaf.create len in
  let dst_off = ref 0 in
  List.iter
    (fun { IOVec.buffer; off = src_off; len } ->
      Bigstringaf.blit buffer ~src_off bs ~dst_off:!dst_off ~len;
      dst_off := !dst_off + len)
    iovecs;
  bs

let to_public_stream (stream : Quic__Stream.t) : Quic.Stream.t = Obj.magic stream
let to_public_client_connection (conn : H3__Client_connection.t) : H3.Client_connection.t = Obj.magic conn
let to_public_reqd (reqd : H3__Reqd.t) : H3.Reqd.t = Obj.magic reqd

let pump_write ~src ~dst ~client_address =
  match Transport.next_write_operation src with
  | `Writev (iovecs, _peer_address, cid) ->
    let bs = copy_iovecs_to_bigstring iovecs in
    let len = Bigstringaf.length bs in
    ignore (Transport.read dst ~client_address bs ~off:0 ~len);
    Transport.report_write_result src ~cid (`Ok len);
    true
  | `Yield _ | `Close _ -> false

let advance_time ~now client server =
  now := Int64.add !now 1L;
  Transport.on_timeout client;
  Transport.on_timeout server

let run_until ~now ~client ~server ~max_steps condition =
  let rec loop step =
    if condition ()
    then true
    else if step >= max_steps
    then false
    else (
      let progressed =
        pump_write ~src:client ~dst:server ~client_address:"client-address"
        || pump_write ~src:server ~dst:client ~client_address:"server-address"
      in
      if not progressed then advance_time ~now client server;
      loop (step + 1))
  in
  loop 0

let schedule_read_all reader on_chunk on_eof =
  let rec loop () =
    Body.Reader.schedule_read
      reader
      ~on_eof
      ~on_read:(fun bs ~off ~len ->
        on_chunk bs ~off ~len;
        loop ())
  in
  loop ()

let create_stack ~server_request_handler =
  let now = ref 0L in
  let now_ms () = !now in
  let client_conn = ref None in
  let server_conn = ref None in
  let server =
    Transport.Server.create
      ~now_ms
      ~config
      (fun ~cid ~start_stream ->
        let conn, handler =
          H3__Server_connection.create_connection
            (fun reqd -> server_request_handler (to_public_reqd reqd))
            ~cid
            ~start_stream
        in
        server_conn := Some conn;
        handler)
  in
  let client_stream_handler ~cid ~start_stream =
    let conn, handler =
      H3__Client_connection.create
        ~error_handler:(fun _ -> Alcotest.fail "unexpected client H3 error")
        ~cid
        ~start_stream
    in
    client_conn := Some conn;
    handler
  in
  let client = Transport.Client.create ~now_ms ~config client_stream_handler in
  Transport.connect client ~address:"server-address" ~host:"localhost" client_stream_handler;
  now, client, server, client_conn, server_conn

let make_start_stream side =
  let next = ref 0L in
  fun ?error_handler:_ direction ->
    let direction' =
      match direction with
      | Quic.Direction.Unidirectional -> Quic__.Direction.Unidirectional
      | Bidirectional -> Quic__.Direction.Bidirectional
    in
    let typ =
      match side with
      | `Client -> Quic__Stream.Type.Client direction'
      | `Server -> Quic__Stream.Type.Server direction'
    in
    let id = Quic__Stream.Type.gen_id ~typ !next in
    next := Int64.succ !next;
    Quic__Stream.create ~typ ~id ~report_application_error:ignore ignore
    |> to_public_stream

let make_peer_quic_stream side ~id app_errors =
  let typ =
    match side with
    | `Client -> Quic__Stream.Type.Client Quic__.Direction.Unidirectional
    | `Server -> Quic__Stream.Type.Server Quic__.Direction.Unidirectional
  in
  Quic__Stream.create
    ~typ
    ~id
    ~report_application_error:(fun code -> app_errors := code :: !app_errors)
    ignore
  |> to_public_stream

let make_client_h3_stream stream : H3__Client_connection.stream =
  { stream
  ; direction = Quic.Direction.Unidirectional
  ; writer = H3__Serialize.Writer.create stream
  ; state = H3__Client_connection.Uninitialized
  }

let make_server_h3_stream stream : H3__Server_connection.stream =
  { stream
  ; direction = Quic.Direction.Unidirectional
  ; reqd = None
  ; writer = H3__Serialize.Writer.create stream
  }

let test_unknown_unidirectional_stream_type_is_ignored () =
  let payload = Bigstringaf.of_string ~off:0 ~len:1 "\x09" in
  match
    Angstrom.parse_bigstring
      ~consume:All
      H3__Parse.unidirectional_stream_header
      payload
  with
  | Ok (H3__Unidirectional_stream.Unknown 0x09) -> ()
  | Ok _ -> Alcotest.fail "expected parser to preserve unknown stream type"
  | Error err ->
    Alcotest.failf "expected unknown stream type to parse cleanly: %s" err

let test_client_rejects_duplicate_critical_streams () =
  let conn, _handler =
    H3__Client_connection.create
      ~error_handler:(fun _ -> Alcotest.fail "unexpected client H3 error")
      ~cid:"client-test"
      ~start_stream:(make_start_stream `Client)
  in
  let app_errors = ref [] in
  let first =
    make_peer_quic_stream `Server ~id:3L app_errors |> make_client_h3_stream
  in
  let second =
    make_peer_quic_stream `Server ~id:7L app_errors |> make_client_h3_stream
  in
  Alcotest.(check bool)
    "first peer control stream is accepted"
    true
    (H3__Client_connection.register_peer_control_stream conn first);
  Alcotest.(check bool)
    "duplicate peer control stream is rejected"
    false
    (H3__Client_connection.register_peer_control_stream conn second);
  Alcotest.(check (list int))
    "duplicate control stream closes the connection"
    [ H3__Error.Code.serialize H3__Error.Code.Stream_creation_error ]
    (List.rev !app_errors)

let test_server_rejects_duplicate_critical_streams () =
  let conn, _handler =
    H3__Server_connection.create_connection
      (fun _reqd -> Alcotest.fail "unexpected request")
      ~cid:"server-test"
      ~start_stream:(make_start_stream `Server)
  in
  let app_errors = ref [] in
  let first =
    make_peer_quic_stream `Client ~id:2L app_errors |> make_server_h3_stream
  in
  let second =
    make_peer_quic_stream `Client ~id:6L app_errors |> make_server_h3_stream
  in
  Alcotest.(check bool)
    "first peer control stream is accepted"
    true
    (H3__Server_connection.register_peer_control_stream conn first);
  Alcotest.(check bool)
    "duplicate peer control stream is rejected"
    false
    (H3__Server_connection.register_peer_control_stream conn second);
  Alcotest.(check (list int))
    "duplicate control stream closes the connection"
    [ H3__Error.Code.serialize H3__Error.Code.Stream_creation_error ]
    (List.rev !app_errors)

let test_buffered_request_body_delivery () =
  let request_payload = String.init (256 * 1024) (fun i -> Char.chr (97 + (i mod 26))) in
  let buffered_reqqd = ref None in
  let server_received = Buffer.create (String.length request_payload) in
  let client_response = ref None in
  let client_done = ref false in
  let server_request_handler reqd = buffered_reqqd := Some reqd in
  let client_response_handler response response_body =
    let { Response.status; _ } = response in
    Alcotest.(check int) "response status" 200 (Status.to_code status);
    let response_buf = Buffer.create 16 in
    schedule_read_all
      response_body
      (fun bs ~off ~len -> Buffer.add_string response_buf (Bigstringaf.substring bs ~off ~len))
      (fun () ->
        client_response := Some (Buffer.contents response_buf);
        client_done := true)
  in
  let now, client, server, client_conn, _server_conn = create_stack ~server_request_handler in
  let got_conn =
    run_until ~now ~client ~server ~max_steps:20_000 (fun () -> Option.is_some !client_conn)
  in
  Alcotest.(check bool) "client connection established" true got_conn;
  let conn = Option.get !client_conn |> to_public_client_connection in
  let headers =
    Headers.of_list
      [ ":authority", "localhost"
      ; "content-length", string_of_int (String.length request_payload)
      ]
  in
  let request = Request.create ~scheme:"https" ~headers `POST "/upload" in
  let request_body =
    Client_connection.request
      conn
      request
      ~error_handler:(fun _ -> Alcotest.fail "unexpected request error")
      ~response_handler:client_response_handler
  in
  Body.Writer.write_string request_body request_payload;
  Body.Writer.close request_body;
  let got_request =
    run_until ~now ~client ~server ~max_steps:20_000 (fun () -> Option.is_some !buffered_reqqd)
  in
  Alcotest.(check bool) "server saw request" true got_request;
  let reqd = Option.get !buffered_reqqd in
  let request_body = Reqd.request_body reqd in
  let responded = ref false in
  let rec read_request_body () =
    Body.Reader.schedule_read
      request_body
      ~on_eof:(fun () ->
        if not !responded
        then (
          responded := true;
          Reqd.respond_with_string
            reqd
            (Response.create `OK)
            (Printf.sprintf "received %d bytes" (Buffer.length server_received))))
      ~on_read:(fun bs ~off ~len ->
        Buffer.add_string server_received (Bigstringaf.substring bs ~off ~len);
        if Buffer.length server_received >= String.length request_payload
        then (
          responded := true;
          Reqd.respond_with_string
            reqd
            (Response.create `OK)
            (Printf.sprintf "received %d bytes" (Buffer.length server_received)))
        else read_request_body ())
  in
  read_request_body ();
  let completed =
    run_until ~now ~client ~server ~max_steps:200_000 (fun () -> !client_done)
  in
  Alcotest.(check bool) "request/response completed" true completed;
  Alcotest.(check string) "server received request body" request_payload (Buffer.contents server_received);
  Alcotest.(check (option string))
    "client received response body"
    (Some (Printf.sprintf "received %d bytes" (String.length request_payload)))
    !client_response

let test_buffered_response_body_delivery () =
  let response_payload = String.init (256 * 1024) (fun i -> Char.chr (65 + (i mod 26))) in
  let pending_response_body = ref None in
  let client_received = Buffer.create (String.length response_payload) in
  let client_done = ref false in
  let server_request_handler reqd =
    let body = Reqd.respond_with_streaming reqd (Response.create `OK) in
    Body.Writer.write_string body response_payload;
    Body.Writer.close body
  in
  let client_response_handler response response_body =
    let { Response.status; _ } = response in
    Alcotest.(check int) "response status" 200 (Status.to_code status);
    pending_response_body := Some response_body
  in
  let now, client, server, client_conn, _server_conn = create_stack ~server_request_handler in
  let got_conn =
    run_until ~now ~client ~server ~max_steps:20_000 (fun () -> Option.is_some !client_conn)
  in
  Alcotest.(check bool) "client connection established" true got_conn;
  let conn = Option.get !client_conn |> to_public_client_connection in
  let request =
    Request.create
      ~scheme:"https"
      ~headers:(Headers.of_list [ ":authority", "localhost" ])
      `GET
      "/file"
  in
  let request_body =
    Client_connection.request
      conn
      request
      ~error_handler:(fun _ -> Alcotest.fail "unexpected request error")
      ~response_handler:client_response_handler
  in
  Body.Writer.close request_body;
  let got_response_headers =
    run_until ~now ~client ~server ~max_steps:50_000 (fun () -> Option.is_some !pending_response_body)
  in
  Alcotest.(check bool) "client received response headers" true got_response_headers;
  let response_body = Option.get !pending_response_body in
  schedule_read_all
    response_body
    (fun bs ~off ~len -> Buffer.add_string client_received (Bigstringaf.substring bs ~off ~len))
    (fun () -> client_done := true);
  let completed =
    run_until ~now ~client ~server ~max_steps:200_000 (fun () -> !client_done)
  in
  Alcotest.(check bool) "response body completed" true completed;
  Alcotest.(check string)
    "client received full response body"
    response_payload
    (Buffer.contents client_received)

let test_bigstring_response_body_write () =
  let response_payload = "bigstring-body-payload" in
  let payload_bs = Bigstringaf.of_string ~off:0 ~len:(String.length response_payload) response_payload in
  let pending_response_body = ref None in
  let client_received = Buffer.create (String.length response_payload) in
  let client_done = ref false in
  let server_request_handler reqd =
    let body = Reqd.respond_with_streaming reqd (Response.create `OK) in
    Body.Writer.write_bigstring body payload_bs;
    Body.Writer.close body
  in
  let client_response_handler response response_body =
    let { Response.status; _ } = response in
    Alcotest.(check int) "response status" 200 (Status.to_code status);
    pending_response_body := Some response_body
  in
  let now, client, server, client_conn, _server_conn = create_stack ~server_request_handler in
  let got_conn =
    run_until ~now ~client ~server ~max_steps:20_000 (fun () -> Option.is_some !client_conn)
  in
  Alcotest.(check bool) "client connection established" true got_conn;
  let conn = Option.get !client_conn |> to_public_client_connection in
  let request =
    Request.create
      ~scheme:"https"
      ~headers:(Headers.of_list [ ":authority", "localhost" ])
      `GET
      "/file"
  in
  let request_body =
    Client_connection.request
      conn
      request
      ~error_handler:(fun _ -> Alcotest.fail "unexpected request error")
      ~response_handler:client_response_handler
  in
  Body.Writer.close request_body;
  let got_response_headers =
    run_until ~now ~client ~server ~max_steps:50_000 (fun () -> Option.is_some !pending_response_body)
  in
  Alcotest.(check bool) "client received response headers" true got_response_headers;
  let response_body = Option.get !pending_response_body in
  schedule_read_all
    response_body
    (fun bs ~off ~len -> Buffer.add_string client_received (Bigstringaf.substring bs ~off ~len))
    (fun () -> client_done := true);
  let completed =
    run_until ~now ~client ~server ~max_steps:50_000 (fun () -> !client_done)
  in
  Alcotest.(check bool) "response body completed" true completed;
  Alcotest.(check string)
    "client received full bigstring response body"
    response_payload
    (Buffer.contents client_received)

let () =
  Mirage_crypto_rng_unix.use_default ();
  Alcotest.run
    "h3-body"
    [ ( "body"
      , [ "unknown unidirectional stream type", `Quick, test_unknown_unidirectional_stream_type_is_ignored
        ; "client duplicate critical stream", `Quick, test_client_rejects_duplicate_critical_streams
        ; "server duplicate critical stream", `Quick, test_server_rejects_duplicate_critical_streams
        ; "buffered request body delivery", `Quick, test_buffered_request_body_delivery
        ; "buffered response body delivery", `Quick, test_buffered_response_body_delivery
        ; "bigstring response body write", `Quick, test_bigstring_response_body_write
        ] ) ]
