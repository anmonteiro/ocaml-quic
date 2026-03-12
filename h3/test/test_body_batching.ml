module Quic_internal = Quic__
module Body = H3__Body
module Reqd = H3__Reqd
module Server_connection = H3__Server_connection
module Serialize = H3__Serialize
module Request = H3__Request
module Headers = H3__Headers

let make_stream id =
  (Obj.magic
     (Quic_internal.Stream.create
        ~typ:(Quic_internal.Stream.Type.Client Quic_internal.Direction.Bidirectional)
        ~id
        ~report_application_error:ignore
        ignore)
    : Quic.Stream.t)

let make_stream_state () =
  let stream = make_stream 0L in
  let encoder_stream = make_stream 2L in
  let request_body = Body.Reader.create (Bigstringaf.create 0x1000) in
  let request =
    let headers = Headers.add Headers.empty ":authority" "localhost" in
    Request.create ~scheme:"https" ~headers `POST "/upload"
  in
  let reqd =
    Reqd.create
      (fun ?request:_ _error _respond -> ())
      ~stream_id:(Quic.Stream.id stream)
      ~encoder:(Qpack.Encoder.create 0)
      ~encoder_stream
      request
      request_body
      stream
      (Serialize.Writer.create stream)
  in
  let stream_state : Server_connection.stream =
    { stream
    ; direction = Quic.Direction.Bidirectional
    ; reqd = Some reqd
    ; writer = Serialize.Writer.create stream
    }
  in
  stream_state, request_body

let test_server_request_body_flush_batches_pending_data_frames () =
  let stream_state, request_body = make_stream_state () in
  let delivered_bytes = ref 0 in
  let read_callbacks = ref 0 in
  let eof = ref false in
  let schedule_reader () =
    let rec read_body () =
      Body.Reader.schedule_read
        request_body
        ~on_eof:(fun () -> eof := true)
        ~on_read:(fun _buffer ~off:_ ~len ->
          incr read_callbacks;
          delivered_bytes := !delivered_bytes + len;
          if !delivered_bytes < 8 then read_body ())
    in
    read_body ()
  in
  schedule_reader ();
  Server_connection.process_data_frame
    stream_state
    (Bigstringaf.of_string ~off:0 ~len:4 "abcd");
  Server_connection.process_data_frame
    stream_state
    (Bigstringaf.of_string ~off:0 ~len:4 "efgh");
  Alcotest.(check int)
    "process_data_frame does not wake the body reader immediately"
    0
    !read_callbacks;
  Server_connection.flush_request_body stream_state;
  Alcotest.(check int) "all bytes delivered" 8 !delivered_bytes;
  Alcotest.(check int)
    "multiple pending DATA frames are delivered in a single application callback"
    1
    !read_callbacks;
  Alcotest.(check bool) "reader stays open until EOF" false !eof

let bigstring_of_char c len =
  Bigstringaf.of_string ~off:0 ~len (String.make len c)

let test_server_request_body_flush_keeps_coalescing_to_contiguous_prefix () =
  let stream_state, request_body = make_stream_state () in
  let deliveries = ref [] in
  let schedule_once () =
    Body.Reader.schedule_read
      request_body
      ~on_eof:(fun () -> Alcotest.fail "unexpected eof")
      ~on_read:(fun _buffer ~off:_ ~len -> deliveries := len :: !deliveries)
  in
  schedule_once ();
  Server_connection.process_data_frame
    stream_state
    (bigstring_of_char 'a' 0x8000);
  Server_connection.process_data_frame
    stream_state
    (bigstring_of_char 'b' 40000);
  Server_connection.process_data_frame
    stream_state
    (bigstring_of_char 'c' 8);
  Server_connection.flush_request_body stream_state;
  Alcotest.(check (list int))
    "first callback only receives the contiguous prefix that fits the coalescing budget"
    [ 0x8000 ]
    (List.rev !deliveries);
  schedule_once ();
  Alcotest.(check (list int))
    "second callback receives the next contiguous prefix"
    [ 0x8000; 40008 ]
    (List.rev !deliveries)

let () =
  Alcotest.run
    "h3-body-batching"
    [ ( "server-connection"
      , [ ( "flush_request_body batches pending DATA frames into one callback"
          , `Quick
          , test_server_request_body_flush_batches_pending_data_frames )
        ; ( "flush_request_body preserves contiguous iovec ordering when batching"
          , `Quick
          , test_server_request_body_flush_keeps_coalescing_to_contiguous_prefix )
        ] ) ]
