module Quic = Quic__
open Quic

let make_stream ?(on_bytes_read = fun _ -> ()) () =
  Stream.create
    ~typ:(Stream.Type.Client Direction.Bidirectional)
    ~id:0L
    ~report_application_error:ignore
    ~on_bytes_read
    ignore

let fragment ~off data =
  let len = String.length data in
  { Frame.off = off
  ; len
  ; payload = Frame.String data
  ; payload_off = 0
  }

let test_in_order_push_is_immediately_poppable () =
  let stream = make_stream () in
  Stream.Recv.push (fragment ~off:0 "abcd") ~is_fin:false stream.recv;
  match Stream.Recv.pop stream.recv with
  | None -> Alcotest.fail "expected in-order fragment to be poppable"
  | Some fragment ->
    Alcotest.(check int) "fragment offset" 0 fragment.Frame.off;
    Alcotest.(check int) "fragment len" 4 fragment.Frame.len;
    Alcotest.(check string)
      "fragment payload"
      "abcd"
      (Frame.payload_substring fragment.Frame.payload ~off:0 ~len:fragment.Frame.len);
    Alcotest.(check (option int)) "no queued fragment remains" None
      (Option.map (fun { Frame.len; _ } -> len) (Stream.Recv.pop stream.recv))

let test_out_of_order_push_still_queues () =
  let callbacks = ref 0 in
  let stream = make_stream () in
  Stream.schedule_read
    stream
    ~on_eof:(fun () -> Alcotest.fail "unexpected eof")
    ~on_read:(fun _buffer ~off:_ ~len:_ -> incr callbacks);
  Stream.Recv.push (fragment ~off:4 "efgh") ~is_fin:false stream.recv;
  Alcotest.(check int) "out-of-order fragment not delivered early" 0 !callbacks;
  Alcotest.(check (option int))
    "out-of-order fragment is not yet contiguous"
    None
    (Option.map (fun { Frame.len; _ } -> len) (Stream.Recv.pop stream.recv))

let test_in_order_push_coexists_with_queued_follow_on_data () =
  let bytes_read = ref 0 in
  let delivered = ref [] in
  let stream = make_stream ~on_bytes_read:(fun n -> bytes_read := !bytes_read + n) () in
  let rec read_body () =
    Stream.schedule_read
      stream
      ~on_eof:(fun () -> ())
      ~on_read:(fun _buffer ~off:_ ~len ->
        delivered := len :: !delivered;
        read_body ())
  in
  read_body ();
  Stream.Recv.push (fragment ~off:4 "efgh") ~is_fin:false stream.recv;
  Stream.Recv.push (fragment ~off:0 "abcd") ~is_fin:false stream.recv;
  let rec drain () =
    match Stream.Recv.pop stream.recv with
    | Some _ -> drain ()
    | None -> ()
  in
  drain ();
  Alcotest.(check (list int))
    "received both fragments in order"
    [ 4; 4 ]
    (List.rev !delivered);
  Alcotest.(check int) "all bytes accounted for" 8 !bytes_read

let test_send_pop_preserves_fifo_for_fresh_data () =
  let send = Stream.Send.create ignore in
  ignore (Stream.Send.push "ab" send : Frame.fragment);
  ignore (Stream.Send.push "cdef" send : Frame.fragment);
  let first, is_fin_1 = Option.get (Stream.Send.pop send) in
  let second, is_fin_2 = Option.get (Stream.Send.pop send) in
  Alcotest.(check int) "first offset" 0 first.Frame.off;
  Alcotest.(check int) "first len" 2 first.len;
  Alcotest.(check bool) "first not fin" false is_fin_1;
  Alcotest.(check int) "second offset" 2 second.Frame.off;
  Alcotest.(check int) "second len" 4 second.len;
  Alcotest.(check bool) "second not fin" false is_fin_2

let test_send_requeue_precedes_fresh_data () =
  let send = Stream.Send.create ignore in
  let first = Stream.Send.push "ab" send in
  ignore (Stream.Send.push "cdef" send : Frame.fragment);
  ignore (Option.get (Stream.Send.pop send) : Frame.fragment * bool);
  Stream.Send.requeue first send;
  let fragment, _ = Option.get (Stream.Send.pop send) in
  Alcotest.(check int) "requeued offset popped first" 0 fragment.Frame.off;
  Alcotest.(check string)
    "requeued payload"
    "ab"
    (Frame.payload_substring fragment.payload ~off:0 ~len:fragment.len)

let test_send_fin_waits_for_deferred_queue_to_empty () =
  let stream = make_stream () in
  Stream.write_string stream "ab";
  Stream.close_writer stream;
  ignore (Stream.Send.flush stream.send : int);
  let first, is_fin_1 = Option.get (Stream.Send.pop stream.send) in
  Stream.Send.requeue first stream.send;
  let again, is_fin_2 = Option.get (Stream.Send.pop stream.send) in
  ignore (Stream.Send.flush stream.send : int);
  let eof_fragment, is_fin_3 = Option.get (Stream.Send.pop stream.send) in
  Alcotest.(check bool) "data fragment is not fin before deferred replay" false is_fin_1;
  Alcotest.(check int) "replayed fragment offset" 0 again.Frame.off;
  Alcotest.(check bool) "replayed data still not fin while eof queued" false is_fin_2;
  Alcotest.(check int) "final fragment empty" 0 eof_fragment.Frame.len;
  Alcotest.(check bool) "empty terminal fragment carries fin" true is_fin_3

let () =
  Alcotest.run
    "stream"
    [ ( "recv"
      , [ ( "in-order push delivers immediately when reader is waiting"
          , `Quick
          , test_in_order_push_is_immediately_poppable )
        ; ( "out-of-order push still queues"
          , `Quick
          , test_out_of_order_push_still_queues )
        ; ( "in-order push coexists with queued follow-on data"
          , `Quick
          , test_in_order_push_coexists_with_queued_follow_on_data )
        ] )
    ; ( "send"
      , [ "fresh data preserves fifo order", `Quick, test_send_pop_preserves_fifo_for_fresh_data
        ; "requeue precedes fresh data", `Quick, test_send_requeue_precedes_fresh_data
        ; ( "fin waits for deferred queue to empty"
          , `Quick
          , test_send_fin_waits_for_deferred_queue_to_empty )
        ] )
    ]
