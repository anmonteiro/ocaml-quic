module Quic = Quic__
open Quic

let range first last =
  { Frame.Range.first = Int64.of_int first; last = Int64.of_int last }

let ack t ~encryption_level ranges =
  Recovery.on_ack_received
    t
    ~encryption_level
    ~ranges:(List.map (fun (first, last) -> range first last) ranges)

let sent_info t ~encryption_level : Recovery.info =
  Spaces.of_encryption_level t encryption_level

let sent_packet_numbers t ~encryption_level =
  let info = sent_info t ~encryption_level in
  Recovery.Q.to_list info.sent |> List.map fst

let sent_size t ~encryption_level =
  let info = sent_info t ~encryption_level in
  Recovery.Q.size info.sent

let sort_ints xs = List.sort compare xs

let send_marker t ~encryption_level ~packet_number marker =
  Recovery.on_packet_sent
    t
    ~encryption_level
    ~packet_number:(Int64.of_int packet_number)
    [ Frame.Max_data marker ]

let marker_of_frame = function
  | Frame.Max_data marker -> marker
  | frame ->
    Alcotest.failf
      "expected Max_data marker frame, got frame type 0x%x"
      (Frame.Type.serialize (Frame.to_frame_type frame))

let drain_markers t ~encryption_level =
  Recovery.drain_acknowledged t ~encryption_level |> List.map marker_of_frame

let ranges_of_tuples ranges = List.map (fun (first, last) -> range first last) ranges

let debug_send
      t
      ~encryption_level
      ~packet_number
      ~time_sent_ms
      ~bytes_sent
      frames
  =
  Recovery.Debug.record_packet_sent
    t
    ~encryption_level
    ~packet_number:(Int64.of_int packet_number)
    ~bytes_sent
    ~time_sent_ms:(Int64.of_int time_sent_ms)
    frames

let debug_ack t ~encryption_level ~ranges ~ack_delay_ms ~now_ms =
  Recovery.Debug.record_ack_received
    t
    ~encryption_level
    ~ranges:(ranges_of_tuples ranges)
    ~ack_delay_ms:(Int64.of_int ack_delay_ms)
    ~now_ms:(Int64.of_int now_ms)

let debug_snapshot t = Recovery.Debug.snapshot t

let test_rfc9002_a2_constants () =
  Alcotest.(check int64)
    "kPacketThreshold"
    3L
    Recovery.Constants.k_packet_threshold;
  Alcotest.(check int64)
    "kTimeThreshold numerator"
    9L
    Recovery.Constants.k_time_threshold_num;
  Alcotest.(check int64)
    "kTimeThreshold denominator"
    8L
    Recovery.Constants.k_time_threshold_den;
  Alcotest.(check int64)
    "kGranularity (ms)"
    1L
    Recovery.Constants.k_granularity_ms;
  Alcotest.(check int64)
    "kInitialRtt (ms)"
    333L
    Recovery.Constants.k_initial_rtt_ms;
  Alcotest.(check int64)
    "kPersistentCongestionThreshold"
    3L
    Recovery.Constants.k_persistent_congestion_threshold

let test_rfc9002_7_2_initial_window_formula () =
  Alcotest.(check int)
    "initial window at 1200-byte datagrams"
    12000
    (Recovery.Constants.initial_window ~max_datagram_size:1200);
  Alcotest.(check int)
    "initial window at 1500-byte datagrams"
    14720
    (Recovery.Constants.initial_window ~max_datagram_size:1500);
  Alcotest.(check int)
    "minimum window at 1200-byte datagrams"
    2400
    (Recovery.Constants.minimum_window ~max_datagram_size:1200)

let test_rfc9002_6_4_discarding_keys_drops_space_state () =
  let t = Recovery.create () in
  send_marker t ~encryption_level:Initial ~packet_number:0 10;
  send_marker t ~encryption_level:Handshake ~packet_number:0 20;
  send_marker t ~encryption_level:Application_data ~packet_number:0 30;
  Recovery.Debug.discard_space t ~encryption_level:Initial;
  Alcotest.(check int)
    "initial space cleared"
    0
    (sent_size t ~encryption_level:Initial);
  Alcotest.(check int)
    "handshake space untouched"
    1
    (sent_size t ~encryption_level:Handshake);
  Alcotest.(check int)
    "application-data space untouched"
    1
    (sent_size t ~encryption_level:Application_data)

let test_rfc9002_6_4_discarding_keys_clears_ack_queue_for_space () =
  let t = Recovery.create () in
  send_marker t ~encryption_level:Initial ~packet_number:0 10;
  ack t ~encryption_level:Initial [ 0, 0 ];
  Alcotest.(check (list int))
    "marker enters ack queue before discard"
    [ 10 ]
    (drain_markers t ~encryption_level:Initial);
  send_marker t ~encryption_level:Initial ~packet_number:1 11;
  ack t ~encryption_level:Initial [ 1, 1 ];
  Recovery.Debug.discard_space t ~encryption_level:Initial;
  Alcotest.(check (list int))
    "ack queue cleared by discard"
    []
    (drain_markers t ~encryption_level:Initial)

let test_rfc9002_5_3_first_rtt_sample_initializes_estimators () =
  let t = Recovery.create () in
  debug_send
    t
    ~encryption_level:Application_data
    ~packet_number:1
    ~time_sent_ms:100
    ~bytes_sent:1200
    [ Frame.Ping ];
  debug_ack
    t
    ~encryption_level:Application_data
    ~ranges:[ 1, 1 ]
    ~ack_delay_ms:0
    ~now_ms:160;
  let s = debug_snapshot t in
  Alcotest.(check (option int64))
    "latest_rtt"
    (Some 60L)
    s.rtt.latest_rtt_ms;
  Alcotest.(check (option int64))
    "min_rtt"
    (Some 60L)
    s.rtt.min_rtt_ms;
  Alcotest.(check int64)
    "smoothed_rtt"
    60L
    s.rtt.smoothed_rtt_ms;
  Alcotest.(check int64)
    "rttvar"
    30L
    s.rtt.rttvar_ms

let test_rfc9002_5_3_second_rtt_sample_updates_smoothing () =
  let t = Recovery.create () in
  debug_send
    t
    ~encryption_level:Application_data
    ~packet_number:1
    ~time_sent_ms:100
    ~bytes_sent:1200
    [ Frame.Ping ];
  debug_ack
    t
    ~encryption_level:Application_data
    ~ranges:[ 1, 1 ]
    ~ack_delay_ms:0
    ~now_ms:160;
  debug_send
    t
    ~encryption_level:Application_data
    ~packet_number:2
    ~time_sent_ms:300
    ~bytes_sent:1200
    [ Frame.Ping ];
  debug_ack
    t
    ~encryption_level:Application_data
    ~ranges:[ 2, 2 ]
    ~ack_delay_ms:10
    ~now_ms:390;
  let s = debug_snapshot t in
  Alcotest.(check (option int64))
    "latest_rtt"
    (Some 90L)
    s.rtt.latest_rtt_ms;
  Alcotest.(check (option int64))
    "min_rtt"
    (Some 60L)
    s.rtt.min_rtt_ms;
  Alcotest.(check int64)
    "smoothed_rtt (7/8 old + 1/8 adjusted)"
    62L
    s.rtt.smoothed_rtt_ms;
  Alcotest.(check int64)
    "rttvar (3/4 old + 1/4 abs error)"
    27L
    s.rtt.rttvar_ms

let test_rfc9002_5_3_ack_delay_clamped_by_max_ack_delay () =
  let t = Recovery.create () in
  debug_send
    t
    ~encryption_level:Application_data
    ~packet_number:1
    ~time_sent_ms:0
    ~bytes_sent:1200
    [ Frame.Ping ];
  debug_ack
    t
    ~encryption_level:Application_data
    ~ranges:[ 1, 1 ]
    ~ack_delay_ms:0
    ~now_ms:100;
  debug_send
    t
    ~encryption_level:Application_data
    ~packet_number:2
    ~time_sent_ms:200
    ~bytes_sent:1200
    [ Frame.Ping ];
  debug_ack
    t
    ~encryption_level:Application_data
    ~ranges:[ 2, 2 ]
    ~ack_delay_ms:100
    ~now_ms:340;
  let s = debug_snapshot t in
  Alcotest.(check (option int64))
    "latest_rtt"
    (Some 140L)
    s.rtt.latest_rtt_ms;
  Alcotest.(check int64)
    "smoothed_rtt uses max_ack_delay clamp (25ms)"
    101L
    s.rtt.smoothed_rtt_ms;
  Alcotest.(check int64)
    "rttvar with clamped adjustment"
    40L
    s.rtt.rttvar_ms

let test_rfc9002_5_1_duplicate_ack_does_not_generate_new_rtt_sample () =
  let t = Recovery.create () in
  debug_send
    t
    ~encryption_level:Application_data
    ~packet_number:1
    ~time_sent_ms:100
    ~bytes_sent:1200
    [ Frame.Ping ];
  debug_ack
    t
    ~encryption_level:Application_data
    ~ranges:[ 1, 1 ]
    ~ack_delay_ms:0
    ~now_ms:160;
  debug_ack
    t
    ~encryption_level:Application_data
    ~ranges:[ 1, 1 ]
    ~ack_delay_ms:0
    ~now_ms:260;
  let s = debug_snapshot t in
  Alcotest.(check (option int64))
    "latest_rtt unchanged on duplicate ACK"
    (Some 60L)
    s.rtt.latest_rtt_ms;
  Alcotest.(check int64)
    "smoothed_rtt unchanged on duplicate ACK"
    60L
    s.rtt.smoothed_rtt_ms

let test_rfc9002_6_2_1_pto_armed_after_ack_eliciting_send () =
  let t = Recovery.create () in
  debug_send
    t
    ~encryption_level:Application_data
    ~packet_number:1
    ~time_sent_ms:0
    ~bytes_sent:1200
    [ Frame.Ping ];
  let s = debug_snapshot t in
  Alcotest.(check (option int64))
    "loss detection timer is armed"
    (Some 1022L)
    s.timer.loss_detection_timer_ms

let test_rfc9002_6_2_1_ack_only_without_in_flight_does_not_arm_pto () =
  let t = Recovery.create () in
  debug_send
    t
    ~encryption_level:Application_data
    ~packet_number:1
    ~time_sent_ms:0
    ~bytes_sent:0
    [ Frame.Ack
        { delay = 0
        ; ranges = [ { Frame.Range.first = 0L; last = 0L } ]
        ; ecn_counts = None
        }
    ];
  let s = debug_snapshot t in
  Alcotest.(check (option int64))
    "no PTO when nothing in flight"
    None
    s.timer.loss_detection_timer_ms

let test_rfc9002_6_2_1_pto_backoff_increases_pto_count () =
  let t = Recovery.create () in
  debug_send
    t
    ~encryption_level:Application_data
    ~packet_number:1
    ~time_sent_ms:0
    ~bytes_sent:1200
    [ Frame.Ping ];
  Recovery.Debug.on_loss_detection_timeout t ~now_ms:1022L;
  let s = debug_snapshot t in
  Alcotest.(check int)
    "pto_count increments after timeout"
    1
    s.timer.pto_count

let test_rfc9002_6_1_2_time_threshold_loss_detection () =
  let t = Recovery.create () in
  debug_send
    t
    ~encryption_level:Application_data
    ~packet_number:10
    ~time_sent_ms:0
    ~bytes_sent:1200
    [ Frame.Ping ];
  debug_ack
    t
    ~encryption_level:Application_data
    ~ranges:[ 10, 10 ]
    ~ack_delay_ms:0
    ~now_ms:20;
  debug_send
    t
    ~encryption_level:Application_data
    ~packet_number:11
    ~time_sent_ms:30
    ~bytes_sent:1200
    [ Frame.Ping ];
  debug_send
    t
    ~encryption_level:Application_data
    ~packet_number:12
    ~time_sent_ms:40
    ~bytes_sent:1200
    [ Frame.Ping ];
  debug_ack
    t
    ~encryption_level:Application_data
    ~ranges:[ 12, 12 ]
    ~ack_delay_ms:0
    ~now_ms:70;
  Alcotest.(check (list int))
    "packet 11 should be declared lost by time-threshold"
    []
    (sent_packet_numbers t ~encryption_level:Application_data
     |> List.map Int64.to_int
     |> List.filter (fun pn -> pn = 11))

let test_rfc9002_7_3_slow_start_increases_cwnd_by_bytes_acked () =
  let t = Recovery.create () in
  debug_send
    t
    ~encryption_level:Application_data
    ~packet_number:1
    ~time_sent_ms:0
    ~bytes_sent:1200
    [ Frame.Ping ];
  debug_ack
    t
    ~encryption_level:Application_data
    ~ranges:[ 1, 1 ]
    ~ack_delay_ms:0
    ~now_ms:50;
  let s = debug_snapshot t in
  Alcotest.(check int)
    "slow-start cwnd grows by bytes acknowledged"
    13200
    s.congestion.congestion_window

let test_rfc9002_7_3_bytes_in_flight_tracks_acked_packets () =
  let t = Recovery.create () in
  debug_send
    t
    ~encryption_level:Application_data
    ~packet_number:1
    ~time_sent_ms:0
    ~bytes_sent:1200
    [ Frame.Ping ];
  let s_before = debug_snapshot t in
  Alcotest.(check int)
    "bytes_in_flight after send"
    1200
    s_before.congestion.bytes_in_flight;
  debug_ack
    t
    ~encryption_level:Application_data
    ~ranges:[ 1, 1 ]
    ~ack_delay_ms:0
    ~now_ms:50;
  let s_after = debug_snapshot t in
  Alcotest.(check int)
    "bytes_in_flight after ack"
    0
    s_after.congestion.bytes_in_flight

let test_rfc9002_7_6_persistent_congestion_collapses_to_min_window () =
  let t = Recovery.create () in
  debug_send
    t
    ~encryption_level:Application_data
    ~packet_number:1
    ~time_sent_ms:0
    ~bytes_sent:1200
    [ Frame.Ping ];
  Recovery.Debug.on_loss_detection_timeout t ~now_ms:1022L;
  Recovery.Debug.on_loss_detection_timeout t ~now_ms:2044L;
  Recovery.Debug.on_loss_detection_timeout t ~now_ms:4088L;
  let s = debug_snapshot t in
  Alcotest.(check int)
    "persistent congestion collapses cwnd to minimum window"
    (Recovery.Constants.minimum_window
       ~max_datagram_size:Recovery.Constants.default_max_datagram_size)
    s.congestion.congestion_window

let test_rfc9002_7_1_ecn_validates_counters_before_reacting () =
  let t = Recovery.create () in
  Recovery.Debug.process_ecn
    t
    ~newly_acked:1200
    ~ect0_count:10
    ~ect1_count:0
    ~ce_count:0;
  let s = debug_snapshot t in
  Alcotest.(check bool)
    "ECN should become validated after receiving consistent counters"
    true
    s.ecn.validated

let test_rfc9002_7_1_ecn_ce_marks_trigger_congestion_response () =
  let t = Recovery.create () in
  let initial = (debug_snapshot t).congestion.congestion_window in
  Recovery.Debug.process_ecn
    t
    ~newly_acked:1200
    ~ect0_count:10
    ~ect1_count:0
    ~ce_count:2;
  let s = debug_snapshot t in
  Alcotest.(check bool)
    "CE markings should reduce congestion window"
    true
    (s.congestion.congestion_window < initial)

let test_rfc9002_7_1_ecn_counters_are_tracked () =
  let t = Recovery.create () in
  Recovery.Debug.process_ecn
    t
    ~newly_acked:1200
    ~ect0_count:12
    ~ect1_count:3
    ~ce_count:4;
  let s = debug_snapshot t in
  Alcotest.(check int) "ect0 counter" 12 s.ecn.ect0;
  Alcotest.(check int) "ect1 counter" 3 s.ecn.ect1;
  Alcotest.(check int) "ce counter" 4 s.ecn.ce

module Packet_threshold_spec = struct
  let k_packet_threshold = 3L

  let contains pn (first, last) =
    Int64.compare pn (Int64.of_int first) >= 0
    && Int64.compare pn (Int64.of_int last) <= 0

  let is_acked pn ranges = List.exists (contains pn) ranges

  let max_opt_int64 xs =
    List.fold_left
      (fun acc x ->
         match acc with
         | None -> Some x
         | Some current -> Some (Int64.max current x))
      None
      xs

  let expected_remaining ~sent ~ranges =
    let sent_i64 = List.map Int64.of_int sent in
    let acked = List.filter (fun pn -> is_acked pn ranges) sent_i64 in
    let not_acked = List.filter (fun pn -> not (is_acked pn ranges)) sent_i64 in
    match max_opt_int64 acked with
    | None -> not_acked
    | Some largest_newly_acked ->
      List.filter
        (fun pn ->
           Int64.compare
             (Int64.add pn k_packet_threshold)
             largest_newly_acked
           > 0)
        not_acked

  let expected_remaining_ints ~sent ~ranges =
    expected_remaining ~sent ~ranges |> List.map Int64.to_int
end

let test_rfc9002_2_ack_eliciting_packets_only () =
  let t = Recovery.create () in
  Recovery.on_packet_sent
    t
    ~encryption_level:Application_data
    ~packet_number:0L
    [ Frame.Ack
        { delay = 0
        ; ranges = [ { Frame.Range.first = 0L; last = 0L } ]
        ; ecn_counts = None
        }
    ];
  Recovery.on_packet_sent
    t
    ~encryption_level:Application_data
    ~packet_number:1L
    [ Frame.Padding 8 ];
  Recovery.on_packet_sent
    t
    ~encryption_level:Application_data
    ~packet_number:2L
    [ Frame.Connection_close_quic
        { frame_type = Frame.Type.Padding
        ; reason_phrase = ""
        ; error_code = Error.No_error
        }
    ];
  Recovery.on_packet_sent
    t
    ~encryption_level:Application_data
    ~packet_number:3L
    [ Frame.Ping ];
  ack t ~encryption_level:Application_data [ 0, 3 ];
  match Recovery.drain_acknowledged t ~encryption_level:Application_data with
  | [ Frame.Ping ] -> ()
  | frames ->
    Alcotest.failf
      "expected only the PING frame to be ack-eliciting, got %d acked frames"
      (List.length frames)

let test_rfc9002_2_non_ack_eliciting_packets_are_removed_when_acked () =
  let t = Recovery.create () in
  Recovery.on_packet_sent
    t
    ~encryption_level:Application_data
    ~packet_number:0L
    [ Frame.Ack
        { delay = 0
        ; ranges = [ { Frame.Range.first = 0L; last = 0L } ]
        ; ecn_counts = None
        }
    ];
  ack t ~encryption_level:Application_data [ 0, 0 ];
  Alcotest.(check int)
    "packet removed from sent map"
    0
    (sent_size t ~encryption_level:Application_data);
  Alcotest.(check (list int))
    "non-ack-eliciting packet does not enter acked queue"
    []
    (drain_markers t ~encryption_level:Application_data)

let test_rfc9002_3_packet_number_spaces_are_independent () =
  let t = Recovery.create () in
  send_marker t ~encryption_level:Initial ~packet_number:0 10;
  send_marker t ~encryption_level:Handshake ~packet_number:0 20;
  send_marker t ~encryption_level:Application_data ~packet_number:0 30;
  ack t ~encryption_level:Handshake [ 0, 0 ];
  Alcotest.(check (list int))
    "handshake acked markers"
    [ 20 ]
    (drain_markers t ~encryption_level:Handshake);
  Alcotest.(check (list int))
    "initial has no acked frames"
    []
    (drain_markers t ~encryption_level:Initial);
  Alcotest.(check (list int))
    "application_data has no acked frames"
    []
    (drain_markers t ~encryption_level:Application_data);
  Alcotest.(check int)
    "initial outstanding"
    1
    (sent_size t ~encryption_level:Initial);
  Alcotest.(check int)
    "handshake outstanding"
    0
    (sent_size t ~encryption_level:Handshake);
  Alcotest.(check int)
    "application_data outstanding"
    1
    (sent_size t ~encryption_level:Application_data)

let test_rfc9002_3_zero_rtt_and_1rtt_share_application_space () =
  let t = Recovery.create () in
  send_marker t ~encryption_level:Zero_RTT ~packet_number:5 42;
  ack t ~encryption_level:Application_data [ 5, 5 ];
  Alcotest.(check (list int))
    "zero-rtt acked from app-data pn space"
    [ 42 ]
    (drain_markers t ~encryption_level:Application_data);
  Alcotest.(check int)
    "application_data outstanding"
    0
    (sent_size t ~encryption_level:Application_data)

let test_rfc9002_13_selective_ack_ranges () =
  let t = Recovery.create () in
  for pn = 0 to 5 do
    send_marker t ~encryption_level:Application_data ~packet_number:pn pn
  done;
  ack t ~encryption_level:Application_data [ 0, 0; 2, 3; 5, 5 ];
  Alcotest.(check (list int))
    "acked markers"
    [ 0; 2; 3; 5 ]
    (drain_markers t ~encryption_level:Application_data |> sort_ints);
  Alcotest.(check (list int))
    "outstanding packet numbers"
    [ 1; 4 ]
    (sent_packet_numbers t ~encryption_level:Application_data
     |> List.map Int64.to_int)

let test_rfc9002_13_duplicate_ack_is_idempotent () =
  let t = Recovery.create () in
  send_marker t ~encryption_level:Application_data ~packet_number:7 7;
  ack t ~encryption_level:Application_data [ 7, 7 ];
  Alcotest.(check (list int))
    "first ack"
    [ 7 ]
    (drain_markers t ~encryption_level:Application_data);
  ack t ~encryption_level:Application_data [ 7, 7 ];
  Alcotest.(check (list int))
    "second ack does not duplicate frames"
    []
    (drain_markers t ~encryption_level:Application_data)

let test_rfc9002_13_overlapping_ranges_do_not_duplicate_frames () =
  let t = Recovery.create () in
  for pn = 0 to 3 do
    send_marker t ~encryption_level:Application_data ~packet_number:pn pn
  done;
  ack t ~encryption_level:Application_data [ 0, 2; 1, 3 ];
  Alcotest.(check (list int))
    "overlapping ranges are deduplicated"
    [ 0; 1; 2; 3 ]
    (drain_markers t ~encryption_level:Application_data |> sort_ints)

let test_rfc9002_13_acking_unsent_packet_is_noop () =
  let t = Recovery.create () in
  send_marker t ~encryption_level:Application_data ~packet_number:0 0;
  ack t ~encryption_level:Application_data [ 9, 9 ];
  Alcotest.(check (list int))
    "no frames acknowledged"
    []
    (drain_markers t ~encryption_level:Application_data);
  Alcotest.(check int)
    "sent packet remains outstanding"
    1
    (sent_size t ~encryption_level:Application_data)

let test_rfc9002_13_drain_acknowledged_is_one_shot () =
  let t = Recovery.create () in
  send_marker t ~encryption_level:Application_data ~packet_number:0 0;
  send_marker t ~encryption_level:Application_data ~packet_number:1 1;
  ack t ~encryption_level:Application_data [ 0, 1 ];
  Alcotest.(check (list int))
    "first drain"
    [ 0; 1 ]
    (drain_markers t ~encryption_level:Application_data |> sort_ints);
  Alcotest.(check (list int))
    "second drain is empty"
    []
    (drain_markers t ~encryption_level:Application_data)

let run_packet_threshold_case ~name ~sent ~ranges =
  let t = Recovery.create () in
  List.iter
    (fun pn -> send_marker t ~encryption_level:Application_data ~packet_number:pn pn)
    sent;
  ack t ~encryption_level:Application_data ranges;
  let expected = Packet_threshold_spec.expected_remaining_ints ~sent ~ranges in
  let actual =
    sent_packet_numbers t ~encryption_level:Application_data |> List.map Int64.to_int
  in
  Alcotest.(check (list int)) name expected actual

let test_rfc9002_6_1_1_packet_threshold_basic () =
  run_packet_threshold_case
    ~name:"kPacketThreshold=3 basic case"
    ~sent:[ 0; 1; 2; 3; 4; 5; 6 ]
    ~ranges:[ 6, 6 ]

let test_rfc9002_6_1_1_no_loss_before_threshold () =
  run_packet_threshold_case
    ~name:"no packet-threshold loss before 3 newer packets are acked"
    ~sent:[ 0; 1; 2; 3; 4; 5; 6 ]
    ~ranges:[ 2, 2 ]

let test_rfc9002_6_1_1_packet_threshold_with_disjoint_acks () =
  run_packet_threshold_case
    ~name:"packet-threshold applies with disjoint ACK ranges"
    ~sent:[ 0; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10 ]
    ~ranges:[ 5, 5; 10, 10 ]

let test_rfc9002_6_1_1_packet_threshold_sparse_outstanding_set () =
  run_packet_threshold_case
    ~name:"packet-threshold over sparse outstanding packet numbers"
    ~sent:[ 1; 2; 4; 6; 7; 8; 9 ]
    ~ranges:[ 9, 9 ]

let test_rfc9002_6_1_1_packet_threshold_is_exactly_three () =
  run_packet_threshold_case
    ~name:"packet-threshold is exactly three packets"
    ~sent:[ 0; 1; 2; 3; 4; 5 ]
    ~ranges:[ 3, 3 ]

let test_rfc9002_6_1_1_no_newly_acked_means_no_threshold_loss () =
  run_packet_threshold_case
    ~name:"no newly acked packets does not trigger threshold loss"
    ~sent:[ 1; 2; 3 ]
    ~ranges:[ 9, 9 ]

let make_client_connection_for_congestion_tests () =
  let source_cid = CID.generate () in
  let quic_transport_parameters =
    Transport_parameters.(
      encode
        [ Encoding.Initial_source_connection_id source_cid
        ; Active_connection_id_limit 2
        ; Initial_max_data (1 lsl 27)
        ; Initial_max_stream_data_bidi_local (1 lsl 27)
        ; Initial_max_stream_data_bidi_remote (1 lsl 27)
        ; Initial_max_stream_data_uni (1 lsl 27)
        ; Initial_max_streams_bidi (1 lsl 8)
        ; Initial_max_streams_uni (1 lsl 8)
        ])
  in
  let tls_state =
    Qtls.client
      ~authenticator:Config.null_auth
      ~alpn_protocols:[ "h3" ]
      ~host:"localhost"
      quic_transport_parameters
  in
  let connection_handler ~cid:_ ~start_stream:_ : Transport.stream_handler =
    Transport.F (fun _ -> { Transport.on_error = (fun _ -> ()) })
  in
  let connection =
    Transport.Connection.create
      ~mode:Client
      ~peer_address:"127.0.0.1:4433"
      ~tls_state
      ~wakeup_writer:(fun () -> ())
      ~shutdown:(fun _ -> ())
      ~connection_handler
      source_cid
  in
  let dest_cid = CID.generate () in
  connection.dest_cid <- dest_cid;
  Encryption_level.add
    Application_data
    { Crypto.encrypter = Crypto.InitialAEAD.make ~mode:Client dest_cid
    ; decrypter = None
    }
    connection.encdec;
  connection.encdec.current <- Application_data;
  connection

let create_data_stream connection =
  let typ = Stream.Type.Client Bidirectional in
  let stream_id = Stream.Type.gen_id ~typ 0L in
  Transport.Connection.create_stream connection ~typ ~id:stream_id

let queue_stream_payloads stream ~payload_len ~count =
  for _ = 1 to count do
    Stream.schedule_bigstring stream (Bigstringaf.create payload_len)
  done

let flush_stream_packets_until_pause connection =
  let rec loop sent_packets =
    match
      Transport.Connection.Streams.flush connection connection.streams
    with
    | Transport.Connection.Didnt_write -> sent_packets
    | Transport.Connection.Wrote | Transport.Connection.Wrote_app_data ->
      loop (sent_packets + 1)
  in
  loop 0

let flush_pending_packets connection =
  let rec loop sent_packets =
    match Transport.Connection._flush_pending_packets connection with
    | Transport.Connection.Didnt_write -> sent_packets
    | Transport.Connection.Wrote | Transport.Connection.Wrote_app_data ->
      loop (sent_packets + 1)
  in
  loop 0

let send_ack_only_packets connection count =
  let ack_only =
    Frame.Ack
      { delay = 0
      ; ranges = [ { Frame.Range.first = 0L; last = 0L } ]
      ; ecn_counts = None
      }
  in
  for _ = 1 to count do
    Transport.Connection.send_frames
      connection
      ~encryption_level:Application_data
      [ ack_only ]
  done;
  ignore (flush_pending_packets connection : int)

let test_rfc9002_7_2_sender_blocks_before_draining_queue () =
  let connection = make_client_connection_for_congestion_tests () in
  let stream = create_data_stream connection in
  queue_stream_payloads stream ~payload_len:1200 ~count:64;
  let writes = flush_stream_packets_until_pause connection in
  Alcotest.(check bool)
    "sender should not drain the full queue before acknowledgements"
    true
    (writes < 64)

let test_rfc9002_7_2_initial_window_upper_bound_for_1200_byte_packets () =
  let connection = make_client_connection_for_congestion_tests () in
  let stream = create_data_stream connection in
  queue_stream_payloads stream ~payload_len:1200 ~count:64;
  let writes = flush_stream_packets_until_pause connection in
  Alcotest.(check bool)
    "initial window should permit at most 10 1200-byte packets"
    true
    (writes <= 10)

let test_rfc9002_7_2_acknowledgements_unblock_sender () =
  let connection = make_client_connection_for_congestion_tests () in
  let stream = create_data_stream connection in
  queue_stream_payloads stream ~payload_len:1200 ~count:64;
  let writes_before_ack = flush_stream_packets_until_pause connection in
  Alcotest.(check bool)
    "sender should block before draining queue"
    true
    (writes_before_ack < 64);
  if writes_before_ack > 0
  then
    ack
      connection.recovery
      ~encryption_level:Application_data
      [ 0, writes_before_ack - 1 ];
  let writes_after_ack = flush_stream_packets_until_pause connection in
  Alcotest.(check bool)
    "sender should send more packets after ACKs free in-flight data"
    true
    (writes_after_ack > 0)

let test_rfc9002_7_2_ack_only_packets_do_not_reduce_send_budget () =
  let baseline_conn = make_client_connection_for_congestion_tests () in
  let baseline_stream = create_data_stream baseline_conn in
  queue_stream_payloads baseline_stream ~payload_len:1200 ~count:64;
  let baseline_writes = flush_stream_packets_until_pause baseline_conn in

  let conn_with_ack_only = make_client_connection_for_congestion_tests () in
  send_ack_only_packets conn_with_ack_only 32;
  let stream = create_data_stream conn_with_ack_only in
  queue_stream_payloads stream ~payload_len:1200 ~count:64;
  let writes_with_ack_only = flush_stream_packets_until_pause conn_with_ack_only in

  Alcotest.(check int)
    "ACK-only packets should not consume congestion window"
    baseline_writes
    writes_with_ack_only

let constants_suite =
  [ "A.2 constants of interest", `Quick, test_rfc9002_a2_constants
  ; "§7.2 window formulas", `Quick, test_rfc9002_7_2_initial_window_formula
  ]

let key_lifecycle_suite =
  [ "§6.4 discarding keys drops packet state", `Quick
    , test_rfc9002_6_4_discarding_keys_drops_space_state
  ; "§6.4 discarding keys clears ack queue", `Quick
    , test_rfc9002_6_4_discarding_keys_clears_ack_queue_for_space
  ]

let ack_processing_suite =
  [ "§2 ack-eliciting packet classification", `Quick
    , test_rfc9002_2_ack_eliciting_packets_only
  ; "§2 non-ack-eliciting packets are removed when ACKed", `Quick
    , test_rfc9002_2_non_ack_eliciting_packets_are_removed_when_acked
  ; "§3 packet-number spaces are independent", `Quick
    , test_rfc9002_3_packet_number_spaces_are_independent
  ; "§3 0-RTT and 1-RTT share application-data PN space", `Quick
    , test_rfc9002_3_zero_rtt_and_1rtt_share_application_space
  ; "§13 selective ACK ranges", `Quick, test_rfc9002_13_selective_ack_ranges
  ; "§13 duplicate ACK is idempotent", `Quick
    , test_rfc9002_13_duplicate_ack_is_idempotent
  ; "§13 overlapping ACK ranges do not duplicate frames", `Quick
    , test_rfc9002_13_overlapping_ranges_do_not_duplicate_frames
  ; "§13 ACK of unsent packet is a no-op", `Quick
    , test_rfc9002_13_acking_unsent_packet_is_noop
  ; "§13 acknowledged-frame drain is one-shot", `Quick
    , test_rfc9002_13_drain_acknowledged_is_one_shot
  ]

let loss_detection_suite =
  [ "§6.1.1 packet-threshold basic", `Quick
    , test_rfc9002_6_1_1_packet_threshold_basic
  ; "§6.1.1 no loss before threshold", `Quick
    , test_rfc9002_6_1_1_no_loss_before_threshold
  ; "§6.1.1 packet-threshold with disjoint ACK ranges", `Quick
    , test_rfc9002_6_1_1_packet_threshold_with_disjoint_acks
  ; "§6.1.1 packet-threshold with sparse outstanding set", `Quick
    , test_rfc9002_6_1_1_packet_threshold_sparse_outstanding_set
  ; "§6.1.1 packet-threshold is exactly three", `Quick
    , test_rfc9002_6_1_1_packet_threshold_is_exactly_three
  ; "§6.1.1 no newly ACKed packet means no threshold loss", `Quick
    , test_rfc9002_6_1_1_no_newly_acked_means_no_threshold_loss
  ]

let rtt_estimation_suite =
  [ "§5.3 first RTT sample initializes estimators", `Quick
    , test_rfc9002_5_3_first_rtt_sample_initializes_estimators
  ; "§5.3 second RTT sample applies smoothing", `Quick
    , test_rfc9002_5_3_second_rtt_sample_updates_smoothing
  ; "§5.3 ACK delay is clamped by max_ack_delay", `Quick
    , test_rfc9002_5_3_ack_delay_clamped_by_max_ack_delay
  ; "§5.1 duplicate ACK does not generate RTT sample", `Quick
    , test_rfc9002_5_1_duplicate_ack_does_not_generate_new_rtt_sample
  ]

let timer_pto_suite =
  [ "§6.2.1 PTO armed after ack-eliciting send", `Quick
    , test_rfc9002_6_2_1_pto_armed_after_ack_eliciting_send
  ; "§6.2.1 ACK-only without in-flight data does not arm PTO", `Quick
    , test_rfc9002_6_2_1_ack_only_without_in_flight_does_not_arm_pto
  ; "§6.2.1 PTO timeout increases backoff counter", `Quick
    , test_rfc9002_6_2_1_pto_backoff_increases_pto_count
  ]

let time_threshold_suite =
  [ "§6.1.2 time-threshold loss detection", `Quick
    , test_rfc9002_6_1_2_time_threshold_loss_detection
  ]

let ecn_suite =
  [ "§7.1 ECN counters are validated", `Quick
    , test_rfc9002_7_1_ecn_validates_counters_before_reacting
  ; "§7.1 CE markings trigger congestion response", `Quick
    , test_rfc9002_7_1_ecn_ce_marks_trigger_congestion_response
  ; "§7.1 ECN counters are tracked", `Quick
    , test_rfc9002_7_1_ecn_counters_are_tracked
  ]

let congestion_algorithm_suite =
  [ "§7.3 bytes_in_flight tracks acks", `Quick
    , test_rfc9002_7_3_bytes_in_flight_tracks_acked_packets
  ; "§7.3 slow-start increases cwnd by bytes acked", `Quick
    , test_rfc9002_7_3_slow_start_increases_cwnd_by_bytes_acked
  ; "§7.6 persistent congestion collapses cwnd", `Quick
    , test_rfc9002_7_6_persistent_congestion_collapses_to_min_window
  ]

let congestion_control_suite =
  [ "§7.2 sender blocks before draining queue", `Quick
    , test_rfc9002_7_2_sender_blocks_before_draining_queue
  ; "§7.2 initial window upper bound (1200-byte packets)", `Quick
    , test_rfc9002_7_2_initial_window_upper_bound_for_1200_byte_packets
  ; "§7.2 acknowledgements unblock sender", `Quick
    , test_rfc9002_7_2_acknowledgements_unblock_sender
  ; "§7.2 ACK-only packets do not consume window", `Quick
    , test_rfc9002_7_2_ack_only_packets_do_not_reduce_send_budget
  ]

let () =
  Mirage_crypto_rng_unix.use_default ();
  Alcotest.run
    "rfc9002"
    [ "constants", constants_suite
    ; "key lifecycle", key_lifecycle_suite
    ; "ack processing", ack_processing_suite
    ; "rtt estimation", rtt_estimation_suite
    ; "timer and pto", timer_pto_suite
    ; "loss detection", loss_detection_suite
    ; "time-threshold loss", time_threshold_suite
    ; "ecn", ecn_suite
    ; "congestion algorithm", congestion_algorithm_suite
    ; "congestion control", congestion_control_suite
    ]
