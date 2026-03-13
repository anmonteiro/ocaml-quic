module Quic = Quic__
open Quic

let hex = Alcotest.of_pp Hex.pp
let expected_dest_cid = `Hex "cb6241dbbc172d3ebf33a83a2271cd0c559293c9"

let read_file path =
  In_channel.with_open_bin path (fun ic ->
    let n = in_channel_length ic in
    really_input_string ic n)

let server_certificates () =
  let certchain =
    let pem = read_file "./certificates/server.pem" in
    match X509.Certificate.decode_pem_multiple pem with
    | Ok certchain -> certchain
    | Error (`Msg m) -> failwith m
  in
  let priv_key =
    let pem = read_file "./certificates/server.key" in
    match X509.Private_key.decode_pem pem with
    | Ok x -> x
    | Error (`Msg m) -> failwith m
  in
  `Single (certchain, priv_key)

let plaintext =
  Hex.to_string
    (`Hex
        "c0ff00001d14cb6241dbbc172d3ebf33a83a2271cd0c559293c910c78d00d671c14508476004fd071c92270040670000000102000000000600405a02000056030333e471d0747f6665b0791a6501070a4b2a30ab44453508ccab8d19211223570200130100002e002b0002030400330024001d002063817bf561dc6ec856426c806af204605fb1e8bb843ae7317c27356f9b222e0b")

let decrypt_stub ~payload_length:_ ~header:_ buf ~off ~len =
  let cs = Cstruct.of_bigarray ~off ~len buf in
  let header, plaintext = Cstruct.split cs 50 in
  Some
    { Crypto.AEAD.packet_number = 1L
    ; header = Cstruct.to_string header
    ; plaintext = Cstruct.to_string plaintext
    ; pn_length = 4
    }

let decrypt_stub_fast ~payload_length ~header ~header_prefix_len:_ buf ~off ~len =
  decrypt_stub ~payload_length ~header buf ~off ~len

let test_parser () =
  let buffer = Bigstringaf.of_string ~off:0 ~len:(String.length plaintext) plaintext in
  match
    Quic.Fast_parse.Packet_parser.parse
      ~decrypt:decrypt_stub_fast
      buffer
      ~off:0
      ~len:(Bigstringaf.length buffer)
  with
  | Packet (packet, consumed) ->
    Alcotest.(check int)
      "parser consumes the datagram"
      (String.length plaintext)
      consumed;
    (match packet with
    | Packet.Frames
        { header = Initial { version; source_cid; dest_cid; token }
        ; payload = _
        ; _
        } ->
      Alcotest.(check int32) "draft-29 version" 0xff00001dl version;
      Alcotest.check
        hex
        "source connection id"
        (`Hex "c78d00d671c14508476004fd071c9227")
        (Hex.of_string (CID.to_string source_cid));
      Alcotest.check
        hex
        "destination connection id"
        expected_dest_cid
        (Hex.of_string (CID.to_string dest_cid));
      Alcotest.(check string) "token is empty" "" token
    | _ -> Alcotest.fail "expected an initial packet with frames")
  | Skip _ -> Alcotest.fail "parser unexpectedly skipped packet"
  | Error (_packet, error, _) ->
    Alcotest.failf "parser returned packet error: %d@." (Error.serialize error)

let serialize_frame frame =
  let f = Faraday.create 128 in
  Quic.Serialize.Frame.write_frame f frame;
  Faraday.serialize_to_string f

let make_connection
      ?(mode = Quic.Crypto.Mode.Client)
      ?(remember_new_token = ignore)
      ?(transport_parameters = Quic.Config.default_transport_parameters)
      ()
  =
  let cid = Quic.CID.of_string "test-client-cid" in
  let tls_state =
    match mode with
    | Quic.Crypto.Mode.Client ->
      Quic.Qtls.client
        ~authenticator:Quic.Config.null_auth
        ~alpn_protocols:[ "h3" ]
        ~host:"localhost"
        (Quic.Transport_parameters.encode [])
    | Server ->
      Quic.Qtls.server ~certificates:(server_certificates ()) ~alpn_protocols:[ "h3" ]
  in
  let conn =
    Quic.Transport.Connection.create
      ~mode
      ~peer_address:"peer-address"
      ~tls_state
      ~transport_parameters
      ~now_ms:(fun () -> 0L)
      ~wakeup_writer:ignore
      ~shutdown:(fun _ -> ())
      ~connection_handler:(fun ~cid:_ ~start_stream:_ ->
        Quic.Transport.F (fun _ -> { Quic.Transport.on_error = ignore }))
      ~remember_new_token
      cid
  in
  conn.dest_cid <-
    Quic.CID.of_string
      (match mode with
      | Quic.Crypto.Mode.Client -> "test-server-cid"
      | Server -> "test-client-cid");
  Quic.Encryption_level.add
    Quic.Encryption_level.Initial
    { Quic.Crypto.encrypter =
        Quic.Crypto.InitialAEAD.make
          ~mode
          conn.dest_cid
    ; decrypter = None
    }
    conn.encdec;
  Quic.Encryption_level.add
    Quic.Encryption_level.Application_data
    { Quic.Crypto.encrypter =
        Quic.Crypto.InitialAEAD.make
          ~mode
          conn.dest_cid
    ; decrypter = None
    }
    conn.encdec;
  conn

let take_queued_packet conn =
  if Queue.is_empty conn.Quic.Transport.Connection.queued_packets
  then None
  else Some (Queue.take conn.queued_packets)

let take_queued_frames conn =
  match take_queued_packet conn with
  | None -> []
  | Some (_header_info, frames) -> frames

let test_fast_frame_parser_roundtrips_payload () =
  let payload =
    let frames =
      [ Frame.Ping
      ; Frame.Max_data 42
      ; Frame.Stream_data_blocked { id = 4L; max_data = 64 }
      ; Frame.Stream
          { id = 0L
          ; fragment =
              { Frame.off = 3
              ; len = 4
              ; payload = "abcd"
              ; payload_off = 0
              }
          ; is_fin = true
          }
      ; Frame.Connection_close_app { error_code = 7; reason_phrase = "bye" }
      ; Frame.Padding 2
      ]
    in
    let f = Faraday.create 256 in
    List.iter (Quic.Serialize.Frame.write_frame f) frames;
    let s = Faraday.serialize_to_string f in
    Bigstringaf.of_string ~off:0 ~len:(String.length s) s
  in
  let fast_frames = ref [] in
  (match
     Quic.Fast_parse.Frame.parse_bigstring
       payload
       ~handler:(fun frame -> fast_frames := frame :: !fast_frames)
   with
  | Ok () -> ()
  | Error e -> Alcotest.failf "fast frame parser failed: %s" e);
  let fast_frames = List.rev !fast_frames in
  Alcotest.(check string)
    "frame parser round-trips the payload"
    (Bigstringaf.to_string payload)
    (String.concat "" (List.map serialize_frame fast_frames))

let test_fast_frame_string_parser_matches_bigstring () =
  let payload =
    let frames =
      [ Frame.Ping
      ; Frame.Max_data 42
      ; Frame.Stream_data_blocked { id = 4L; max_data = 64 }
      ; Frame.Stream
          { id = 0L
          ; fragment =
              { Frame.off = 3
              ; len = 4
              ; payload = "abcd"
              ; payload_off = 0
              }
          ; is_fin = true
          }
      ; Frame.Connection_close_app { error_code = 7; reason_phrase = "bye" }
      ; Frame.Padding 2
      ]
    in
    let f = Faraday.create 256 in
    List.iter (Quic.Serialize.Frame.write_frame f) frames;
    Faraday.serialize_to_string f
  in
  let bigstring_frames = ref [] in
  (match
     Quic.Fast_parse.Frame.parse_bigstring
       (Bigstringaf.of_string ~off:0 ~len:(String.length payload) payload)
       ~handler:(fun frame -> bigstring_frames := frame :: !bigstring_frames)
   with
  | Ok () -> ()
  | Error e -> Alcotest.failf "fast bigstring frame parser failed: %s" e);
  let string_frames = ref [] in
  (match
     Quic.Fast_parse.Frame.parse_string
       payload
       ~handler:(fun frame -> string_frames := frame :: !string_frames)
   with
  | Ok () -> ()
  | Error e -> Alcotest.failf "fast string frame parser failed: %s" e);
  Alcotest.(check (list string))
    "string parser matches bigstring parser"
    (List.rev_map serialize_frame !bigstring_frames)
    (List.rev_map serialize_frame !string_frames)

let test_quic_transport_parameters () =
  let encoded_params =
    Hex.to_string
      (`Hex
          "010480007530030245460404809896800504800f42400604800f42400704800f424008024064090240640a01030b01190c000f14e8302a4aab4c1dc29add56136a6f4e030e826d72")
  in
  match Quic.Transport_parameters.Encoding.parse_string encoded_params with
  | Ok params ->
    let f = Faraday.create (String.length encoded_params) in
    Quic.Transport_parameters.Encoding.serialize f params;
    let serialized = Faraday.serialize_to_string f in
    Alcotest.check
      hex
      "roundtrip"
      (Hex.of_string encoded_params)
      (Hex.of_string serialized)
  | Error e -> Alcotest.fail e

let test_short_header () =
  let dest_cid = Quic.CID.(of_string (String.make src_length 'a')) in
  let f = Faraday.create 20 in
  Quic.Serialize.Pkt.Header.write_short_header f ~pn_length:4 ~dest_cid;
  (* Asserts that we don't write it for short headers *)
  Quic.Serialize.Pkt.Header.write_payload_length
    f
    ~pn_length:4
    ~header:(Quic.Packet.Header.Short { dest_cid })
    0;
  Quic.Serialize.Pkt.Header.write_packet_number
    f
    ~pn_length:4
    ~packet_number:12L;
  let hdr = Faraday.serialize_to_string f in
  match
    Quic.Fast_parse.Packet_parser.parse_protected_header
      (Bigstringaf.of_string ~off:0 ~len:(String.length hdr) hdr)
      ~off:0
      ~len:(String.length hdr)
  with
  | { header = Quic.Packet.Header.Short _; _ } -> ()
  | _ -> Alcotest.fail "expected short protected header"

let ack_ranges_to_tuples ranges =
  List.map
    (fun { Quic.Frame.Range.first; last } -> Int64.to_int first, Int64.to_int last)
    ranges

let test_packet_number_ack_ranges_are_incremental () =
  let pn = Quic.Transport.Packet_number.create () in
  List.iter
    (Quic.Transport.Packet_number.insert_for_acking pn)
    [ 1L; 2L; 4L; 3L; 7L; 6L; 5L; 20L ];
  match Quic.Transport.Packet_number.compose_ack_frame pn with
  | Frame.Ack { ranges; _ } ->
    Alcotest.(check (list (pair int int)))
      "ack ranges stay merged and sorted"
      [ 20, 20; 1, 7 ]
      (ack_ranges_to_tuples ranges)
  | _ -> Alcotest.fail "expected ACK frame"

let test_packet_number_ack_ranges_prune_old_packets () =
  let pn = Quic.Transport.Packet_number.create () in
  Quic.Transport.Packet_number.insert_for_acking pn 1L;
  Quic.Transport.Packet_number.insert_for_acking pn 5000L;
  match Quic.Transport.Packet_number.compose_ack_frame pn with
  | Frame.Ack { ranges; _ } ->
    Alcotest.(check (list (pair int int)))
      "old packet numbers are pruned from ack history"
      [ 5000, 5000 ]
      (ack_ranges_to_tuples ranges)
  | _ -> Alcotest.fail "expected ACK frame"

let test_packet_number_ack_ranges_merge_bridged_gap () =
  let pn = Quic.Transport.Packet_number.create () in
  List.iter
    (Quic.Transport.Packet_number.insert_for_acking pn)
    [ 10L; 11L; 13L; 12L ];
  match Quic.Transport.Packet_number.compose_ack_frame pn with
  | Frame.Ack { ranges; _ } ->
    Alcotest.(check (list (pair int int)))
      "bridging packet merges adjacent ranges"
      [ 10, 13 ]
      (ack_ranges_to_tuples ranges)
  | _ -> Alcotest.fail "expected ACK frame"

let test_packet_number_ack_ranges_trim_cutoff () =
  let pn = Quic.Transport.Packet_number.create () in
  List.iter
    (Quic.Transport.Packet_number.insert_for_acking pn)
    [ 1L; 2L; 3L; 4099L ];
  match Quic.Transport.Packet_number.compose_ack_frame pn with
  | Frame.Ack { ranges; _ } ->
    Alcotest.(check (list (pair int int)))
      "ranges crossing the cutoff are trimmed in place"
      [ 4099, 4099; 3, 3 ]
      (ack_ranges_to_tuples ranges)
  | _ -> Alcotest.fail "expected ACK frame"

let test_frame_validity_by_encryption_level () =
  let open Quic.Transport.Connection in
  let cases =
    [ "initial accepts ACK", Encryption_level.Initial, Frame.Ack { delay = 0; ranges = []; ecn_counts = None }, true
    ; ( "initial rejects STREAM"
      , Encryption_level.Initial
      , Frame.Stream
          { id = 0L
          ; fragment =
              { Frame.off = 0
              ; len = 0
              ; payload = ""
              ; payload_off = 0
              }
          ; is_fin = false
          }
      , false )
    ; "handshake rejects MAX_DATA", Encryption_level.Handshake, Frame.Max_data 1, false
    ; ( "0-rtt accepts STREAM"
      , Encryption_level.Zero_RTT
      , Frame.Stream
          { id = 0L
          ; fragment =
              { Frame.off = 0
              ; len = 0
              ; payload = ""
              ; payload_off = 0
              }
          ; is_fin = false
          }
      , true )
    ; "0-rtt rejects ACK", Encryption_level.Zero_RTT, Frame.Ack { delay = 0; ranges = []; ecn_counts = None }, false
    ; ( "0-rtt rejects PATH_RESPONSE"
      , Encryption_level.Zero_RTT
      , Frame.Path_response (Bigstringaf.of_string ~off:0 ~len:4 "path")
      , false )
    ; "1-rtt accepts HANDSHAKE_DONE", Encryption_level.Application_data, Frame.Handshake_done, true
    ; "initial preserves unknown frame handling", Encryption_level.Initial, Frame.Unknown 0x2f, true
    ]
  in
  List.iter
    (fun (name, encryption_level, frame, expected) ->
      Alcotest.(check bool)
        name
        expected
        (frame_allowed_at_encryption_level ~encryption_level frame))
    cases

let test_local_stream_ids_track_direction_separately () =
  let conn = make_connection () in
  Quic.Transport.Connection.process_max_streams_frame
    conn
    ~direction:Bidirectional
    3;
  Quic.Transport.Connection.process_max_streams_frame
    conn
    ~direction:Unidirectional
    2;
  let bidi1 = conn.start_stream Direction.Bidirectional in
  let uni1 = conn.start_stream Direction.Unidirectional in
  let bidi2 = conn.start_stream Direction.Bidirectional in
  Alcotest.(check int64)
    "first client bidi stream id"
    0L
    (Stream.id bidi1);
  Alcotest.(check int64)
    "first client uni stream id"
    2L
    (Stream.id uni1);
  Alcotest.(check int64)
    "second client bidi stream id"
    4L
    (Stream.id bidi2)

let test_max_streams_updates_peer_limit_and_emits_streams_blocked () =
  let conn = make_connection () in
  Quic.Transport.Connection.process_max_streams_frame
    conn
    ~direction:Bidirectional
    2;
  Alcotest.(check int64)
    "peer bidi stream limit is updated"
    2L
    conn.peer_max_streams_bidi;
  ignore (conn.start_stream Direction.Bidirectional);
  ignore (conn.start_stream Direction.Bidirectional);
  Alcotest.check_raises
    "opening past the peer limit raises"
    (Invalid_argument "peer stream limit reached")
    (fun () -> ignore (conn.start_stream Direction.Bidirectional));
  Alcotest.(check (list string))
    "peer stream exhaustion emits STREAMS_BLOCKED"
    [ serialize_frame (Frame.Streams_blocked (Bidirectional, 2)) ]
    (List.map serialize_frame (take_queued_frames conn))

let test_streams_blocked_reissues_current_limit () =
  let transport_parameters =
    Quic.Config.
      { default_transport_parameters with
        initial_max_streams_bidi = 4
      ; initial_max_streams_uni = 8
      }
  in
  let conn = make_connection ~transport_parameters () in
  Quic.Transport.Connection.process_streams_blocked_frame
    conn
    ~direction:Unidirectional
    1;
  Alcotest.(check (list string))
    "receiving STREAMS_BLOCKED below the current limit reissues MAX_STREAMS"
    [ serialize_frame (Frame.Max_streams (Unidirectional, 8)) ]
    (List.map serialize_frame (take_queued_frames conn))

let test_data_blocked_reissues_current_limit () =
  let transport_parameters =
    Quic.Config.
      { default_transport_parameters with
        initial_max_data = 4096
      }
  in
  let conn = make_connection ~transport_parameters () in
  Quic.Transport.Connection.process_data_blocked_frame conn 1024;
  Alcotest.(check (list string))
    "receiving DATA_BLOCKED below the current limit reissues MAX_DATA"
    [ serialize_frame (Frame.Max_data 4096) ]
    (List.map serialize_frame (take_queued_frames conn))

let test_stream_data_blocked_reissues_current_limit () =
  let transport_parameters =
    Quic.Config.
      { default_transport_parameters with
        initial_max_stream_data_bidi_remote = 2048
      }
  in
  let conn = make_connection ~transport_parameters () in
  Quic.Transport.Connection.process_stream_data_blocked_frame
    conn
    ~stream_id:1L
    ~max_data:512;
  Alcotest.(check (list string))
    "receiving STREAM_DATA_BLOCKED below the current limit reissues MAX_STREAM_DATA"
    [ serialize_frame (Frame.Max_stream_data { stream_id = 1L; max_data = 2048 }) ]
    (List.map serialize_frame (take_queued_frames conn))

let test_new_token_is_remembered_on_client () =
  let remembered = ref None in
  let conn =
    make_connection
      ~remember_new_token:(fun token -> remembered := Some token)
      ()
  in
  let token = "fresh-token" in
  let data = Bigstringaf.of_string ~off:0 ~len:(String.length token) token in
  let packet_info =
    { Quic.Transport.packet_number = 0L
    ; header =
        Packet.Header.Short
          { dest_cid = Quic.CID.of_string "test-server-cid" }
    ; encryption_level = Encryption_level.Application_data
    ; connection = conn
    ; packet_has_ack_eliciting_frame = false
    }
  in
  Quic.Transport.Connection.frame_handler
    ~packet_info
    conn
    (Frame.New_token { length = String.length token; data });
  Alcotest.(check (option string))
    "client remembers NEW_TOKEN payload"
    (Some token)
    !remembered

let test_connect_uses_remembered_new_token () =
  let config =
    Quic.Config.
      { certificates = server_certificates ()
      ; alpn_protocols = [ "h3" ]
      ; transport_parameters = default_transport_parameters
      }
  in
  let transport =
    Quic.Transport.Client.create
      ~now_ms:(fun () -> 0L)
      ~config
      (fun ~cid:_ ~start_stream:_ ->
         Quic.Transport.F (fun _ -> { Quic.Transport.on_error = ignore }))
  in
  transport.remembered_new_token <- Some "cached-token";
  Quic.Transport.connect
    transport
    ~address:"peer-address"
    ~host:"localhost"
    (fun ~cid:_ ~start_stream:_ ->
       Quic.Transport.F (fun _ -> { Quic.Transport.on_error = ignore }));
  let connection =
    Quic.Transport.Connection.Table.to_seq_values transport.connections
    |> List.of_seq
    |> List.hd
  in
  Alcotest.(check string)
    "cached NEW_TOKEN is copied into the next client connection"
    "cached-token"
    connection.token_value

let test_server_issues_new_token_frame () =
  let conn = make_connection ~mode:Quic.Crypto.Mode.Server () in
  conn.encdec.current <- Encryption_level.Application_data;
  Quic.Transport.Connection.issue_new_token conn;
  match take_queued_frames conn with
  | [ Frame.New_token { length; data } ] ->
    Alcotest.(check bool) "issued token is not empty" true (length > 0);
    Alcotest.(check int)
      "NEW_TOKEN length matches payload"
      length
      (Bigstringaf.length data)
  | _ -> Alcotest.fail "expected a single NEW_TOKEN frame"

let test_local_connection_close_enters_closing () =
  let conn = make_connection () in
  conn.encdec.current <- Encryption_level.Application_data;
  Quic.Transport.Connection.report_error conn Error.Internal_error;
  (match conn.close_state with
  | Quic.Transport.Connection.Closing _ -> ()
  | _ -> Alcotest.fail "expected local close to enter closing");
  let packet_info =
    { Quic.Transport.packet_number = 0L
    ; header =
        Packet.Header.Short
          { dest_cid = Quic.CID.of_string "test-server-cid" }
    ; encryption_level = Encryption_level.Application_data
    ; connection = conn
    ; packet_has_ack_eliciting_frame = false
    }
  in
  Quic.Transport.Connection.frame_handler ~packet_info conn Frame.Ping;
  Alcotest.(check (list string))
    "closing connections requeue the stored CONNECTION_CLOSE"
    [ serialize_frame
        (Frame.Connection_close_quic
           { frame_type = Frame.Type.Padding
           ; reason_phrase = ""
           ; error_code = Error.Internal_error
           }) ]
    (List.map serialize_frame (take_queued_frames conn))

let test_remote_connection_close_enters_draining () =
  let conn = make_connection () in
  Quic.Transport.Connection.process_connection_close_app_frame
    conn
    ~error_code:7
    "bye";
  (match conn.close_state with
  | Quic.Transport.Connection.Draining _ -> ()
  | _ -> Alcotest.fail "expected peer close to enter draining");
  let packet_info =
    { Quic.Transport.packet_number = 0L
    ; header =
        Packet.Header.Short
          { dest_cid = Quic.CID.of_string "test-server-cid" }
    ; encryption_level = Encryption_level.Application_data
    ; connection = conn
    ; packet_has_ack_eliciting_frame = false
    }
  in
  Quic.Transport.Connection.frame_handler ~packet_info conn Frame.Ping;
  Alcotest.(check (list string))
    "draining connections ignore subsequent frames"
    []
    (List.map serialize_frame (take_queued_frames conn))

let test_close_timeout_deregisters_connection () =
  let config =
    Quic.Config.
      { certificates = server_certificates ()
      ; alpn_protocols = [ "h3" ]
      ; transport_parameters = default_transport_parameters
      }
  in
  let transport =
    Quic.Transport.Client.create
      ~now_ms:(fun () -> 1L)
      ~config
      (fun ~cid:_ ~start_stream:_ ->
         Quic.Transport.F (fun _ -> { Quic.Transport.on_error = ignore }))
  in
  Quic.Transport.connect
    transport
    ~address:"peer-address"
    ~host:"localhost"
    (fun ~cid:_ ~start_stream:_ ->
       Quic.Transport.F (fun _ -> { Quic.Transport.on_error = ignore }));
  let connection =
    Quic.Transport.Connection.Table.to_seq_values transport.connections
    |> List.of_seq
    |> List.hd
  in
  connection.close_state <- Quic.Transport.Connection.Closing 0L;
  Quic.Transport.on_timeout transport;
  Alcotest.(check int)
    "closing connections are removed after their timeout"
    0
    (Quic.Transport.Connection.Table.length transport.connections)

let suite =
  [ "parser", `Quick, test_parser
  ; "fast frame roundtrip", `Quick, test_fast_frame_parser_roundtrips_payload
  ; "fast frame string parity", `Quick, test_fast_frame_string_parser_matches_bigstring
  ; "quic transport parameters", `Quick, test_quic_transport_parameters
  ; "short header", `Quick, test_short_header
  ; "packet number ack ranges", `Quick, test_packet_number_ack_ranges_are_incremental
  ; "packet number ack pruning", `Quick, test_packet_number_ack_ranges_prune_old_packets
  ; "packet number ack bridging", `Quick, test_packet_number_ack_ranges_merge_bridged_gap
  ; "packet number ack cutoff trim", `Quick, test_packet_number_ack_ranges_trim_cutoff
  ; "frame validity by encryption level", `Quick, test_frame_validity_by_encryption_level
  ; "local stream ids by direction", `Quick, test_local_stream_ids_track_direction_separately
  ; ( "max streams updates peer limit"
    , `Quick
    , test_max_streams_updates_peer_limit_and_emits_streams_blocked )
  ; "streams blocked reissues limit", `Quick, test_streams_blocked_reissues_current_limit
  ; "data blocked reissues limit", `Quick, test_data_blocked_reissues_current_limit
  ; ( "stream data blocked reissues limit"
    , `Quick
    , test_stream_data_blocked_reissues_current_limit )
  ; "client remembers NEW_TOKEN", `Quick, test_new_token_is_remembered_on_client
  ; "connect uses remembered NEW_TOKEN", `Quick, test_connect_uses_remembered_new_token
  ; "server issues NEW_TOKEN", `Quick, test_server_issues_new_token_frame
  ; "local connection close enters closing", `Quick
    , test_local_connection_close_enters_closing
  ; "remote connection close enters draining", `Quick
    , test_remote_connection_close_enters_draining
  ; "close timeout deregisters connection", `Quick
    , test_close_timeout_deregisters_connection
  ]

let () =
  Mirage_crypto_rng_unix.use_default ();
  Alcotest.run "parsing" [ "parser", suite ]
