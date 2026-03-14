module Quic = Quic__
open Quic

let hex = Alcotest.of_pp Hex.pp
let expected_dest_cid = `Hex "cb6241dbbc172d3ebf33a83a2271cd0c559293c9"

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
  match decrypt_stub ~payload_length ~header buf ~off ~len with
  | Some ret ->
    Some
      { Crypto.AEAD.packet_number = ret.packet_number
      ; first_byte_unprotected = Char.code ret.header.[0]
      ; plaintext = ret.plaintext
      ; pn_length = ret.pn_length
      }
  | None -> None

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
  ]

let () = Alcotest.run "parsing" [ "parser", suite ]
