module Quic = Quic__
open Quic

let hex = Alcotest.of_pp Hex.pp
let expected_dest_cid = `Hex "cb6241dbbc172d3ebf33a83a2271cd0c559293c9"

let plaintext =
  Hex.to_string
    (`Hex
        "c0ff00001d14cb6241dbbc172d3ebf33a83a2271cd0c559293c910c78d00d671c14508476004fd071c92270040670000000102000000000600405a02000056030333e471d0747f6665b0791a6501070a4b2a30ab44453508ccab8d19211223570200130100002e002b0002030400330024001d002063817bf561dc6ec856426c806af204605fb1e8bb843ae7317c27356f9b222e0b")

let test_parser () =
  let packet =
    Angstrom.parse_string
      ~consume:All
      (Parse.Packet.parser
         ~decrypt:(fun ~payload_length:_ ~header:_ buf ~off ~len ->
           let cs = Cstruct.of_bigarray ~off ~len buf in
           let header, plaintext = Cstruct.split cs 50 in
           Format.eprintf
             "gah %a %a@."
             Hex.pp
             (Hex.of_cstruct header)
             Hex.pp
             (Hex.of_cstruct plaintext);
           Some
             { Crypto.AEAD.packet_number = 1L
             ; header = Cstruct.to_string header
             ; plaintext = Cstruct.to_string plaintext
             ; pn_length = 4
             }))
      plaintext
  in

  match packet with
  | Ok (Packet packet) ->
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
  | Ok Skip -> Alcotest.fail "x"
  | Ok (Error (_packet, _error)) ->
    Alcotest.failf "pkt err: %d@." (Error.serialize _error)
  | Error e -> Alcotest.fail e

let test_quic_transport_parameters () =
  let encoded_params =
    Hex.to_string
      (`Hex
          "010480007530030245460404809896800504800f42400604800f42400704800f424008024064090240640a01030b01190c000f14e8302a4aab4c1dc29add56136a6f4e030e826d72")
  in
  match
    Angstrom.parse_string
      ~consume:All
      Quic.Transport_parameters.Encoding.parser
      encoded_params
  with
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
    Angstrom.parse_string ~consume:Prefix Quic.Parse.Packet.protected_header hdr
  with
  | Ok _ -> ()
  | Error e -> Alcotest.fail e

let suite =
  [ "parser", `Quick, test_parser
  ; "quic transport parameters", `Quick, test_quic_transport_parameters
  ; "short header", `Quick, test_short_header
  ]

let () = Alcotest.run "parsing" [ "parser", suite ]
