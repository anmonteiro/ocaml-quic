module Quic = Quic__

module Crypto = Quic.Crypto
module InitialAEAD = Quic.Crypto.InitialAEAD
module AEAD = Quic.Crypto.AEAD
module Packet_parser = Quic.Fast_parse.Packet_parser
module Writer = Quic.Serialize.Writer

let dest_cid = Hex.to_string (`Hex "8394c8f03e515708")

module Client_initial = struct
  let unprotected_payload =
    let frames =
      Hex.to_string
        (`Hex
            "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff")
    in
    frames ^ String.make (1162 - String.length frames) '\x00'

  let unprotected_header =
    Hex.to_string (`Hex "c300000001088394c8f03e5157080000449e00000002")

  let expected_protected_packet =
    Hex.to_string
      (`Hex
          "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934")

  let packet_number = 2L
  let largest_pn = 1L
  let payload_length = String.length expected_protected_packet - String.length unprotected_header + 4
  let header_prefix_len = String.length unprotected_header - 4
end

type backend =
  [ `Legacy
  | `OpenSSL
  ]

let backend = ref (`OpenSSL : backend)
let iters = ref 200_000

let parse_backend = function
  | "legacy" -> `Legacy
  | "openssl" -> `OpenSSL
  | s -> invalid_arg ("unknown backend: " ^ s)

let arg_spec =
  [ "-iters", Arg.Set_int iters, " Number of iterations per benchmark"
  ; ( "-backend"
    , Arg.String (fun s -> backend := parse_backend s)
    , " openssl|legacy" )
  ]

let usage = "bench_packet_protection.exe [-backend openssl|legacy] [-iters N]"

let stream_frame_payload =
  let payload = String.make 1024 'x' in
  let f = Faraday.create 1200 in
  Quic.Serialize.Frame.write_frame
    f
    (Quic.Frame.Stream
       { id = 0L
       ; fragment =
           { Quic.Frame.off = 0
           ; len = String.length payload
           ; payload
           ; payload_off = 0
           }
       ; is_fin = false
       });
  Faraday.serialize_to_string f

let serialize_with writer_fn ~header_info frames =
  let writer = Writer.create 0x1000 in
  writer_fn writer ~header_info frames;
  Faraday.serialize_to_string writer.encoder

let app_header_info ~packet_number =
  let encrypter = InitialAEAD.make ~mode:Server (Quic.CID.of_string "abc") in
  Writer.make_header_info
    ~encrypter
    ~encryption_level:Application_data
    ~packet_number
    ~token:""
    (Quic.CID.of_string "abcdefgh")

let serializer_cases =
  let payload_1k = String.make 1024 'x' in
  [ ( "serialize_runtime_small_stream"
    , app_header_info ~packet_number:17L
    , [ Quic.Frame.Stream
          { id = 0L
          ; fragment =
              { Quic.Frame.off = 0
              ; len = String.length payload_1k
              ; payload = payload_1k
              ; payload_off = 0
              }
          ; is_fin = false
          }
      ] )
  ; ( "serialize_runtime_large_off"
    , app_header_info ~packet_number:18L
    , [ Quic.Frame.Stream
          { id = 4L
          ; fragment =
              { Quic.Frame.off = 1 lsl 20
              ; len = String.length payload_1k
              ; payload = payload_1k
              ; payload_off = 0
              }
          ; is_fin = false
          }
      ] )
  ; ( "serialize_runtime_multi_frame"
    , app_header_info ~packet_number:19L
    , [ Quic.Frame.Ack
          { delay = 3
          ; ranges =
              [ { Quic.Frame.Range.first = 8L; last = 10L }
              ; { Quic.Frame.Range.first = 4L; last = 5L }
              ]
          ; ecn_counts = Some (1, 2, 3)
          }
      ; Quic.Frame.Max_data 4096
      ; Quic.Frame.Stream
          { id = 4L
          ; fragment =
              { Quic.Frame.off = 1024
              ; len = 11
              ; payload = "hello world"
              ; payload_off = 0
              }
          ; is_fin = false
          }
      ] )
  ]

let benchmark name ~bytes_per_iter f =
  Gc.full_major ();
  let t0 = Unix.gettimeofday () in
  let acc = ref 0 in
  for _ = 1 to !iters do
    acc := !acc lxor Sys.opaque_identity (f ())
  done;
  let dt = Unix.gettimeofday () -. t0 in
  let total_bytes = float_of_int (bytes_per_iter * !iters) in
  let mib_per_s = if dt = 0. then infinity else total_bytes /. dt /. 1024. /. 1024. in
  Printf.printf
    "%-28s %.3fs  %.2f MiB/s  checksum=%d\n%!"
    name
    dt
    mib_per_s
    !acc

let () =
  Arg.parse arg_spec ignore usage;
  let previous = !(Crypto.backend) in
  Fun.protect
    ~finally:(fun () -> Crypto.backend := previous)
    (fun () ->
      Crypto.backend := !backend;
      let encrypter =
        InitialAEAD.make ~mode:Client (Quic.CID.of_string dest_cid)
      in
      let packet = Client_initial.expected_protected_packet in
      let packet_bs =
        Bigstringaf.of_string ~off:0 ~len:(String.length packet) packet
      in
      let decrypt ~payload_length ~header:_ ~header_prefix_len bs ~off ~len =
        AEAD.decrypt_packet_bigstring_for_parse
          encrypter
          ~payload_length
          ~header_prefix_len
          ~largest_pn:Client_initial.largest_pn
          bs
          ~off
          ~len
      in
      Printf.printf
        "backend=%s iterations=%d packet_len=%d payload_len=%d\n%!"
        (match !backend with `Legacy -> "legacy" | `OpenSSL -> "openssl")
        !iters
        (String.length packet)
        Client_initial.payload_length;
      benchmark
        "encrypt_payload_into"
        ~bytes_per_iter:(String.length Client_initial.unprotected_payload)
        (fun () ->
          let sealed =
            AEAD.encrypt_payload_into
              encrypter
              ~packet_number:Client_initial.packet_number
              ~header:Client_initial.unprotected_header
              Client_initial.unprotected_payload
          in
          Bytes.get_uint8 sealed 0);
      benchmark
        "decrypt_packet"
        ~bytes_per_iter:(String.length packet)
        (fun () ->
          match
            AEAD.decrypt_packet
              encrypter
              ~largest_pn:Client_initial.largest_pn
              ~payload_length:Client_initial.payload_length
              packet
          with
          | Some ret -> String.length ret.plaintext lxor Int64.to_int ret.packet_number
          | None -> 0);
      benchmark
        "decrypt_packet_bigstring"
        ~bytes_per_iter:(String.length packet)
        (fun () ->
          match
            AEAD.decrypt_packet_bigstring
              encrypter
              ~largest_pn:Client_initial.largest_pn
              ~payload_length:Client_initial.payload_length
              ~header_prefix_len:Client_initial.header_prefix_len
              packet_bs
              ~off:0
              ~len:(Bigstringaf.length packet_bs)
          with
          | Some ret -> String.length ret.plaintext lxor Int64.to_int ret.packet_number
          | None -> 0);
      benchmark
        "decrypt_bigstring_parse"
        ~bytes_per_iter:(String.length packet)
        (fun () ->
          match
            AEAD.decrypt_packet_bigstring_for_parse
              encrypter
              ~largest_pn:Client_initial.largest_pn
              ~payload_length:Client_initial.payload_length
              ~header_prefix_len:Client_initial.header_prefix_len
              packet_bs
              ~off:0
              ~len:(Bigstringaf.length packet_bs)
          with
          | Some ret -> String.length ret.plaintext lxor Int64.to_int ret.packet_number
          | None -> 0);
      benchmark
        "fast_parse_packet"
        ~bytes_per_iter:(String.length packet)
        (fun () ->
          match
            Packet_parser.parse
              ~decrypt
              packet_bs
              ~off:0
              ~len:(Bigstringaf.length packet_bs)
          with
          | Packet_parser.Packet (_, consumed) -> consumed
          | Packet_parser.Error (_, _, consumed) -> consumed
          | Packet_parser.Skip consumed -> consumed);
      let stream_frame_payload_bs =
        Bigstringaf.of_string
          ~off:0
          ~len:(String.length stream_frame_payload)
          stream_frame_payload
      in
      benchmark
        "frame_parse_string_stream"
        ~bytes_per_iter:(String.length stream_frame_payload)
        (fun () ->
          let frames = ref 0 in
          (match
             Quic.Fast_parse.Frame.parse_string
               stream_frame_payload
               ~handler:(fun _ -> incr frames)
           with
           | Ok () -> ()
           | Error e -> failwith e);
          !frames);
      benchmark
        "frame_parse_bigstring_stream"
        ~bytes_per_iter:(String.length stream_frame_payload)
        (fun () ->
          let frames = ref 0 in
          (match
             Quic.Fast_parse.Frame.parse_bigstring
               stream_frame_payload_bs
               ~handler:(fun _ -> incr frames)
           with
           | Ok () -> ()
           | Error e -> failwith e);
          !frames);
      List.iter
        (fun (name, header_info, frames) ->
           let bytes_per_iter =
             String.length
               (serialize_with Writer.write_frames_packet ~header_info frames)
           in
           benchmark
             (name ^ "_dispatch")
             ~bytes_per_iter
             (fun () ->
               String.length
                 (serialize_with Writer.write_frames_packet ~header_info frames));
           benchmark
             (name ^ "_direct")
             ~bytes_per_iter
             (fun () ->
               String.length
                 (serialize_with Writer.write_frames_packet_direct ~header_info frames)))
        serializer_cases)
