module Quic = Quic__

let hex = Alcotest.of_pp Hex.pp
let dest_cid = Hex.to_string (`Hex "8394c8f03e515708")

module Crypto = Quic.Crypto
module InitialAEAD = Quic.Crypto.InitialAEAD
module AEAD = Quic.Crypto.AEAD

module Keys = struct
  let test_initial_secret () =
    Alcotest.check
      hex
      "Initial Secret"
      (`Hex "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44")
      (Hex.of_string
         (Cstruct.to_string (InitialAEAD.get_initial_secret dest_cid)))

  let test_client_secrets () =
    let client_secret = InitialAEAD.get_secret ~mode:Client dest_cid in
    Alcotest.check
      hex
      "client_initial_secret"
      (`Hex "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
      (Hex.of_string (Cstruct.to_string client_secret));
    let client_key, client_iv =
      Crypto.Kdf.get_key_and_iv ~hash:`SHA256 ~kn:16 ~ivn:12 client_secret
    in
    Alcotest.check
      hex
      "client_key"
      (`Hex "1f369613dd76d5467730efcbe3b1a22d")
      (Hex.of_string (Cstruct.to_string client_key));
    Alcotest.check
      hex
      "client_iv"
      (`Hex "fa044b2f42a3fd3b46fb255c")
      (Hex.of_string (Cstruct.to_string client_iv));
    let client_hp =
      Crypto.Kdf.get_header_protection_key ~hash:`SHA256 ~kn:16 client_secret
    in
    Alcotest.check
      hex
      "client_hp"
      (`Hex "9f50449e04a0e810283a1e9933adedd2")
      (Hex.of_string (Cstruct.to_string client_hp))

  let test_server_secrets () =
    let server_secret = InitialAEAD.get_secret ~mode:Server dest_cid in
    Alcotest.check
      hex
      "server_initial_secret"
      (`Hex "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
      (Hex.of_string (Cstruct.to_string server_secret));
    let server_key, server_iv =
      Crypto.Kdf.get_key_and_iv ~hash:`SHA256 ~kn:16 ~ivn:12 server_secret
    in
    Alcotest.check
      hex
      "server_key"
      (`Hex "cf3a5331653c364c88f0f379b6067e37")
      (Hex.of_string (Cstruct.to_string server_key));
    Alcotest.check
      hex
      "server_iv"
      (`Hex "0ac1493ca1905853b0bba03e")
      (Hex.of_string (Cstruct.to_string server_iv));
    let server_hp =
      Crypto.Kdf.get_header_protection_key ~hash:`SHA256 ~kn:16 server_secret
    in
    Alcotest.check
      hex
      "server_hp"
      (`Hex "c206b8d9b9f0f37644430b490eeaa314")
      (Hex.of_string (Cstruct.to_string server_hp))

  let suite =
    [ "initial secret", `Quick, test_initial_secret
    ; "client secrets", `Quick, test_client_secrets
    ; "server secrets", `Quick, test_server_secrets
    ]
end

module Client_initial = struct
  let unprotected_payload =
    let frames =
      Hex.to_string
        (`Hex
          "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff")
    in
    frames
    (* Add PADDING *)
    ^ String.make (1162 - String.length frames) '\x00'

  let unprotected_header =
    Hex.to_string (`Hex "c300000001088394c8f03e5157080000449e00000002")

  let expected_protected_packet =
    `Hex
      "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934"

  let test_encrypt_client_initial () =
    let encrypter =
      InitialAEAD.make ~mode:Client (Quic.CID.of_string dest_cid)
    in
    let packet_number = 2L in
    let data = Cstruct.of_string unprotected_payload in
    let header = Cstruct.of_string unprotected_header in
    let sealed_payload =
      AEAD.encrypt_payload encrypter ~packet_number ~header data
    in
    let sample = Cstruct.sub sealed_payload 0 16 in
    Alcotest.check
      hex
      "sample"
      (`Hex "d1b1c98dd7689fb8ec11d242b123dc9b")
      (Hex.of_cstruct sample);
    let header = AEAD.encrypt_header encrypter ~sample header in
    Alcotest.check
      hex
      "header"
      (`Hex "c000000001088394c8f03e5157080000449e7b9aec34")
      (Hex.of_cstruct header);
    Alcotest.check
      hex
      "resulting protected packet"
      expected_protected_packet
      (Hex.of_cstruct (Cstruct.append header sealed_payload));
    let header = Cstruct.of_string unprotected_header in
    let packet =
      Crypto.AEAD.encrypt_packet encrypter ~packet_number ~header data
    in
    Alcotest.check
      hex
      "resulting protected packet"
      expected_protected_packet
      (Hex.of_cstruct packet);
    let decrypted =
      Crypto.AEAD.decrypt_packet
        encrypter
        ~largest_pn:1L
        (Cstruct.of_string (Hex.to_string expected_protected_packet))
        ~payload_length:
          (String.length (Hex.to_string expected_protected_packet)
          - String.length unprotected_header
          + 4)
    in
    Alcotest.(check bool) "roundtrips" true (Option.is_some decrypted);
    Alcotest.(check hex)
      "roundtrips"
      (Hex.of_string (unprotected_header ^ unprotected_payload))
      (Hex.of_string
         (Cstruct.to_string (Option.get decrypted).header
         ^ Cstruct.to_string (Option.get decrypted).plaintext))

  let suite = [ "encrypt client initial", `Quick, test_encrypt_client_initial ]
end

module Server_initial = struct
  let unprotected_payload =
    Hex.to_string
      (`Hex
        "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00020304")

  let unprotected_header =
    Hex.to_string (`Hex "c1000000010008f067a5502a4262b50040750001")

  let expected_protected_packet =
    `Hex
      "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee"

  let test_encrypt_server_initial () =
    let encrypter =
      InitialAEAD.make ~mode:Server (Quic.CID.of_string dest_cid)
    in
    let packet_number = 1L in
    let data = Cstruct.of_string unprotected_payload in
    let header = Cstruct.of_string unprotected_header in
    let sealed_payload =
      AEAD.encrypt_payload encrypter ~packet_number ~header data
    in
    let sample = Cstruct.sub sealed_payload 2 16 in
    Alcotest.check
      hex
      "sample"
      (`Hex "2cd0991cd25b0aac406a5816b6394100")
      (Hex.of_cstruct sample);
    let header = AEAD.encrypt_header encrypter ~sample header in
    Alcotest.check
      hex
      "header"
      (`Hex "cf000000010008f067a5502a4262b5004075c0d9")
      (Hex.of_cstruct header);
    Alcotest.check
      hex
      "resulting protected packet"
      expected_protected_packet
      (Hex.of_cstruct (Cstruct.append header sealed_payload));
    let header = Cstruct.of_string unprotected_header in
    let packet =
      Crypto.AEAD.encrypt_packet encrypter ~packet_number ~header data
    in
    Alcotest.check
      hex
      "resulting protected packet"
      expected_protected_packet
      (Hex.of_cstruct packet)

  let suite = [ "encrypt server initial", `Quick, test_encrypt_server_initial ]
end

module Retry = struct
  let test_retry_integrity_check () =
    let data =
      Hex.to_string
        (`Hex
          "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba")
    in
    match
      Angstrom.parse_string ~consume:All Quic__.Parse.Packet.Payload.retry data
    with
    | Ok
        (Retry
          { header : Quic.Packet.Header.t = _
          ; token : string = _
          ; pseudo : Bigstringaf.t
          ; tag : Bigstringaf.t = _
          }) ->
      Alcotest.check
        hex
        "pseudo"
        (Hex.of_string (String.sub data 0 (String.length data - 16)))
        (Hex.of_bigstring pseudo);
      let integrity_tag =
        Crypto.Retry.calculate_integrity_tag
          (Quic.CID.of_string dest_cid)
          (Bigstringaf.of_string ~off:0 ~len:(String.length data - 16) data)
      in
      Alcotest.check
        hex
        "integrity tag"
        (Hex.of_string (String.sub data (String.length data - 16) 16))
        (Hex.of_cstruct integrity_tag)
    | _ -> assert false

  let suite = [ "check retry integrity", `Quick, test_retry_integrity_check ]
end

module ChaCha = struct
  let secret =
    Cstruct.of_string
      (Hex.to_string
         (`Hex
           "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"))

  let unprotected_payload = Hex.to_cstruct (`Hex "01")
  let unprotected_header = `Hex "4200bff4"

  let expected_protected_packet =
    `Hex "4cfe4189655e5cd55c41f69080575d7999c25a5bfb"

  let test_chacha_keys () =
    let key, iv =
      Crypto.Kdf.get_key_and_iv ~hash:`SHA256 ~kn:32 ~ivn:12 secret
    in
    Alcotest.check
      hex
      "key"
      (`Hex "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8")
      (Hex.of_string (Cstruct.to_string key));
    Alcotest.check
      hex
      "iv"
      (`Hex "e0459b3474bdd0e44a41c144")
      (Hex.of_string (Cstruct.to_string iv));
    let hp = Crypto.Kdf.get_header_protection_key ~hash:`SHA256 ~kn:32 secret in
    Alcotest.check
      hex
      "hp"
      (`Hex "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
      (Hex.of_string (Cstruct.to_string hp));
    let ku = Crypto.Kdf.get_ku ~hash:`SHA256 ~kn:32 secret in
    Alcotest.check
      hex
      "ku"
      (`Hex "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")
      (Hex.of_string (Cstruct.to_string ku))

  let test_chacha_short_header () =
    let packet_number = 654360564L in
    let encrypter = AEAD.make ~ciphersuite:`CHACHA20_POLY1305_SHA256 secret in
    let sealed_payload =
      AEAD.encrypt_payload
        encrypter
        ~packet_number
        ~header:(Hex.to_cstruct unprotected_header)
        unprotected_payload
    in
    Alcotest.check
      hex
      "protected payload"
      (`Hex "655e5cd55c41f69080575d7999c25a5bfb")
      (Hex.of_cstruct sealed_payload);
    let sample = Cstruct.sub sealed_payload 1 16 in
    let header =
      AEAD.encrypt_header encrypter ~sample (Hex.to_cstruct unprotected_header)
    in
    Alcotest.check
      hex
      "protected header"
      (`Hex "4cfe4189")
      (Hex.of_cstruct header);
    Alcotest.check
      hex
      "resulting protected packet"
      expected_protected_packet
      (Hex.of_cstruct (Cstruct.append header sealed_payload));
    let packet =
      Crypto.AEAD.encrypt_packet
        encrypter
        ~packet_number
        ~header:(Hex.to_cstruct unprotected_header)
        unprotected_payload
    in
    Alcotest.check
      hex
      "resulting protected packet"
      expected_protected_packet
      (Hex.of_cstruct packet)

  let suite =
    [ "chacha keys ", `Quick, test_chacha_keys
    ; "chacha short header", `Quick, test_chacha_short_header
    ]
end

module InitialAEAD_encryption = struct
  let test_initial_aead_header_encryption_decryption () =
    let conn_id = Hex.to_string (`Hex "decafbad") in
    let client_encrypter =
      InitialAEAD.make ~mode:Client (Quic.CID.of_string conn_id)
    in
    let unprotected_header = Client_initial.unprotected_header in
    let sample = Cstruct.of_hex "655e5cd55c41f69080575d7999c25a5b" in
    assert (Cstruct.length sample = 16);
    let header =
      (* the first byte and the last 4 bytes should be encrypted *)
      AEAD.encrypt_header
        client_encrypter
        ~sample
        (Cstruct.of_string unprotected_header)
    in
    (*
     *  Initial Packet {
     *    Header Form (1) = 1,
     *    Fixed Bit (1) = 1,
     *    Long Packet Type (2) = 0,
     *    Reserved Bits (2),         # Protected
     *    Packet Number Length (2),  # Protected
     *    Version (32),
     *    DCID Len (8),
     *    Destination Connection ID (0..160),
     *    SCID Len (8),
     *    Source Connection ID (0..160),
     *    Token Length (i),
     *    Token (..),
     *    Length (i),
     *    Packet Number (8..32),     # Protected
     *    Protected Payload (0..24), # Skipped Part
     *    Protected Payload (128),   # Sampled Part
     *    Protected Payload (..)     # Remainder
     *  }
     *)
    Alcotest.(check bool)
      "only the last 4 bits of the first byte are encrypted"
      true
      (Cstruct.get_uint8 header 0 land 0x0f
      <> Char.code unprotected_header.[0] land 0x0f);
    Alcotest.check
      hex
      "bytes 1-6 are unmodified (not protected)"
      (Hex.of_cstruct (Cstruct.sub header 1 5))
      (Hex.of_string (String.sub unprotected_header 1 5));
    let pn_length =
      Crypto.packet_number_length (Cstruct.of_string unprotected_header)
    in
    Alcotest.(check bool)
      "last 4 bytes are modified (protected)"
      true
      (Cstruct.to_string
         (Cstruct.sub header (Cstruct.length header - pn_length) pn_length)
      <> String.sub
           unprotected_header
           (Cstruct.length header - pn_length)
           pn_length);
    let decrypted_header =
      AEAD.decrypt_header client_encrypter ~sample header
    in
    Alcotest.check
      hex
      "decrypted_header matches unprotected_header"
      (Hex.of_string unprotected_header)
      (Hex.of_cstruct decrypted_header);
    let server_encrypter =
      InitialAEAD.make ~mode:Server (Quic.CID.of_string conn_id)
    in
    let header =
      (* the first byte and the last 4 bytes should be encrypted *)
      AEAD.encrypt_header
        server_encrypter
        ~sample
        (Cstruct.of_string unprotected_header)
    in
    Alcotest.(check bool)
      "only the last 4 bits of the first byte are encrypted"
      true
      (Cstruct.get_uint8 header 0 land 0x0f
      <> Char.code unprotected_header.[0] land 0x0f);
    Alcotest.check
      hex
      "bytes 1-6 are unmodified (not protected)"
      (Hex.of_cstruct (Cstruct.sub header 1 5))
      (Hex.of_string (String.sub unprotected_header 1 5));
    Alcotest.(check bool)
      "last 4 bytes are modified (protected)"
      true
      (Cstruct.to_string
         (Cstruct.sub header (Cstruct.length header - pn_length) pn_length)
      <> String.sub
           unprotected_header
           (Cstruct.length header - pn_length)
           pn_length);
    let decrypted_header =
      AEAD.decrypt_header server_encrypter ~sample header
    in
    Alcotest.check
      hex
      "decrypted_header matches unprotected_header"
      (Hex.of_string unprotected_header)
      (Hex.of_cstruct decrypted_header)

  let test_client_initial_aead_packet_encryption_decryption () =
    let client_encrypter =
      InitialAEAD.make ~mode:Client (Quic.CID.of_string dest_cid)
    in
    let unprotected_header =
      Cstruct.of_string Client_initial.unprotected_header
    in
    let data = Cstruct.of_string Client_initial.unprotected_payload in
    let packet_number = 2L in
    let protected_packet =
      Crypto.AEAD.encrypt_packet
        client_encrypter
        ~packet_number
        ~header:unprotected_header
        data
    in
    Alcotest.check
      hex
      "resulting protected packet"
      Client_initial.expected_protected_packet
      (Hex.of_cstruct protected_packet);
    let { Crypto.AEAD.header = decrypted_header
        ; plaintext = decrypted_packet
        ; _
        }
      =
      Option.get
        (Crypto.AEAD.decrypt_packet
           client_encrypter
           ~largest_pn:0L
           ~payload_length:
             (Cstruct.length protected_packet
             - Cstruct.length unprotected_header
             + 4)
           protected_packet)
    in
    Alcotest.check
      hex
      "expected decrypted header"
      (Hex.of_string Client_initial.unprotected_header)
      (Hex.of_cstruct decrypted_header);
    Alcotest.check
      hex
      "expected decrypted payload"
      (Hex.of_string Client_initial.unprotected_payload)
      (Hex.of_cstruct decrypted_packet)

  let test_server_initial_aead_packet_encryption_decryption () =
    let server_encrypter =
      InitialAEAD.make ~mode:Server (Quic.CID.of_string dest_cid)
    in
    let unprotected_header =
      Cstruct.of_string Server_initial.unprotected_header
    in
    let data = Cstruct.of_string Server_initial.unprotected_payload in
    let packet_number = 1L in
    let protected_packet =
      Crypto.AEAD.encrypt_packet
        server_encrypter
        ~packet_number
        ~header:unprotected_header
        data
    in
    Alcotest.check
      hex
      "resulting protected packet"
      Server_initial.expected_protected_packet
      (Hex.of_cstruct protected_packet);
    let { Crypto.AEAD.header = decrypted_header
        ; plaintext = decrypted_packet
        ; _
        }
      =
      Option.get
        (Crypto.AEAD.decrypt_packet
           server_encrypter
           ~largest_pn:0L
           ~payload_length:
             (Cstruct.length protected_packet
             - Cstruct.length unprotected_header
             + 2)
           protected_packet)
    in
    Alcotest.check
      hex
      "expected decrypted header"
      (Hex.of_string Server_initial.unprotected_header)
      (Hex.of_cstruct decrypted_header);
    Alcotest.check
      hex
      "expected decrypted payload"
      (Hex.of_string Server_initial.unprotected_payload)
      (Hex.of_cstruct decrypted_packet)

  let test_ocaml_quic_enc_dec () =
    let module Writer = Quic.Serialize.Writer in
    let unprotected_header = `Hex "c3ff00001d0361626300001900000001" in
    let plaintext_payload = `Hex "0201000000" in
    let encrypter =
      InitialAEAD.make ~mode:Server (Quic.CID.of_string dest_cid)
    in
    let protected_packet =
      Crypto.AEAD.encrypt_packet
        encrypter
        ~packet_number:1L
        ~header:(Hex.to_cstruct unprotected_header)
        (Hex.to_cstruct plaintext_payload)
    in
    let { Crypto.AEAD.header = decrypted_header
        ; plaintext = decrypted_packet
        ; _
        }
      =
      Option.get
        (Crypto.AEAD.decrypt_packet
           encrypter
           ~largest_pn:0L
           ~payload_length:
             (Cstruct.length protected_packet
             - String.length (Hex.to_string unprotected_header)
             + 4)
           protected_packet)
    in
    Alcotest.check
      hex
      "roundtrip header"
      unprotected_header
      (Hex.of_cstruct decrypted_header);
    Alcotest.check
      hex
      "roundtrip payload"
      plaintext_payload
      (Hex.of_cstruct decrypted_packet)

  let test_ocaml_quic_decrypt_serialized () =
    let module Writer = Quic.Serialize.Writer in
    let encrypter = InitialAEAD.make ~mode:Server (Quic.CID.of_string "abc") in
    let writer = Writer.create 0x1000 in
    Writer.write_frames_packet
      writer
      ~header_info:
        (Writer.make_header_info
           ~encrypter
           ~encryption_level:Initial
           ~packet_number:1L
           (Quic.CID.of_string "abc"))
      [ Ack
          { delay = 0
          ; ranges = [ { Quic.Frame.Range.first = 1L; last = 1L } ]
          ; ecn_counts = None
          }
      ];
    let protected_packet =
      Cstruct.of_bigarray (Faraday.serialize_to_bigstring writer.encoder)
    in
    let ret =
      Crypto.AEAD.decrypt_packet
        encrypter
        ~largest_pn:0L
        ~payload_length:22
        protected_packet
    in
    match ret with
    | Some { Crypto.AEAD.packet_number; pn_length; _ } ->
      Alcotest.(check int64) "packet number" 1L packet_number;
      Alcotest.(check int) "packet number length" 1 pn_length
    | None -> Alcotest.fail "expected packet to decrypt successfully"

  let suite =
    [ ( "header encryption / decryption"
      , `Quick
      , test_initial_aead_header_encryption_decryption )
    ; ( "client packet encryption / decryption"
      , `Quick
      , test_client_initial_aead_packet_encryption_decryption )
    ; ( "server packet encryption / decryption"
      , `Quick
      , test_server_initial_aead_packet_encryption_decryption )
    ; "ocaml-quic generated", `Quick, test_ocaml_quic_enc_dec
    ; "ocaml-quic serialized", `Quick, test_ocaml_quic_decrypt_serialized
    ]
end

module ChaCha20_encryption = struct
  let test_chacha20_header_encryption_decryption () =
    let client_encrypter =
      { (AEAD.make ~ciphersuite:`CHACHA20_POLY1305_SHA256 ChaCha.secret) with
        conn_id_len = 0
      }
    in
    let unprotected_header = Client_initial.unprotected_header in
    let sample = Cstruct.of_hex "655e5cd55c41f69080575d7999c25a5b" in
    assert (Cstruct.length sample = 16);
    let header =
      (* the first byte and the last 4 bytes should be encrypted *)
      AEAD.encrypt_header
        client_encrypter
        ~sample
        (Cstruct.of_string unprotected_header)
    in
    Alcotest.(check bool)
      "only the last 4 bits of the first byte are encrypted"
      true
      (Cstruct.get_uint8 header 0 land 0x0f
      <> Char.code unprotected_header.[0] land 0x0f);
    Alcotest.check
      hex
      "bytes 1-6 are unmodified (not protected)"
      (Hex.of_cstruct (Cstruct.sub header 1 5))
      (Hex.of_string (String.sub unprotected_header 1 5));
    let pn_length =
      Crypto.packet_number_length (Cstruct.of_string unprotected_header)
    in
    Alcotest.(check bool)
      "last 4 bytes are modified (protected)"
      true
      (Cstruct.to_string
         (Cstruct.sub header (Cstruct.length header - pn_length) pn_length)
      <> String.sub
           unprotected_header
           (Cstruct.length header - pn_length)
           pn_length);
    let decrypted_header =
      AEAD.decrypt_header client_encrypter ~sample header
    in
    Alcotest.check
      hex
      "decrypted_header matches unprotected_header"
      (Hex.of_string unprotected_header)
      (Hex.of_cstruct decrypted_header)

  let test_chacha20_packet_encryption_decryption () =
    let packet_number = 654360564L in
    let encrypter =
      { (AEAD.make ~ciphersuite:`CHACHA20_POLY1305_SHA256 ChaCha.secret) with
        conn_id_len = 0
      }
    in
    let unprotected_header = Hex.to_cstruct ChaCha.unprotected_header in
    let protected_packet =
      Crypto.AEAD.encrypt_packet
        encrypter
        ~packet_number
        ~header:unprotected_header
        ChaCha.unprotected_payload
    in
    Alcotest.check
      hex
      "resulting protected packet"
      ChaCha.expected_protected_packet
      (Hex.of_cstruct protected_packet);
    let { Crypto.AEAD.header = decrypted_header
        ; plaintext = decrypted_packet
        ; _
        }
      =
      Option.get
        (Crypto.AEAD.decrypt_packet
           encrypter
           ~largest_pn:(Int64.sub packet_number 100L)
           ~payload_length:20
           protected_packet)
    in
    Alcotest.check
      hex
      "expected decrypted header"
      ChaCha.unprotected_header
      (Hex.of_cstruct decrypted_header);
    Alcotest.check
      hex
      "expected decrypted payload"
      (Hex.of_cstruct ChaCha.unprotected_payload)
      (Hex.of_cstruct decrypted_packet)

  let suite =
    [ ( "header encryption / decryption"
      , `Quick
      , test_chacha20_header_encryption_decryption )
    ; ( "client packet encryption / decryption"
      , `Quick
      , test_chacha20_packet_encryption_decryption )
    ]
end

let () =
  Alcotest.run
    "packets"
    [ "A.1. Keys", Keys.suite
    ; "A.2. Client Initial", Client_initial.suite
    ; "A.3. Server Initial", Server_initial.suite
    ; "A.4. Retry", Retry.suite
    ; "A.5. ChaCha20-Poly1305 Short Header Packet", ChaCha.suite
    ; "Initial AEAD", InitialAEAD_encryption.suite
    ; "ChaCha20", ChaCha20_encryption.suite
    ]
