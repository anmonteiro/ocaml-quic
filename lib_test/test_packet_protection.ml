module Quic = Quic__

let hex = Alcotest.of_pp Hex.pp

let dest_cid = Hex.to_string (`Hex "8394c8f03e515708")

module InitialAEAD = Quic.Crypto.InitialAEAD

let test_initial_secret () =
  Alcotest.check
    hex
    "Initial Secret"
    (`Hex "1e7e7764529715b1e0ddc8e9753c61576769605187793ed366f8bbf8c9e986eb")
    (Hex.of_string
       (Cstruct.to_string (InitialAEAD.get_initial_secret dest_cid)))

let test_client_secrets () =
  let client_secret = InitialAEAD.get_secret ~mode:Client dest_cid in
  Alcotest.check
    hex
    "client_initial_secret"
    (`Hex "0088119288f1d866733ceeed15ff9d50902cf82952eee27e9d4d4918ea371d87")
    (Hex.of_string (Cstruct.to_string client_secret));
  let client_key, client_iv = InitialAEAD.get_key_and_iv client_secret in
  Alcotest.check
    hex
    "client_key"
    (`Hex "175257a31eb09dea9366d8bb79ad80ba")
    (Hex.of_string (Cstruct.to_string client_key));
  Alcotest.check
    hex
    "client_iv"
    (`Hex "6b26114b9cba2b63a9e8dd4f")
    (Hex.of_string (Cstruct.to_string client_iv));
  let client_hp = InitialAEAD.get_header_protection_key client_secret in
  Alcotest.check
    hex
    "client_hp"
    (`Hex "9ddd12c994c0698b89374a9c077a3077")
    (Hex.of_string (Cstruct.to_string client_hp))

let test_server_secrets () =
  let server_secret = InitialAEAD.get_secret ~mode:Server dest_cid in
  Alcotest.check
    hex
    "client_initial_secret"
    (`Hex "006f881359244dd9ad1acf85f595bad67c13f9f5586f5e64e1acae1d9ea8f616")
    (Hex.of_string (Cstruct.to_string server_secret));
  let server_key, server_iv = InitialAEAD.get_key_and_iv server_secret in
  Alcotest.check
    hex
    "server_key"
    (`Hex "149d0b1662ab871fbe63c49b5e655a5d")
    (Hex.of_string (Cstruct.to_string server_key));
  Alcotest.check
    hex
    "server_iv"
    (`Hex "bab2b12a4c76016ace47856d")
    (Hex.of_string (Cstruct.to_string server_iv));
  let server_hp = InitialAEAD.get_header_protection_key server_secret in
  Alcotest.check
    hex
    "server_hp"
    (`Hex "c0c499a65a60024a18a250974ea01dfa")
    (Hex.of_string (Cstruct.to_string server_hp))

let test_encrypt_client_initial () =
  let unprotected_payload =
    Hex.to_string
      (`Hex
        "060040c4010000c003036660261ff947cea49cce6cfad687f457cf1b14531ba14131a0e8f309a1d0b9c4000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d00204cfdfcd178b784bf328cae793b136f2aedce005ff183d7bb1495207236647037002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001")
  in
  let unprotected_header =
    Hex.to_string (`Hex "c3ff00001d088394c8f03e5157080000449e00000002")
  in
  let expected_protected_packet =
    `Hex
      "c5ff00001d088394c8f03e5157080000449e4a95245bfb66bc5f93032b7ddd89fe0ff15d9c4f7050fccdb71c1cd80512d4431643a53aafa1b0b518b44968b18b8d3e7a4d04c30b3ed9410325b2abb2dafb1c12f8b70479eb8df98abcaf95dd8f3d1c78660fbc719f88b23c8aef6771f3d50e10fdfb4c9d92386d44481b6c52d59e5538d3d3942de9f13a7f8b702dc31724180da9df22714d01003fc5e3d165c950e630b8540fbd81c9df0ee63f94997026c4f2e1887a2def79050ac2d86ba318e0b3adc4c5aa18bcf63c7cf8e85f569249813a2236a7e72269447cd1c755e451f5e77470eb3de64c8849d292820698029cfa18e5d66176fe6e5ba4ed18026f90900a5b4980e2f58e39151d5cd685b10929636d4f02e7fad2a5a458249f5c0298a6d53acbe41a7fc83fa7cc01973f7a74d1237a51974e097636b6203997f921d07bc1940a6f2d0de9f5a11432946159ed6cc21df65c4ddd1115f86427259a196c7148b25b6478b0dc7766e1c4d1b1f5159f90eabc61636226244642ee148b464c9e619ee50a5e3ddc836227cad938987c4ea3c1fa7c75bbf88d89e9ada642b2b88fe8107b7ea375b1b64889a4e9e5c38a1c896ce275a5658d250e2d76e1ed3a34ce7e3a3f383d0c996d0bed106c2899ca6fc263ef0455e74bb6ac1640ea7bfedc59f03fee0e1725ea150ff4d69a7660c5542119c71de270ae7c3ecfd1af2c4ce551986949cc34a66b3e216bfe18b347e6c05fd050f85912db303a8f054ec23e38f44d1c725ab641ae929fecc8e3cefa5619df4231f5b4c009fa0c0bbc60bc75f76d06ef154fc8577077d9d6a1d2bd9bf081dc783ece60111bea7da9e5a9748069d078b2bef48de04cabe3755b197d52b32046949ecaa310274b4aac0d008b1948c1082cdfe2083e386d4fd84c0ed0666d3ee26c4515c4fee73433ac703b690a9f7bf278a77486ace44c489a0c7ac8dfe4d1a58fb3a730b993ff0f0d61b4d89557831eb4c752ffd39c10f6b9f46d8db278da624fd800e4af85548a294c1518893a8778c4f6d6d73c93df200960104e062b388ea97dcf4016bced7f62b4f062cb6c04c20693d9a0e3b74ba8fe74cc01237884f40d765ae56a51688d985cf0ceaef43045ed8c3f0c33bced08537f6882613acd3b08d665fce9dd8aa73171e2d3771a61dba2790e491d413d93d987e2745af29418e428be34941485c93447520ffe231da2304d6a0fd5d07d0837220236966159bef3cf904d722324dd852513df39ae030d8173908da6364786d3c1bfcb19ea77a63b25f1e7fc661def480c5d00d44456269ebd84efd8e3a8b2c257eec76060682848cbf5194bc99e49ee75e4d0d254bad4bfd74970c30e44b65511d4ad0e6ec7398e08e01307eeeea14e46ccd87cf36b285221254d8fc6a6765c524ded0085dca5bd688ddf722e2c0faf9d0fb2ce7a0c3f2cee19ca0ffba461ca8dc5d2c8178b0762cf67135558494d2a96f1a139f0edb42d2af89a9c9122b07acbc29e5e722df8615c343702491098478a389c9872a10b0c9875125e257c7bfdf27eef4060bd3d00f4c14fd3e3496c38d3c5d1a5668c39350effbc2d16ca17be4ce29f02ed969504dda2a8c6b9ff919e693ee79e09089316e7d1d89ec099db3b2b268725d888536a4b8bf9aee8fb43e82a4d919d4843b1ca70a2d8d3f725ead1391377dcc0"
  in
  let encrypter = InitialAEAD.make ~mode:Client dest_cid in
  let packet_number = 2L in
  let data =
    Cstruct.of_string
      (unprotected_payload
      (* Add PADDING *)
      ^ String.make (1162 - String.length unprotected_payload) '\x00')
  in
  let header = Cstruct.of_string unprotected_header in
  let sealed_payload = encrypter.encrypt_payload ~packet_number ~header data in
  let sample = Cstruct.sub sealed_payload 0 16 in
  Alcotest.check
    hex
    "sample"
    (`Hex "fb66bc5f93032b7ddd89fe0ff15d9c4f")
    (Hex.of_cstruct sample);
  let header = encrypter.encrypt_header ~sample header in
  Alcotest.check
    hex
    "header"
    (`Hex "c5ff00001d088394c8f03e5157080000449e4a95245b")
    (Hex.of_cstruct header);
  Alcotest.check
    hex
    "resulting protected packet"
    expected_protected_packet
    (Hex.of_cstruct (Cstruct.append header sealed_payload));
  let header = Cstruct.of_string unprotected_header in
  let packet =
    Quic.Crypto.AEAD.encrypt_packet encrypter ~packet_number ~header data
  in
  Alcotest.check
    hex
    "resulting protected packet"
    expected_protected_packet
    (Hex.of_cstruct packet)

let test_encrypt_server_initial () =
  let unprotected_payload =
    Hex.to_string
      (`Hex
        "0d0000000018410a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00020304")
  in
  let unprotected_header =
    Hex.to_string (`Hex "c1ff00001d0008f067a5502a4262b50040740001")
  in
  let expected_protected_packet =
    `Hex
      "caff00001d0008f067a5502a4262b5004074aaf2f007823a5d3a1207c86ee49132824f0465243d082d868b107a38092bc80528664cbf9456ebf27673fb5fa5061ab573c9f001b81da028a00d52ab00b15bebaa70640e106cf2acd043e9c6b4411c0a79637134d8993701fe779e58c2fe753d14b0564021565ea92e57bc6faf56dfc7a40870e6"
  in
  let encrypter = InitialAEAD.make ~mode:Server dest_cid in
  let packet_number = 1L in
  let data = Cstruct.of_string unprotected_payload in
  let header = Cstruct.of_string unprotected_header in
  let sealed_payload = encrypter.encrypt_payload ~packet_number ~header data in
  let sample = Cstruct.sub sealed_payload 2 16 in
  Alcotest.check
    hex
    "sample"
    (`Hex "823a5d3a1207c86ee49132824f046524")
    (Hex.of_cstruct sample);
  let header = encrypter.encrypt_header ~sample header in
  Alcotest.check
    hex
    "header"
    (`Hex "caff00001d0008f067a5502a4262b5004074aaf2")
    (Hex.of_cstruct header);
  Alcotest.check
    hex
    "resulting protected packet"
    expected_protected_packet
    (Hex.of_cstruct (Cstruct.append header sealed_payload));
  let header = Cstruct.of_string unprotected_header in
  let packet =
    Quic.Crypto.AEAD.encrypt_packet encrypter ~packet_number ~header data
  in
  Alcotest.check
    hex
    "resulting protected packet"
    expected_protected_packet
    (Hex.of_cstruct packet)

let test_retry_integrity_check () =
  let data =
    Hex.to_string
      (`Hex
        "ffff00001d0008f067a5502a4262b5746f6b656ed16926d81f6f9ca2953a8aa4575e1e49")
  in
  let integrity_tag =
    Quic.Crypto.Retry.calculate_integrity_tag
      { Quic.Packet.CID.length = String.length dest_cid; id = dest_cid }
      (Bigstringaf.of_string ~off:0 ~len:(String.length data - 16) data)
  in
  Alcotest.check
    hex
    "integrity tag"
    (Hex.of_string (String.sub data (String.length data - 16) 16))
    (Hex.of_cstruct integrity_tag)

let chacha_secret =
  Cstruct.of_string
    (Hex.to_string
       (`Hex "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"))

let test_chacha_keys () =
  let key, iv = Quic.Crypto.ChaCha20.get_key_and_iv chacha_secret in
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
  let hp = Quic.Crypto.ChaCha20.get_header_protection_key chacha_secret in
  Alcotest.check
    hex
    "hp"
    (`Hex "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
    (Hex.of_string (Cstruct.to_string hp));
  let ku = Quic.Crypto.ChaCha20.get_ku chacha_secret in
  Alcotest.check
    hex
    "ku"
    (`Hex "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")
    (Hex.of_string (Cstruct.to_string ku))

let test_chacha_short_header () =
  let module ChaCha20 = Quic.Crypto.ChaCha20 in
  let unprotected_payload = Hex.to_cstruct (`Hex "01") in
  let unprotected_header = `Hex "4200bff4" in
  let expected_protected_packet =
    `Hex "4cfe4189655e5cd55c41f69080575d7999c25a5bfb"
  in
  let packet_number = 654360564L in
  let encrypter = ChaCha20.make ~secret:chacha_secret in
  let sealed_payload =
    encrypter.encrypt_payload
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
    encrypter.encrypt_header ~sample (Hex.to_cstruct unprotected_header)
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
    Quic.Crypto.AEAD.encrypt_packet
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

let test_initial_aead_header_encryption_decryption () =
  let conn_id = Hex.to_string (`Hex "decafbad") in
  let client_encrypter = InitialAEAD.make ~mode:Client conn_id in
  let unprotected_header = Hex.to_string (`Hex "8e0001020304deadbeef") in
  let sample = Cstruct.of_hex "655e5cd55c41f69080575d7999c25a5b" in
  assert (Cstruct.len sample = 16);
  let header =
    (* the first byte and the last 4 bytes should be encrypted *)
    client_encrypter.encrypt_header
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
  Alcotest.(check bool)
    "bytes 6-10 are unmodified (not protected)"
    true
    (Cstruct.to_string (Cstruct.sub header 6 4)
    <> String.sub unprotected_header 6 4);
  let decrypted_header = client_encrypter.decrypt_header ~sample header in
  Alcotest.check
    hex
    "decrypted_header matches unprotected_header"
    (Hex.of_string unprotected_header)
    (Hex.of_cstruct decrypted_header)

let test_chacha20_header_encryption_decryption () =
  let module ChaCha20 = Quic.Crypto.ChaCha20 in
  let client_encrypter = ChaCha20.make ~secret:chacha_secret in
  let unprotected_header = Hex.to_string (`Hex "8e0001020304deadbeef") in
  let sample = Cstruct.of_hex "655e5cd55c41f69080575d7999c25a5b" in
  assert (Cstruct.len sample = 16);
  let header =
    (* the first byte and the last 4 bytes should be encrypted *)
    client_encrypter.encrypt_header
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
    "bytes 6-10 are unmodified (not protected)"
    true
    (Cstruct.to_string (Cstruct.sub header 6 4)
    <> String.sub unprotected_header 6 4);
  let decrypted_header = client_encrypter.decrypt_header ~sample header in
  Alcotest.check
    hex
    "decrypted_header matches unprotected_header"
    (Hex.of_string unprotected_header)
    (Hex.of_cstruct decrypted_header)

let keys_suite =
  [ "initial secret", `Quick, test_initial_secret
  ; "client secrets", `Quick, test_client_secrets
  ; "server secrets", `Quick, test_server_secrets
  ]

let client_initial_suite =
  [ "encrypt client initial", `Quick, test_encrypt_client_initial ]

let server_initial_suite =
  [ "encrypt server initial", `Quick, test_encrypt_server_initial ]

let retry_integrity_check_suite =
  [ "check retry integrity", `Quick, test_retry_integrity_check ]

let chacha_short_header_suite =
  [ "chacha keys ", `Quick, test_chacha_keys
  ; "chacha short header", `Quick, test_chacha_short_header
  ]

let initial_aead_suite =
  [ ( "header encryption / decryption"
    , `Quick
    , test_initial_aead_header_encryption_decryption )
  ]

let chacha20_suite =
  [ ( "header encryption / decryption"
    , `Quick
    , test_chacha20_header_encryption_decryption )
  ]

let () =
  Alcotest.run
    "packets"
    [ "A.1. Keys", keys_suite
    ; "A.2. Client Initial", client_initial_suite
    ; "A.3. Server Initial", server_initial_suite
    ; "A.4. Retry", retry_integrity_check_suite
    ; "A.5. ChaCha20-Poly1305 Short Header Packet", chacha_short_header_suite
    ; "Initial AEAD", initial_aead_suite
    ; "ChaCha20", chacha20_suite
    ]
