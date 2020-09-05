module Quic = Quic__
open Quic

let protected_packet =
  Hex.to_string
    (`Hex
      "c5babababa10ba3277447bcd7d52f000dbd01a9036d214ee486210a44ac02365ac618b2deaff628b23b15500448248d5d15e9dd1560fc7a98125a72459d81aa0b05a474359d30158428c2a21b9d8e7832bb3876bb92919d35ca529d94ba590a3a00d749092bb8bc34ad602fa567dc0a252dd46f4345af617f1761d8eddc12fea7d25ff8576dab200ce8597e1a7352a2b9206a115c179ec188108fa04748e4a6ec683e7ef9b0407de7b8fe0361a26945812b67ade453dea1b19b1658defaa5057b3489ae01c5930785040d90dbc4758a5a51192a8d9e3ea243315a64bc9b369b9e327499565a01acb001e958aa740332183a7216474cf99e7ae30a292e8c5c094b8adbe363f11736d7efb0d8396965f0cafd59222635d17ae1873d7c086e6530290c8a11998d9d774e96e134cc458b41ddb1789d31642114a551ba559b9e03993a85c2bdcad7ea9ed34ffde0983572a1f6fa851fd67605894f0be9fa00f9139c9a23be6becf10860656b4ba39e34c5b9388497dabc0585870dcc47d2e425099d9a0559dfe362f4c0702fcfdd39429625bc4210dd2ecbf8e6775fcd728b0688f9a3993eba471fc2f6a3b35746f35a74b3c9f116162d0c813ac050d70499bd7f36d2b42135fe18888f2209fbc879e267281b4aaca0803ac9b09bf22b4caf7415a5845cf00ebd0b7c3c5d5afe18539e44119aac4e8e9b7815bdec0937ce39d48d1cf618bc67aca69801f1df22267f4d61dbe7dafce33763cc0534dcef15730493e80a13f93063192a8cb37498cde0228ab2fae27339058ac89e4872b3e6e437720248201c771fc037306535b90b3fd5a7d0b9e7d4d202c47fa9769b970d05318be726c46955e5ae5649f1dfa9d4a98720d67af43b203a2885ec8ab1d5d609bc20d2ca894e3aa84d02fbcc5a3ba8107e2910b43602c185745b1cb02a83900d375d4a12a1d83646eca037bfe10c5ef8bc9b2601662dbfca8195388d36a6af8450325a9849346a22dc9eefcddd0e45d09c64ab41eb5c83df805ae38bbcb03f39602a1762129ae1e2286356a7e2214584d5935a09d1c82bbb7cf7e5f9b2af93ba030ded13af08fec811141d92d3c07d23aa5a23f9412801f2abc0437fa39ff1183d10a8d93a426a0432afc93773a9600af5fac8bb1a8b3e00b5711c99a6179dc31e876f1c04442f6a19955e0e71cdf0366e655e0df769165ee1923be7726a3eadbd709fe4d5a02ffbcbf4052fcb68c39013fba4e441f1be57c8eb5a274609cd6340103dd488654cba9752675e908c16b32652fbc8d956069c4797c2dc722cda71c9914eeaed20f72619bbf5b85381daaacac997703f05da8292f16365f73fbe3ba2ffdbbf1175bc8b94c43c7aa7fba069a6b508a6af27e61bf887cef6415a76c071160418a2c0fed71aa340ea065509724b97a69b33eea623becda9c1e3434d6807153905df46fafd1f0b875a0ecb4a8fcff5852d4f07312355a6fe5ebf6bb0c390157d4aba2abbf1373ae806141fd8dc9e18905104b31dd1bff24e553d3670ce152c4f405d6b962b118a267442be61cd34c0dbc340b536718de0fb1e2f577020726644e3fd9b91245fa327904c826bf74fb60cecf687275ea6fcaee9db30ee688e5d24860824745fc651ef887530a7c53040979440d0bd2900e86f5fd3eabaa044a6a56e4cecf4938aaf27367cd0b79778a4bc9")

(* let protected_packet = Hex.to_string (`Hex
   "c5ff00001d088394c8f03e5157080000449e4a95245bfb66bc5f93032b7ddd89fe0ff15d9c4f7050fccdb71c1cd80512d4431643a53aafa1b0b518b44968b18b8d3e7a4d04c30b3ed9410325b2abb2dafb1c12f8b70479eb8df98abcaf95dd8f3d1c78660fbc719f88b23c8aef6771f3d50e10fdfb4c9d92386d44481b6c52d59e5538d3d3942de9f13a7f8b702dc31724180da9df22714d01003fc5e3d165c950e630b8540fbd81c9df0ee63f94997026c4f2e1887a2def79050ac2d86ba318e0b3adc4c5aa18bcf63c7cf8e85f569249813a2236a7e72269447cd1c755e451f5e77470eb3de64c8849d292820698029cfa18e5d66176fe6e5ba4ed18026f90900a5b4980e2f58e39151d5cd685b10929636d4f02e7fad2a5a458249f5c0298a6d53acbe41a7fc83fa7cc01973f7a74d1237a51974e097636b6203997f921d07bc1940a6f2d0de9f5a11432946159ed6cc21df65c4ddd1115f86427259a196c7148b25b6478b0dc7766e1c4d1b1f5159f90eabc61636226244642ee148b464c9e619ee50a5e3ddc836227cad938987c4ea3c1fa7c75bbf88d89e9ada642b2b88fe8107b7ea375b1b64889a4e9e5c38a1c896ce275a5658d250e2d76e1ed3a34ce7e3a3f383d0c996d0bed106c2899ca6fc263ef0455e74bb6ac1640ea7bfedc59f03fee0e1725ea150ff4d69a7660c5542119c71de270ae7c3ecfd1af2c4ce551986949cc34a66b3e216bfe18b347e6c05fd050f85912db303a8f054ec23e38f44d1c725ab641ae929fecc8e3cefa5619df4231f5b4c009fa0c0bbc60bc75f76d06ef154fc8577077d9d6a1d2bd9bf081dc783ece60111bea7da9e5a9748069d078b2bef48de04cabe3755b197d52b32046949ecaa310274b4aac0d008b1948c1082cdfe2083e386d4fd84c0ed0666d3ee26c4515c4fee73433ac703b690a9f7bf278a77486ace44c489a0c7ac8dfe4d1a58fb3a730b993ff0f0d61b4d89557831eb4c752ffd39c10f6b9f46d8db278da624fd800e4af85548a294c1518893a8778c4f6d6d73c93df200960104e062b388ea97dcf4016bced7f62b4f062cb6c04c20693d9a0e3b74ba8fe74cc01237884f40d765ae56a51688d985cf0ceaef43045ed8c3f0c33bced08537f6882613acd3b08d665fce9dd8aa73171e2d3771a61dba2790e491d413d93d987e2745af29418e428be34941485c93447520ffe231da2304d6a0fd5d07d0837220236966159bef3cf904d722324dd852513df39ae030d8173908da6364786d3c1bfcb19ea77a63b25f1e7fc661def480c5d00d44456269ebd84efd8e3a8b2c257eec76060682848cbf5194bc99e49ee75e4d0d254bad4bfd74970c30e44b65511d4ad0e6ec7398e08e01307eeeea14e46ccd87cf36b285221254d8fc6a6765c524ded0085dca5bd688ddf722e2c0faf9d0fb2ce7a0c3f2cee19ca0ffba461ca8dc5d2c8178b0762cf67135558494d2a96f1a139f0edb42d2af89a9c9122b07acbc29e5e722df8615c343702491098478a389c9872a10b0c9875125e257c7bfdf27eef4060bd3d00f4c14fd3e3496c38d3c5d1a5668c39350effbc2d16ca17be4ce29f02ed969504dda2a8c6b9ff919e693ee79e09089316e7d1d89ec099db3b2b268725d888536a4b8bf9aee8fb43e82a4d919d4843b1ca70a2d8d3f725ead1391377dcc0") *)

let read_string t s =
  let len = String.length s in
  let bs = Bigstringaf.of_string ~off:0 ~len s in
  Server_connection.read t bs ~off:0 ~len

let test_initial () =
  let t = Server_connection.create () in
  let read = read_string t protected_packet in
  Alcotest.(check int)
    "reads the whole packet"
    (String.length protected_packet)
    read;
  assert false

(* match *)
(* Angstrom.parse_string ~consume:All Quic.Parse.Packet.parser protected_packet *)
(* with *)
(* | Ok packet -> *)
(* (match packet with *)
(* | Crypt { header = Initial { source_cid; dest_cid; _ }; payload; _ } -> *)
(* let decrypter = Quic.Crypto.InitialAEAD.make ~mode:Client dest_cid.id in *)
(* let _, unprotected = *)
(* Quic.Crypto.AEAD.decrypt_packet *)
(* decrypter *)
(* ~largest_pn:0L *)
(* (Cstruct.of_string protected_packet) *)
(* in *)
(* Format.eprintf "X: %s@." (Cstruct.debug (Option.get unprotected)); *)
(* Alcotest.(check int) "source_cid len" 20 source_cid.length; *)
(* Alcotest.(check string) *)
(* "source_cid" *)
(* "\238Hb\016\164J\192#e\172a\139-\234\255b\139#\177U" *)
(* source_cid.id; *)
(* Format.eprintf "Crypt: %d@." (Bigstringaf.length payload); *)
(* (match *)
(* Angstrom.parse_bigstring *)
(* ~consume:Prefix *)
(* Quic.Parse.Frame.parser *)
(* (Option.get unprotected |> Cstruct.to_bigarray) *)
(* with *)
(* | Ok frame -> *)
(* let hex = *)
(* Hex.of_string (Bigstringaf.substring payload ~off:0 ~len:20) *)
(* in *)
(* Format.eprintf "Success %a @." Hex.pp hex; *)
(* Format.eprintf *)
(* "Success 0x%x @." *)
(* (Quic.Frame.to_frame_type frame |> Quic.Frame.Type.serialize) *)
(* | _ -> *)
(* assert false); *)
(* assert false *)
(* | _ -> *)
(* assert false) *)
(* | Error _ -> *)
(* Alcotest.fail "Expected the parser to succeed" *)

let suites = [ "initial", `Quick, test_initial ]

let () =
  Mirage_crypto_rng_unix.initialize ();
  Alcotest.run "packets" [ "packets", suites ]
