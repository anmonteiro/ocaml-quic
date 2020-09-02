let packet =
  Hex.to_string
    (`Hex
      "c5babababa10ba3277447bcd7d52f000dbd01a9036d214ee486210a44ac02365ac618b2deaff628b23b15500448248d5d15e9dd1560fc7a98125a72459d81aa0b05a474359d30158428c2a21b9d8e7832bb3876bb92919d35ca529d94ba590a3a00d749092bb8bc34ad602fa567dc0a252dd46f4345af617f1761d8eddc12fea7d25ff8576dab200ce8597e1a7352a2b9206a115c179ec188108fa04748e4a6ec683e7ef9b0407de7b8fe0361a26945812b67ade453dea1b19b1658defaa5057b3489ae01c5930785040d90dbc4758a5a51192a8d9e3ea243315a64bc9b369b9e327499565a01acb001e958aa740332183a7216474cf99e7ae30a292e8c5c094b8adbe363f11736d7efb0d8396965f0cafd59222635d17ae1873d7c086e6530290c8a11998d9d774e96e134cc458b41ddb1789d31642114a551ba559b9e03993a85c2bdcad7ea9ed34ffde0983572a1f6fa851fd67605894f0be9fa00f9139c9a23be6becf10860656b4ba39e34c5b9388497dabc0585870dcc47d2e425099d9a0559dfe362f4c0702fcfdd39429625bc4210dd2ecbf8e6775fcd728b0688f9a3993eba471fc2f6a3b35746f35a74b3c9f116162d0c813ac050d70499bd7f36d2b42135fe18888f2209fbc879e267281b4aaca0803ac9b09bf22b4caf7415a5845cf00ebd0b7c3c5d5afe18539e44119aac4e8e9b7815bdec0937ce39d48d1cf618bc67aca69801f1df22267f4d61dbe7dafce33763cc0534dcef15730493e80a13f93063192a8cb37498cde0228ab2fae27339058ac89e4872b3e6e437720248201c771fc037306535b90b3fd5a7d0b9e7d4d202c47fa9769b970d05318be726c46955e5ae5649f1dfa9d4a98720d67af43b203a2885ec8ab1d5d609bc20d2ca894e3aa84d02fbcc5a3ba8107e2910b43602c185745b1cb02a83900d375d4a12a1d83646eca037bfe10c5ef8bc9b2601662dbfca8195388d36a6af8450325a9849346a22dc9eefcddd0e45d09c64ab41eb5c83df805ae38bbcb03f39602a1762129ae1e2286356a7e2214584d5935a09d1c82bbb7cf7e5f9b2af93ba030ded13af08fec811141d92d3c07d23aa5a23f9412801f2abc0437fa39ff1183d10a8d93a426a0432afc93773a9600af5fac8bb1a8b3e00b5711c99a6179dc31e876f1c04442f6a19955e0e71cdf0366e655e0df769165ee1923be7726a3eadbd709fe4d5a02ffbcbf4052fcb68c39013fba4e441f1be57c8eb5a274609cd6340103dd488654cba9752675e908c16b32652fbc8d956069c4797c2dc722cda71c9914eeaed20f72619bbf5b85381daaacac997703f05da8292f16365f73fbe3ba2ffdbbf1175bc8b94c43c7aa7fba069a6b508a6af27e61bf887cef6415a76c071160418a2c0fed71aa340ea065509724b97a69b33eea623becda9c1e3434d6807153905df46fafd1f0b875a0ecb4a8fcff5852d4f07312355a6fe5ebf6bb0c390157d4aba2abbf1373ae806141fd8dc9e18905104b31dd1bff24e553d3670ce152c4f405d6b962b118a267442be61cd34c0dbc340b536718de0fb1e2f577020726644e3fd9b91245fa327904c826bf74fb60cecf687275ea6fcaee9db30ee688e5d24860824745fc651ef887530a7c53040979440d0bd2900e86f5fd3eabaa044a6a56e4cecf4938aaf27367cd0b79778a4bc9")

let test_initial () =
  match Angstrom.parse_string ~consume:All Quic.Parse.Packet.parser packet with
  | Ok packet ->
    (match packet with
    | Crypt { header = Initial { source_cid; _ }; payload } ->
      Alcotest.(check int) "source_cid len" 20 source_cid.length;
      Alcotest.(check string)
        "source_cid"
        "\238Hb\016\164J\192#e\172a\139-\234\255b\139#\177U"
        source_cid.id;
      Format.eprintf "Crypt: %d@." (Bigstringaf.length payload);
      (match
         Angstrom.parse_bigstring
           ~consume:Prefix
           Quic.Parse.Frame.parser
           payload
       with
      | Ok frame ->
        let hex =
          Hex.of_string (Bigstringaf.substring payload ~off:0 ~len:20)
        in
        Format.eprintf "Success %a @." Hex.pp hex;
        Format.eprintf
          "Success 0x%x @."
          (Quic.Frame.to_frame_type frame |> Quic.Frame.Type.serialize)
      | _ ->
        assert false);
      assert false
    | _ ->
      assert false)
  | Error _ ->
    Alcotest.fail "Expected the parser to succeed"

let suites = [ "initial", `Quick, test_initial ]

let () = Alcotest.run "packets" [ "packets", suites ]
