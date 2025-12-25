module Quic = Quic__
open Quic

module Read_operation = struct
  type t =
    [ `Read
    | `Close
    | `Error of Error.t
    ]

  let pp_hum fmt t =
    let str = match t with `Read -> "Read" | `Close -> "Close" in
    Format.pp_print_string fmt str
end

module Write_operation = struct
  type t =
    [ `Write of Bigstringaf.t IOVec.t list
    | `Yield
    | `Close of int
    ]

  let iovecs_to_string iovecs =
    let len = IOVec.lengthv iovecs in
    let bytes = Bytes.create len in
    let dst_off = ref 0 in
    List.iter
      (fun { IOVec.buffer; off = src_off; len } ->
         Bigstringaf.unsafe_blit_to_bytes
           buffer
           ~src_off
           bytes
           ~dst_off:!dst_off
           ~len;
         dst_off := !dst_off + len)
      iovecs;
    Bytes.unsafe_to_string bytes

  let hex_of_string s =
    let (`Hex hex) = Hex.of_string s in
    String.uppercase_ascii hex

  let pp_hum fmt t =
    match t with
    | `Write iovecs ->
      Format.fprintf fmt "Write %S" (iovecs_to_string iovecs |> hex_of_string)
    | `Yield -> Format.pp_print_string fmt "Yield"
    | `Close len -> Format.fprintf fmt "Close %i" len

  let to_write_as_string t =
    match t with
    | `Write iovecs -> Some (iovecs_to_string iovecs)
    | `Close _ | `Yield -> None
end

let hex =
  (module struct
    include Hex

    let equal (`Hex h1) (`Hex h2) = String.equal h1 h2
  end : Alcotest.TESTABLE
    with type t = Hex.t)

(* let read_operation = Alcotest.of_pp Read_operation.pp_hum *)

(* let write_operation = Alcotest.of_pp Write_operation.pp_hum *)

let expected_dest_cid =
  Hex.to_string (`Hex "31347941dee1e9c13303aa17dfcd533d4c")

let protected_packet =
  Hex.to_string
    (`Hex
        "c1000000011131347941dee1e9c13303aa17dfcd533d4c000044c9bb2103827afc9e007a5ea80137885f3cbc4624705757ac85773de20bd4205591d180c6424b5b4721cf61d6010b8d644976065f673b0282770fbaf473b7c727bfdc0c615081c69bdc98781262af3d13ba8bd74fe74842e7a253171d5b738a4df79aeede469ce2652fcc0a8ad75cae5df2f369bcca9870631e6a307a560a6f47abee7db547829de3c1b813221a9f4ed1bc6f2f8594b4d3bc1b22bfee9cdd91971133712cfeab64b435ac3b6d90c967c5d57ec9aa1ed8051e46b2c71986c11387b4688f184e7c8da2c68195c40173607ba75b73a7b059ff395c5042d40ab7df99659d0ed859805c41d7e5261e1a9f9a9e4c5c47f4e6b77f02dcbf1eb9e4fee7545cc23392cfbcceb7d7b812edf48bd3cf3ac1b3ce4f783840f3142c9a55efcdfb935462fcd6186aae6a563fdc0a1182f3bca13d0bebe7e9d8e415f78352baa0297511e8d404e105f02e2ae67a45dca398ca6f0f704870b43722067970661c9e4c06b4995826277853324f0b6e5dcc2c57954a73a5176d7a179d6879d5dcc872b1b0abaec7d8875eb49132836ea00594214ec57bb349af9ba451d5172d8422f8e240cd2127f1336f1c286b3d3d5e9ed8baa65226fcb991aa064c870fca28bbea155a921e6e9a926322a25469e3d6488d912aeff1c04deeaeb520b9bff93f47ea02dc2ab0c1d2fdb4885ae9bf1529c52430491af3810739e070255900fc006e8131fd227a5ba0d35ea9b936334d6f4ad56f188a02bce72b9dfe90f79cf1e9524b9c37b32dfb3b45f63df3dbffa170f8dabb1a7d311afc86ea7450523fa0affb66fdd0ddeb219dca1593be41b703b136eb442489a5c99baf49aa325e9c601a91d242232932f40968db02de9469dc16824b116e343c07a9dd162aa10b76d58a85bfc46347cc06d161e116d8ba8c67a29e67c0cc033ea42655fb37f6eab278e9aca80c8352d22355d633eae753da13504ce0778954d33183cb5547ced30c9121e46feeac7844105f2b40d2d1bb4167ca289c32f6333e1257d2072d3076e23005abf7e61ec0cccfb58c42003734d22ecab6ff2f751f4e661eadd742cbaee596480701f4fd672654cb07069c08a820dca138a400deed7b8896b4afb5319a44baa0eae4ab089759e03e2e51119f4b10ea7d601956b0ef9f6b7a79a07a15506cd9d31b804982fc196874387cfcdeca19f89561a7234b902513e64ede0fd8bca02884b4d1a7e8f75975d2af5cbc85b991e0350f6adfd6f5c418ebd25a2933b62ff4e2786da1eba6862ad718da5676c5297fccbeb122dffab01e10c2db61304585afc20500c19390923537953aa27d474b1fa788b97e7061f3a5e9ccad9e191ead0cca5016315bc4cf28b385b5e13bc902f83246915dc80363ee5a870a21e4c0b171133aee608dfedf7088857ebe52e1d8a3228e6454d804dcd2e570027f42bc68a3ebaadf895871575f5d0b010b0b5f262e01bc4c101b0d536cbb4f619e656d493f3ed4f8866d53a25ac672b5f0fbe2959d2238bc2145671deacfbdf929503ad9d1bea3469f6536334a0ec2f1d3931ba2d52dd5cf98803e1e23b578cb7590225126b8892c4d68109f58c9c39f5675588dc5aaccca9f7beb3473a5bbaba55e6f4ea006e98bf0a3c07c526579a177f885d2d89460eac3fa8dbde6f63ad6f45ac625a1093e1ba490aa1f7848ab69b28098939f5f1cc4248020e41065adf78b599d5241cdc275bddbd394525983f9761921")

let second_protected_packet =
  Hex.to_string
    (`Hex
        "cd0000000114c3eaeabd54582a4ee2cb75bff63b8f0a874a51ad00004470555a3920a0379d2e1cffd359712768d5b196797209b3e6d31152dd3ae73e4b334d7f6f09b50c3475f64f94b9f793b08590b47563b54021febf6a4a7488063a8b608f5d82edc11fc56e50b56194c98c06206756cb43dd9548dbad5ba56d34dc18dc6970dbade5a185a16e6956ff635db8cb90d2c2652d9f126bf2612886b840ac8a977812d04e0934baede3ef9dc096356efc11fbc3dd79e1ddedcf4dad461085d9d30c3f0ba47f09c691a634a903fa6597bc11e299ad113dc0b7d9623b912fbced5c8968999b508b04b60a2ee60354a3ee28b743a591c0c728073721650bca6f0d8038120139fb3f3b36316c8b34e89531022cce51060b5e720f332b7fa3934b432cde7873aff242e45950f940540cff52262feb3724280d3d2f19f02b206926446ac34211d8bf88bddc6a717e246e35970a1405b9cfa9c335b52791f62e6dc40b958335dc7e224aba5ecac678b84ec8c9299fe3e9be87fe3bff6b01d2ebdd60f27564e78999aef0302919c4e91c59aa70f7c4bdf010e22e4dbb841cc1d12e04ce3547fa7169b66ee10e9673df4e5da70e4e7e34b0abe944d4e07aa925d4e4e81ac39b73064adcc5c6ce593a01db04ae9613730bc352bea694ee3527c59353f49bf5f0354f4d0b3cc3bf28bc985038e04682893f65b026bb7c8f2d52d2466e55427cbba9cec63c95013915c9de6d0b94ca9802b1d81262d41e26690ae9eb7844597a1752ddaa01d4cd4056e39471030957a7f909c581cc91af636d0714a88cacb9135dce88126ebd08148c7f9bbddd3cb674bb983c3682b8b2f255d0fa1b6a2cd0813d0ec747474aa6645d07e810faa90668523e343494ebebc7f643a7de5b79cfb7d2f4f4e8ff538d01cf558891974e769038d7a338557695bded367e6a806ce3d51a16eaf6d3593b299a817cf2649abcd063ae17446dd941fcdf30e09f281ef1c0fc4bb8b07d184d270289058556cf4a6f133b09eeade3e5e25784dbe8902cf462fa18bede650024edc3f06f89b65a33104cbc10454116bea92ca63cf42048a56973f3c3e64f336aaa9372ab7f798bbe7b6017af0228c5253889c9a7fcc9abc92261656210da4461830a8c193f81e0dab89c06d1f99a416819c01101a2f7558fd837d8b50ee3dadd55f68fea157f9a5bc59a31d83e9b9c451a52a0bf2cad656697b5cb916706a73bb7f03849a9b18e62e6eb524665f9607add1af5d5a2c7986d7db72d34f873e0a886a91b4c3ac298ab1e94d235625093b507e17abaa44cb9c22f47fea7423ca0d13a787fb2df6755f3cf6df1233cac9e37c6e54ea25a29bb132ae94d3daeb3b2684495fa1ad115c7386b8bbb5f6a7a268be1677858606465d8637b1b238469fce3ed1c5be474bef515606150696428373e403c5b89447ff1943e3ec8564685ecf5a3e82f3f9601163fa98f17a898754e8bc79321a187b395f87b7b8cb2c2e1fb5491630e0805a836522e51f3890a46a32d90233476b9189beb55cdc3a9a3a43aa5db92268ace3669a79ec55d4ed9a5883add2afd984d48d14085f3a767d2af8d74a6531c70e092b334300b07d8a88ffc904efa734503308ec863f1c05542a87b20899592373319c4ef0000000114c3eaeabd54582a4ee2cb75bff63b8f0a874a51ad004039627d0c5ce4b2fc326d7863092f945f7c613111c2e2d89c255e2c42efb41105661323bd911e75187fb2f3f8cb38e27d8688eaf95085603687b9")

let read_string t s =
  let len = String.length s in
  let bs = Bigstringaf.of_string ~off:0 ~len s in
  Transport.read_with_more t bs ~off:0 ~len Incomplete

let test_initial () =
  let t =
    let config =
      { Quic.Config.certificates = `None; alpn_protocols = [ "h3" ] }
    in
    Transport.Server.create ~config (fun ~cid:_ ~start_stream:_ -> assert false)
  in
  let read = read_string t protected_packet in
  Alcotest.(check int)
    "reads the whole packet"
    (String.length protected_packet)
    read;
  match Transport.next_write_operation t with
  | `Write (iovecs, _) ->
    let packet_hex = Write_operation.iovecs_to_string iovecs in
    Format.eprintf "serialized: %a@." Hex.pp (Hex.of_string packet_hex);
    let client_decrypter =
      Crypto.InitialAEAD.make ~mode:Server (CID.of_string expected_dest_cid)
    in
    let decrypted =
      Crypto.AEAD.decrypt_packet
        client_decrypter
        ~largest_pn:0L
        packet_hex
        ~payload_length:(String.length packet_hex - 16)
    in
    Alcotest.(check bool)
      "decrypts successfully using initial secrets"
      true
      (decrypted <> None)
    (* Check our serialization. *)
    (* let iovec_len = IOVec.lengthv iovecs in *)
    (* report_write_result conn (`Ok iovec_len); *)
    (* writer_yields conn; *)
    (* ready_to_read conn *)
  | _ ->
    Alcotest.fail
      "Expected state machine to issue a write operation after seeing headers."

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

let setup_logging ?style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level level

let () =
  (* setup_logging (Some Debug); *)
  Mirage_crypto_rng_unix.use_default ();
  (* initialize (module Mirage_crypto_rng.Fortuna); *)
  Alcotest.run "packets" [ "packets", suites ]
