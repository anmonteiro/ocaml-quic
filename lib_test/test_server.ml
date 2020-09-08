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
    | `Yield ->
      Format.pp_print_string fmt "Yield"
    | `Close len ->
      Format.fprintf fmt "Close %i" len

  let to_write_as_string t =
    match t with
    | `Write iovecs ->
      Some (iovecs_to_string iovecs)
    | `Close _ | `Yield ->
      None
end

(* let read_operation = Alcotest.of_pp Read_operation.pp_hum *)

(* let write_operation = Alcotest.of_pp Write_operation.pp_hum *)

let dest_cid = Hex.to_string (`Hex "1a62e7da4450e266238c715d3a779620")

let protected_packet =
  Hex.to_string
    (`Hex
      "c8ff00001d101a62e7da4450e266238c715d3a779620147aa9d9db36ecf47946506282abffc83805f1000f004482893691606fa3d8e6ead667b736131cd1f2002260557a831873dc63266b5426312208fb44f208e3694639dbcfd106f193a5ba87cf13b4b56f5af461962569f6e3b301953de490f90503675084c9614e85dff281334bedabe5f27c0a55e51a566ee3918031efc88f0022519a9007fe1daada1cf22613a7e5ab1dcc975cf255ccc22c459991fa9a332fafa10fcf01a3217709a734d3e9b6d943f1acde66f9a1fd9480f0eb3bd719a448bfca56e9580568dcadfbc1edfd28feafa157a0ee3540c1edfe6b50452f820e6bab2de31694e38f0cecba005b09f50c8d07a15df74302d91c277bd6746b4e4d0aab702b857e4105d21f5aa9046126d38dc8ac26884cc4332553840bbc3345182bfb74e79b3537920456d82003d2d56f3032b37e73e527583f36392a8f6e5ce47fa6a60a7eacc27a2ed87d2c1e10d4f57b3e02dfac0e852df34da68d6e0f01a58e6c36d33428a6c421cc4d44224190099f0dd13db7fb313e047d06dd85ab64eb184711e6b9681f0cfedaa8b2f0aa50810ffa22d60c0211374f257564441cc8360cfd61b947355b700845c5415fd409748c928c0dc5f18855298fed22dd10f7f01548458b686e691802a95f643aff8ef9550fd31e6fb607e529182a3db2bef6aae1d05143b5b49f5c4eb37a0943fee87f17787a8bd9601bdbf086b99af7c381e12998e4fce36de1ce05f9436eb1aaa861f86409eb941eadeb3574dcd8d9c2532352740200b3b9d9a505bec4d0f2a30ffc9411e902969b1fa3514b961dd857c8c10191377ce1e3e231461f48d77a292a5828999d3a69425687fd032e321839568861598472eee85ccb06d174dee25578bbc219c9ba8c549593dc508a0205d1e3e77035d70347eb62c1102e5ead2fd3beb3e06a2f616c30f8f8543b45ad68d5f6d919f9914ffbeaac39e4ac546486aae7adf90418390a99a5ddf041077fbda5f80e7ac387a41b2899eac0c1846f08f0e7693b0f329a3d4cb8ac12b609cea01fac474c75089c5f994cb53d2d08b11554bb3c9d7e7ff9ba13847603b7a6d19ec22d38f231f6c0bc2100a52ee44c8050b02f02df82df8d593a66924d93ae2cb8b433fae27e567484fe76f0de017ec7ceac94800538be4fc7341a827bd326ccb4886faa4f869b5991b77841b74a33a3c6203d8b74df3403786bcca845bb347b8ca6345e1d014502a44c7313af2ef07c09a579d394da8e49a9dae1ae7b57339adfb723d59af3989177e8edd9d37c98b9426ed5129168e01276f435476a72a7baeab11266c40645f4fdc142420775e52611416a6c424bea1412d39fad7102fea7b20c26d75fdbe21597b155c66a3536e2572152680406b82dc3ae37f88f494d62bccb2e6cce01ac40ae4c7c327157b6e78c9819b2d3808c33ffd1afd7087ed842034bb1d396a7bcfaa9abf9979d73cffe6275f107f849f3cfc7439f779a10efb8864b6450a1579b9780484e1892b5439ce076364ef44e5486eaec03dc23ff0c279d300eb86d0f1570c67059cdb155d5bac34f122491014494e59d2cc09b288823b63a85feeff01d61b5ea8cf2eca4d0d6e5df8355582986ac34c89b436782f7cc7e49849d947fe71f40ec9dccd6f7aac7ff4258bb1fb61e8b9bb2024fecb849")

let second_protected_packet =
  Hex.to_string
    (`Hex
      "caff00001d147aa9d9db36ecf47946506282abffc83805f1000f101a62e7da4450e266238c715d3a779620004077491b214c376c0043173c542cc6ad28812619e5e386051a03187168bcff1063306990679a8831c0e264b50d89155eb8952fa01b6ab57f742a2bd4348f0bfc124c27fa25292fe961fbdb87e85a408c26c3e78d8dc703c35f65b131b294d0136ad4e81cea000d6848fdc426a58eb9c115b1c16cc60237fc46")

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
  match Server_connection.next_write_operation t with
  | `Write (iovecs, _) ->
    let packet_hex = Write_operation.iovecs_to_string iovecs in
    Format.eprintf "serialized: %a@." Hex.pp (Hex.of_string packet_hex);
    let client_decrypter = Crypto.InitialAEAD.make ~mode:Server dest_cid in
    let decrypted =
      Crypto.AEAD.decrypt_packet
        client_decrypter
        ~largest_pn:0L
        (Cstruct.of_string packet_hex)
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
  Mirage_crypto_rng_unix.initialize ();
  Alcotest.run "packets" [ "packets", suites ]
