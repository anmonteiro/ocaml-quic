open Qpack__

type index =
  | PostBase
  | Relative

type table =
  | Static of int
  | Dynamic of index * int

type s = (string, Types.error) result

module Instruction = struct
  type t =
    | SetDynamicTableCapacity of int
    | InsertWithNameRef of table * s
    | InsertWithoutNameRef of s * s
    | Duplicate of int

  let parser =
    let open Angstrom in
    peek_char_fail >>= fun c ->
    let b = Char.code c in
    if b land 0b1100_0000 = 0b1100_0000 then
      lift2
        (fun idx value -> InsertWithNameRef (Static idx, value))
        (any_uint8 >>= fun b -> Qint.decode b 6)
        (Qstring.decode 8)
    else if b land 0b1000_0000 = 0b1000_0000 then
      lift2
        (fun idx value -> InsertWithNameRef (Dynamic (Relative, idx), value))
        (any_uint8 >>= fun b -> Qint.decode b 6)
        (Qstring.decode 8)
    else if b land 0b0100_0000 = 0b0100_0000 then
      lift2
        (fun name value -> InsertWithoutNameRef (name, value))
        (Qstring.decode 6)
        (Qstring.decode 8)
    else if b land 0b0010_0000 = 0b0010_0000 then
      lift (fun max -> SetDynamicTableCapacity max) (Qint.decode b 5)
    else (
      assert (b land 0b0001_0000 = 0);
      lift (fun idx -> Duplicate idx) (any_uint8 >>= fun b -> Qint.decode b 5))

  let decode stream =
    Result.get_ok (Angstrom.parse_string ~consume:Prefix parser stream)

  let decode_many stream =
    Result.get_ok
      (Angstrom.parse_string ~consume:Prefix (Angstrom.many1 parser) stream)

  module Testable : Alcotest.TESTABLE with type t = t = struct
    type nonrec t = t

    (** A way to pretty-print the value. *)
    let pp fmt = function
      | SetDynamicTableCapacity max ->
        Format.fprintf fmt "SetDynamicTableCapacity %d" max
      | InsertWithNameRef (Static idx, s) ->
        Format.fprintf
          fmt
          "InsertWithNameRef Static %d %S"
          idx
          (Result.get_ok s)
      | InsertWithNameRef (Dynamic (PostBase, idx), s) ->
        Format.fprintf
          fmt
          "InsertWithNameRef Dynamic PostBase %d %S"
          idx
          (Result.get_ok s)
      | InsertWithNameRef (Dynamic (Relative, idx), s) ->
        Format.fprintf
          fmt
          "InsertWithNameRef Dynamic Relative %d %S"
          idx
          (Result.get_ok s)
      | InsertWithoutNameRef (name, value) ->
        Format.fprintf
          fmt
          "InsertWithoutNameRef %S %S"
          (Result.get_ok name)
          (Result.get_ok value)
      | Duplicate idx ->
        Format.fprintf fmt "Duplicate %d" idx

    let equal t1 t2 =
      match t1, t2 with
      | SetDynamicTableCapacity max1, SetDynamicTableCapacity max2 ->
        max1 = max2
      | InsertWithNameRef (Static idx1, s1), InsertWithNameRef (Static idx2, s2)
        ->
        idx1 = idx2 && s1 = s2
      | ( InsertWithNameRef (Dynamic (PostBase, idx1), s1)
        , InsertWithNameRef (Dynamic (PostBase, idx2), s2) ) ->
        idx1 = idx2 && s1 = s2
      | ( InsertWithNameRef (Dynamic (Relative, idx1), s1)
        , InsertWithNameRef (Dynamic (Relative, idx2), s2) ) ->
        idx1 = idx2 && s1 = s2
      | ( InsertWithoutNameRef (name1, value1)
        , InsertWithoutNameRef (name2, value2) ) ->
        name1 = name2 && value1 = value2
      | Duplicate idx1, Duplicate idx2 ->
        idx1 = idx2
      | _ ->
        assert false
  end

  let testable : t Alcotest.testable = (module Testable)
end

module Encoding = struct
  type block =
    | Indexed of table
    | LiteralWithNameRef of table * s
    | LiteralWithoutNameRef of s * s

  let parser =
    let open Angstrom in
    peek_char_fail >>= fun c ->
    let b = Char.code c in
    if b land 0b1100_0000 = 0b1100_0000 then
      lift
        (fun idx -> Indexed (Static idx))
        (any_uint8 >>= fun b -> Qint.decode b 6)
    else if b land 0b1000_0000 = 0b1000_0000 then
      lift
        (fun idx -> Indexed (Dynamic (Relative, idx)))
        (any_uint8 >>= fun b -> Qint.decode b 6)
    else if b land 0b0100_0000 = 0b0100_0000 then
      lift2
        (fun idx value ->
          let is_static = b land 0b0001_0000 = 0b0001_0000 in
          LiteralWithNameRef
            ((if is_static then Static idx else Dynamic (Relative, idx)), value))
        (any_uint8 >>= fun b -> Qint.decode b 4)
        (Qstring.decode 8)
    else if b land 0b0010_0000 = 0b0010_0000 then
      lift2
        (fun name value -> LiteralWithoutNameRef (name, value))
        (Qstring.decode 4)
        (Qstring.decode 8)
    else if b land 0b0001_0000 = 0b0001_0000 then
      lift
        (fun idx -> Indexed (Dynamic (PostBase, idx)))
        (any_uint8 >>= fun b -> Qint.decode b 4)
    else (
      assert (b land 0b1111_0000 = 0b0000_0000);
      lift2
        (fun idx value -> LiteralWithNameRef (Dynamic (PostBase, idx), value))
        (any_uint8 >>= fun b -> Qint.decode b 3)
        (Qstring.decode 8))

  let decode stream =
    Format.eprintf "%a@." Hex.pp (Hex.of_string stream);
    match Angstrom.parse_string ~consume:Prefix parser stream with
    | Ok x ->
      x
    | Error e ->
      failwith e

  let decode_many stream =
    Format.eprintf "%a@." Hex.pp (Hex.of_string stream);
    match
      Angstrom.parse_string ~consume:Prefix (Angstrom.many1 parser) stream
    with
    | Ok x ->
      x
    | Error e ->
      failwith e

  module Testable : Alcotest.TESTABLE with type t = block = struct
    type t = block

    (** A way to pretty-print the value. *)
    let pp fmt = function
      | Indexed (Static idx) ->
        Format.fprintf fmt "Indexed Static %d" idx
      | Indexed (Dynamic (PostBase, idx)) ->
        Format.fprintf fmt "Indexed Dynamic Postbase %d" idx
      | Indexed (Dynamic (Relative, idx)) ->
        Format.fprintf fmt "Indexed Dynamic Relative %d" idx
      | LiteralWithNameRef (Static idx, s) ->
        Format.fprintf
          fmt
          "LiteralWithNameRef Static %d %S"
          idx
          (Result.get_ok s)
      | LiteralWithNameRef (Dynamic (Relative, idx), s) ->
        Format.fprintf
          fmt
          "LiteralWithNameRef Dynamic Relative %d %S"
          idx
          (Result.get_ok s)
      | LiteralWithNameRef (Dynamic (PostBase, idx), s) ->
        Format.fprintf
          fmt
          "LiteralWithNameRef Dynamic PostBase %d %S"
          idx
          (Result.get_ok s)
      | LiteralWithoutNameRef (name, value) ->
        Format.fprintf
          fmt
          "LiteralWithoutNameRef %S %S"
          (Result.get_ok name)
          (Result.get_ok value)

    let equal t1 t2 =
      match t1, t2 with
      | Indexed (Static idx1), Indexed (Static idx2)
      | Indexed (Dynamic (PostBase, idx1)), Indexed (Dynamic (PostBase, idx2))
      | Indexed (Dynamic (Relative, idx1)), Indexed (Dynamic (Relative, idx2))
        ->
        idx1 = idx2
      | ( LiteralWithNameRef (Static idx1, s1)
        , LiteralWithNameRef (Static idx2, s2) )
      | ( LiteralWithNameRef (Dynamic (Relative, idx1), s1)
        , LiteralWithNameRef (Dynamic (Relative, idx2), s2) )
      | ( LiteralWithNameRef (Dynamic (PostBase, idx1), s1)
        , LiteralWithNameRef (Dynamic (PostBase, idx2), s2) ) ->
        idx1 = idx2 && s1 = s2
      | ( LiteralWithoutNameRef (name1, value1)
        , LiteralWithoutNameRef (name2, value2) ) ->
        name1 = name2 && value1 = value2
      | _ ->
        assert false
  end

  let testable : block Alcotest.testable = (module Testable)
end

let hex = Alcotest.of_pp Hex.pp

let encoding = Encoding.testable

let instruction = Instruction.testable

let hex_of_int i =
  let c1, c2 = Hex.of_char (Char.chr i) in
  `Hex (Format.asprintf "%c%c" c1 c2)

let header ?(sensitive = false) name value = { Types.name; value; sensitive }

let encode t hs =
  let prefixBuffer = Faraday.create 0x1000 in
  let encoder_buffer = Faraday.create 0x1000 in
  let faraday = Faraday.create 0x1000 in
  Encoder.encode_headers t ~prefixBuffer ~encoder_buffer faraday hs;
  let s = Faraday.serialize_to_string faraday in
  let e = Faraday.serialize_to_string encoder_buffer in
  e, s

let test_encode_static () =
  let hdr = header ":method" "GET" in
  let t = Encoder.create 4096 in
  let encoder, stream = encode t [ hdr ] in
  Alcotest.(check string) "no encoder instructions" "" encoder;
  Alcotest.check
    encoding
    "encoded static table index"
    (Encoding.Indexed (Static 17))
    (Encoding.decode stream)

let test_encode_static_name_reference () =
  let hdr = header "location" "/bar" in
  let t = Encoder.create 4096 in
  let encoder, stream = encode t [ hdr ] in
  Alcotest.check
    encoding
    "encoded in the dynamic table with post base indexing"
    (Encoding.Indexed (Dynamic (PostBase, 0)))
    (Encoding.decode stream);
  Alcotest.check
    instruction
    "insert with (static) name ref"
    (Instruction.InsertWithNameRef (Static 12, Ok "/bar"))
    (Instruction.decode encoder)

let test_encode_static_nameref_indexed_in_dynamic () =
  let hdr = header "location" "/bar" in
  let t = Encoder.create 4096 in
  let _ = encode t [ hdr ] in
  let encoder, stream = encode t [ hdr ] in
  Alcotest.check
    encoding
    "encoded in the dynamic table with post base indexing"
    (Encoding.Indexed (Dynamic (Relative, 0)))
    (Encoding.decode stream);
  Alcotest.(check string) "no encoder instructions" "" encoder

let test_encode_dynamic_insert () =
  let hdr = header "foo" "bar" in
  let t = Encoder.create 4096 in
  let encoder, stream = encode t [ hdr ] in
  Alcotest.check
    encoding
    "encoded in the dynamic table with post base indexing"
    (Encoding.Indexed (Dynamic (PostBase, 0)))
    (Encoding.decode stream);
  Alcotest.check
    instruction
    "insert with name ref"
    (Instruction.InsertWithoutNameRef (Ok "foo", Ok "bar"))
    (Instruction.decode encoder)

let test_encode_dynamic_insert_nameref () =
  let t = Encoder.create 4096 in
  let _ = encode t [ header "foo" "bar"; header "baz" "bar" ] in
  let encoder, stream = encode t [ header "foo" "quxx" ] in
  Alcotest.check
    encoding
    "encoded in the dynamic table with post base indexing"
    (Encoding.Indexed (Dynamic (PostBase, 0)))
    (Encoding.decode stream);
  Alcotest.check
    instruction
    "insert with (dynamic) name ref"
    (Instruction.InsertWithNameRef (Dynamic (Relative, 1), Ok "quxx"))
    (Instruction.decode encoder)

(* TODO: add a test that sets the capacity to 0 and check that the encoder
 * stream emits a table size update. *)
let test_encode_literal () =
  let t = Encoder.create 0 in
  let hdr = header "foo" "bar" in
  let encoder, stream = encode t [ hdr ] in
  Alcotest.(check string) "no encoder instructions" "" encoder;
  Alcotest.check
    encoding
    "encoded in the dynamic table with post base indexing"
    (Encoding.LiteralWithoutNameRef (Ok "foo", Ok "bar"))
    (Encoding.decode stream)

let test_encode_literal_with_nameref () =
  let t = Encoder.create 63 in
  let hdr = header "foo" "bar" in
  let _encoder, stream = encode t [ hdr ] in
  Alcotest.check
    encoding
    "encoded in the dynamic table with post base indexing"
    (Encoding.Indexed (Dynamic (PostBase, 0)))
    (Encoding.decode stream);
  let encoder, stream = encode t [ header "foo" "quxx" ] in
  Alcotest.check
    encoding
    "encoded in the dynamic table with post base indexing"
    (Encoding.LiteralWithNameRef (Dynamic (Relative, 0), Ok "quxx"))
    (Encoding.decode stream);
  Alcotest.(check string) "no encoder instructions" "" encoder

let test_encode_literal_postbase_nameref () =
  let t = Encoder.create 63 in
  let encoder, stream = encode t [ header "foo" "bar"; header "foo" "quxx" ] in
  Alcotest.check
    instruction
    "insert with name ref"
    (Instruction.InsertWithoutNameRef (Ok "foo", Ok "bar"))
    (Instruction.decode encoder);
  Alcotest.(check (list encoding))
    "encoded in the dynamic table with post base indexing"
    [ Encoding.Indexed (Dynamic (PostBase, 0))
    ; Encoding.LiteralWithNameRef (Dynamic (PostBase, 0), Ok "quxx")
    ]
    (Encoding.decode_many stream)

let test_encode_with_header_block () =
  let t = Encoder.create 4096 in
  for idx = 1 to 4 do
    ignore
    @@ encode
         t
         [ header (Format.asprintf "foo%d" idx) (Format.asprintf "bar%d" idx) ]
  done;
  let encoder, stream =
    encode
      t
      [ header ":method" "GET"
      ; header "foo1" "bar1"
      ; header "foo3" "new bar3"
      ; header ":method" "staticnameref"
      ; header "newfoo" "newbar"
      ]
  in
  Alcotest.(check int)
    "dynamic table has 7 entries"
    7
    t.Encoder.table.Dynamic_table.length;
  Alcotest.(check (list instruction))
    "expected encoder instructions"
    [ Instruction.InsertWithNameRef (Dynamic (Relative, 1), Ok "new bar3")
    ; InsertWithNameRef
        (Static Static_table.TokenIndices.token__method, Ok "staticnameref")
    ; InsertWithoutNameRef (Ok "newfoo", Ok "newbar")
    ]
    (Instruction.decode_many encoder);
  Alcotest.(check (list encoding))
    "expected encoded header block"
    [ Encoding.Indexed (Static 17)
    ; Indexed (Dynamic (Relative, 3))
    ; Indexed (Dynamic (PostBase, 0))
    ; Indexed (Dynamic (PostBase, 1))
    ; Indexed (Dynamic (PostBase, 2))
    ]
    (Encoding.decode_many stream)

let suite =
  [ "static access", `Quick, test_encode_static
  ; ( "encode with static name reference"
    , `Quick
    , test_encode_static_name_reference )
  ; ( "encode static name, after dynamic indexing"
    , `Quick
    , test_encode_static_nameref_indexed_in_dynamic )
  ; "encode dynamic insert", `Quick, test_encode_dynamic_insert
  ; "encode with dynamic name ref", `Quick, test_encode_dynamic_insert_nameref
  ; "encode literal", `Quick, test_encode_literal
  ; "encode literal with name ref", `Quick, test_encode_literal_with_nameref
  ; ( "encode literal with postbase name ref"
    , `Quick
    , test_encode_literal_postbase_nameref )
  ; "encode with header block", `Quick, test_encode_with_header_block
  ]
