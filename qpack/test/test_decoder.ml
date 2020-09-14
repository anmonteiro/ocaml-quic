open Qpack__
open Test_helpers

(*
  *  /**
 *   * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
 *   * 4.3.1.  Insert With Name Reference
 *   */
 *  #[test]
 *  fn test_insert_field_with_wrong_name_index_from_static_table() {
 *      let mut buf = vec![];
 *      InsertWithNameRef::new_static(3000, "")
 *          .encode(&mut buf)
 *          .unwrap();
 *      let mut enc = Cursor::new(&buf);
 *      let mut table = build_table_with_size(0);
 *      let res = on_encoder_recv(&mut table.inserter(), &mut enc, &mut vec![]);
 *      assert_eq!(res, Err(Error::InvalidStaticIndex(3000)));
 *  }

 *  /**
 *   * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
 *   * 4.3.1.  Insert With Name Reference
 *   */
 *  #[test]
 *  fn test_insert_field_with_wrong_name_index_from_dynamic_table() {
 *      let mut buf = vec![];
 *      InsertWithNameRef::new_dynamic(3000, "")
 *          .encode(&mut buf)
 *          .unwrap();
 *      let mut enc = Cursor::new(&buf);
 *      let mut dec = vec![];
 *      let mut table = build_table_with_size(0);
 *      let res = on_encoder_recv(&mut table.inserter(), &mut enc, &mut dec);
 *      assert_eq!(
 *          res,
 *          Err(Error::DynamicTableError(
 *              DynamicTableError::BadRelativeIndex(3000)
 *          ))
 *      );

 *      assert!(dec.is_empty());
 *  }

 *  #[test]
 *  fn largest_ref_too_big() {
 *      let table = build_table_with_size(0);
 *      let mut buf = vec![];
 *      HeaderPrefix::new(8, 8, 10, TABLE_SIZE).encode(&mut buf);

 *      let mut read = Cursor::new(&buf);
 *      assert_eq!(decode_header(&table, &mut read), Err(Error::MissingRefs(8)));
 *  }

 *  fn field(n: usize) -> HeaderField {
 *      HeaderField::new(format!("foo{}", n), "bar")
 *  }

 *  //      Largest Reference
 *  //        Base Index = 2
 *  //             |
 *  // foo4 foo3  foo2  foo1
 *  // +---+-----+-----+-----+
 *  // | 4 |  3  |  2  |  1  |  Absolute Index
 *  // +---+-----+-----+-----+
 *  //           |  0  |  1  |  Relative Index
 *  // +-----+-----+---+-----+
 *  // | 1 |  0  |              Post-Base Index
 *  // +---+-----+

 *  #[test]
 *  fn decode_post_base_indexed() {
 *      let mut buf = vec![];
 *      HeaderPrefix::new(4, 2, 4, TABLE_SIZE).encode(&mut buf);
 *      Indexed::Dynamic(0).encode(&mut buf);
 *      IndexedWithPostBase(0).encode(&mut buf);
 *      IndexedWithPostBase(1).encode(&mut buf);

 *      let mut read = Cursor::new(&buf);
 *      let (headers, had_refs) = decode_header(&build_table_with_size(4), &mut read).unwrap();
 *      assert!(had_refs);
 *      assert_eq!(headers, &[field(2), field(3), field(4)])
 *  }

 *  #[test]
 *  fn decode_name_ref_header_field() {
 *      let mut buf = vec![];
 *      HeaderPrefix::new(2, 2, 4, TABLE_SIZE).encode(&mut buf);
 *      LiteralWithNameRef::new_dynamic(1, "new bar1")
 *          .encode(&mut buf)
 *          .unwrap();
 *      LiteralWithNameRef::new_static(18, "PUT")
 *          .encode(&mut buf)
 *          .unwrap();

 *      let mut read = Cursor::new(&buf);
 *      let (headers, had_refs) = decode_header(&build_table_with_size(4), &mut read).unwrap();
 *      assert!(had_refs);
 *      assert_eq!(
 *          headers,
 *          &[
 *              field(1).with_value("new bar1"),
 *              StaticTable::get(18).unwrap().with_value("PUT")
 *          ]
 *      )
 *  }

 *  #[test]
 *  fn decode_post_base_name_ref_header_field() {
 *      let mut buf = vec![];
 *      HeaderPrefix::new(2, 2, 4, TABLE_SIZE).encode(&mut buf);
 *      LiteralWithPostBaseNameRef::new(0, "new bar3")
 *          .encode(&mut buf)
 *          .unwrap();

 *      let mut read = Cursor::new(&buf);
 *      let (headers, _) = decode_header(&build_table_with_size(4), &mut read).unwrap();
 *      assert_eq!(headers, &[field(3).with_value("new bar3")]);
 *  }

 *  #[test]
 *  fn decode_without_name_ref_header_field() {
 *      let mut buf = vec![];
 *      HeaderPrefix::new(0, 0, 0, TABLE_SIZE).encode(&mut buf);
 *      Literal::new("foo", "bar").encode(&mut buf).unwrap();

 *      let mut read = Cursor::new(&buf);
 *      let table = build_table_with_size(0);
 *      let (headers, _) = decode_header(&table, &mut read).unwrap();
 *      assert_eq!(
 *          headers,
 *          &[HeaderField::new(b"foo".to_vec(), b"bar".to_vec())]
 *      );
 *  }

 *  // Largest Reference = 4
 *  //  |            Base Index = 0
 *  //  |                |
 *  // foo4 foo3  foo2  foo1
 *  // +---+-----+-----+-----+
 *  // | 4 |  3  |  2  |  1  |  Absolute Index
 *  // +---+-----+-----+-----+
 *  //                          Relative Index
 *  // +---+-----+-----+-----+
 *  // | 2 |   2 |  1  |  0  |  Post-Base Index
 *  // +---+-----+-----+-----+

 *  #[test]
 *  fn decode_single_pass_encoded() {
 *      let mut buf = vec![];
 *      HeaderPrefix::new(4, 0, 4, TABLE_SIZE).encode(&mut buf);
 *      IndexedWithPostBase(0).encode(&mut buf);
 *      IndexedWithPostBase(1).encode(&mut buf);
 *      IndexedWithPostBase(2).encode(&mut buf);
 *      IndexedWithPostBase(3).encode(&mut buf);

 *      let mut read = Cursor::new(&buf);
 *      let (headers, _) = decode_header(&build_table_with_size(4), &mut read).unwrap();
 *      assert_eq!(headers, &[field(1), field(2), field(3), field(4)]);
 *  }

 *  #[test]
 *  fn largest_ref_greater_than_max_entries() {
 *      let max_entries = TABLE_SIZE / 32;
 *      // some fields evicted
 *      let table = build_table_with_size(max_entries + 10);
 *      let mut buf = vec![];

 *      // Pre-base relative reference
 *      HeaderPrefix::new(
 *          max_entries + 5,
 *          max_entries + 5,
 *          max_entries + 10,
 *          TABLE_SIZE,
 *      )
 *      .encode(&mut buf);
 *      Indexed::Dynamic(10).encode(&mut buf);

 *      let mut read = Cursor::new(&buf);
 *      let (headers, _) =
 *          decode_header(&build_table_with_size(max_entries + 10), &mut read).expect("decode");
 *      assert_eq!(headers, &[field(max_entries - 5)]);

 *      let mut buf = vec![];

 *      // Post-base reference
 *      HeaderPrefix::new(
 *          max_entries + 10,
 *          max_entries + 5,
 *          max_entries + 10,
 *          TABLE_SIZE,
 *      )
 *      .encode(&mut buf);
 *      IndexedWithPostBase(0).encode(&mut buf);
 *      IndexedWithPostBase(4).encode(&mut buf);

 *      let mut read = Cursor::new(&buf);
 *      let (headers, _) = decode_header(&table, &mut read).unwrap();
 *      assert_eq!(headers, &[field(max_entries + 6), field(max_entries + 10)]);
 *  }
 *)

module Instruction = struct
  type t =
    | Section_ack of int64
    | Stream_cancelation of int64
    | Insert_count_increment of int

  let parser =
    let open Angstrom in
    any_uint8 >>= fun b ->
    if b land 0b1000_0000 = 0b1000_0000 then
      (* From RFC<QPACK-RFC>§4.4.1:
       *   The instruction begins with the '1' one-bit pattern, followed by the
       *   field section's associated stream ID encoded as a 7-bit prefix
       *   integer; see Section 4.1.1. *)
      lift
        (fun stream_id -> Section_ack (Int64.of_int stream_id))
        (Qint.decode b 7)
    else if b land 0b0100_0000 = 0b0100_0000 then
      (* From RFC<QPACK-RFC>§4.4.2:
       *   The instruction begins with the '01' two-bit pattern, followed by the
       *   stream ID of the affected stream encoded as a 6-bit prefix integer. *)
      lift
        (fun stream_id -> Stream_cancelation (Int64.of_int stream_id))
        (Qint.decode b 6)
    else (
      assert (b land 0b1100_0000 = 0b0000_0000);
      (* From RFC<QPACK-RFC>§4.4.3:
       *   The Insert Count Increment instruction begins with the '00' two-bit
       *   pattern, followed by the Increment encoded as a 6-bit prefix integer. *)
      lift (fun inc -> Insert_count_increment inc) (Qint.decode b 6))

  let decode_many = Angstrom.many parser

  module Testable : Alcotest.TESTABLE with type t = t = struct
    type nonrec t = t

    (** A way to pretty-print the value. *)
    let pp fmt = function
      | Section_ack stream_id ->
        Format.fprintf fmt "Section_ack %Ld" stream_id
      | Stream_cancelation stream_id ->
        Format.fprintf fmt "Stream_cancelation %Ld" stream_id
      | Insert_count_increment inc ->
        Format.fprintf fmt "Insert_count_increment %d" inc

    let equal t1 t2 =
      match t1, t2 with
      | Section_ack s1, Section_ack s2
      | Stream_cancelation s1, Stream_cancelation s2 ->
        Int64.equal s1 s2
      | Insert_count_increment inc1, Insert_count_increment inc2 ->
        inc1 = inc2
      | _ ->
        assert false
  end

  let testable : t Alcotest.testable = (module Testable)
end

let instruction = Instruction.testable

let header ?(sensitive = false) name value = { Types.name; value; sensitive }

let decode_instructions t buf =
  Angstrom.parse_string ~consume:All (Decoder.Instruction.parser t) buf

let decode_header_block t hs =
  Angstrom.parse_string ~consume:All (Decoder.decode_block t) hs

let test_insert_field_with_dynamic_name_ref () =
  let t = Decoder.create 4096 in
  let f = Faraday.create 0x1000 in
  Encoder.Instruction.encode_insert_with_name_reference
    f
    ~table:Static (* not used in static refs *)
    ~base:(-1)
    1
    "serial value";
  let s = Faraday.serialize_to_string f in
  match decode_instructions t s with
  | Ok decoder ->
    Alcotest.(check int) "entry in the dynamic table" 1 t.table.length;
    let name, value = Dynamic_table.get t.table 0 in
    Alcotest.(check string) "name" ":path" name;
    Alcotest.(check string) "value" "serial value" value;
    (match Angstrom.parse_string ~consume:All Instruction.parser decoder with
    | Ok ins ->
      Alcotest.check
        instruction
        "insert count increment emitted"
        (Instruction.Insert_count_increment 1)
        ins
    | Error e ->
      Alcotest.fail e)
  | Error e ->
    Alcotest.fail e

let test_insert_field_without_name_ref () =
  let t = Decoder.create 4096 in
  let f = Faraday.create 0x1000 in
  Encoder.Instruction.encode_insert_without_name_reference f "key" "value";
  let s = Faraday.serialize_to_string f in
  match decode_instructions t s with
  | Ok decoder ->
    Alcotest.(check int) "entry in the dynamic table" 1 t.table.length;
    let name, value = Dynamic_table.get t.table 0 in
    Alcotest.(check string) "name" "key" name;
    Alcotest.(check string) "value" "value" value;
    (match Angstrom.parse_string ~consume:All Instruction.parser decoder with
    | Ok ins ->
      Alcotest.check
        instruction
        "insert count increment emitted"
        (Instruction.Insert_count_increment 1)
        ins
    | Error e ->
      Alcotest.fail e)
  | Error e ->
    Alcotest.fail e

let test_duplicate_field () =
  let t = Decoder.create 4096 in
  let f = Faraday.create 0x1000 in
  let added1 = Decoder.add t "" "" in
  let added2 = Decoder.add t "foo" "bar" in
  Alcotest.(check bool) "added to the dynamic table" true added1;
  Alcotest.(check bool) "added to the dynamic table" true added2;
  Encoder.Instruction.encode_duplicate f ~base:2 1;
  let s = Faraday.serialize_to_string f in
  match decode_instructions t s with
  | Ok decoder ->
    Alcotest.(check int) "entry in the dynamic table" 3 t.table.length;
    let name, value = Dynamic_table.get t.table 2 in
    Alcotest.(check string) "name" "foo" name;
    Alcotest.(check string) "value" "bar" value;
    (match Angstrom.parse_string ~consume:All Instruction.parser decoder with
    | Ok ins ->
      Alcotest.check
        instruction
        "insert count increment emitted"
        (Instruction.Insert_count_increment 1)
        ins
    | Error e ->
      Alcotest.fail e)
  | Error e ->
    Alcotest.fail e

let test_dynamic_table_size_update () =
  let t = Decoder.create 25 in
  let f = Faraday.create 0x1000 in
  Encoder.Instruction.encode_set_dynamic_table_capacity f 25;
  let s = Faraday.serialize_to_string f in
  match decode_instructions t s with
  | Ok decoder ->
    Alcotest.(check int) "processed table size update" 25 t.table.max_size;
    (match
       Angstrom.parse_string ~consume:All Instruction.decode_many decoder
     with
    | Ok ins ->
      Alcotest.(check (list instruction)) "No instructions emitted" [] ins
    | Error e ->
      Alcotest.fail e)
  | Error e ->
    Alcotest.fail e

let test_instruction_too_short () =
  let t = Decoder.create 25 in
  let f = Faraday.create 0x1000 in
  (match decode_instructions t "" with
  | Ok _ ->
    Alcotest.fail "expected decoding instruction too short to fail"
  | Error _ ->
    Alcotest.(check pass) "failed decoding a too short instruction" true true);
  Faraday.write_uint8 f 0b1000_0000;
  let s = Faraday.serialize_to_string f in
  match decode_instructions t s with
  | Ok _ ->
    Alcotest.fail "expected decoding instruction too short to fail"
  | Error _ ->
    Alcotest.(check pass) "failed decoding a too short instruction" true true

(*
 *  Largest Reference
 *    Base Index = 2
 *        |
 *      foo2   foo1
 *     +-----+-----+
 *     |  1  |  0  |  Absolute Index
 *     +-----+-----+
 *     |  0  |  1  |  Relative Index
 *     --+---+-----+
 *)
let test_decode_indexed_header_field () =
  let t = Decoder.create 4096 in
  let added1 = Decoder.add t "foo1" "bar" in
  let added2 = Decoder.add t "foo2" "bar" in
  Alcotest.(check bool) "added to the dynamic table" true added1;
  Alcotest.(check bool) "added to the dynamic table" true added2;
  let f = Faraday.create 0x1000 in
  Encoder.encode_section_prefix
    (Encoder.create 4096)
    f
    ~required_insert_count:2
    ~base:2;
  Encoder.encode_index_reference f ~table:Dynamic ~base:2 1;
  Encoder.encode_index_reference f ~table:Dynamic ~base:2 0;
  Encoder.encode_index_reference f ~table:Static ~base:2 18;
  let s = Faraday.serialize_to_string f in
  match decode_header_block t s with
  | Ok headers ->
    Alcotest.(check (list (pair qstring qstring)))
      "expected headers"
      [ "foo2", "bar"; "foo1", "bar"; Static_table.table.(18) ]
      headers
  | Error e ->
    Alcotest.fail e

let suite =
  [ ( "insert field with name reference"
    , `Quick
    , test_insert_field_with_dynamic_name_ref )
  ; "insert without name reference", `Quick, test_insert_field_without_name_ref
  ; "duplicate field", `Quick, test_duplicate_field
  ; "dynamic table size update", `Quick, test_dynamic_table_size_update
  ; "parse instruction that is too short", `Quick, test_instruction_too_short
  ; "decode indexed header field", `Quick, test_decode_indexed_header_field
  ]
