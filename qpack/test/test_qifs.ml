open Qpack__
open Test_helpers

let rec join ?(memo = []) = function
  | [] ->
    Ok (List.rev memo)
  | (Error _ as err) :: _ ->
    err
  | Ok x :: xs ->
    join ~memo:(x :: memo) xs

let decoder ~max_size ~max_blocked_streams:_ = Decoder.create max_size

type decoded =
  | Instruction of string
  | Headers of (string * string) list

let decode_instruction t { Qif.encoded; _ } =
  Angstrom.parse_string ~consume:All (Decoder.Instruction.parser t) encoded

let decode_block t { Qif.encoded; _ } =
  Angstrom.parse_string ~consume:All (Decoder.parser t) encoded

let test t ({ Qif.stream_id; _ } as qif) =
  if Int64.equal stream_id 0L then
    Result.map (fun s -> Instruction s) (decode_instruction t qif)
  else
    Result.map (fun hs -> Headers hs) (decode_block t qif)

let test_many t ~f xs = join (List.map (f t) xs)

let test_case ~max_size ~max_blocked_streams ~expected f () =
  let content = Qif.read_entire_file f in
  match
    Angstrom.(
      parse_string
        ~consume:Prefix
        (many Qif.parser)
        (* (lift2 (fun x y -> x, y) Qif.parser Qif.parser) *)
        content)
  with
  | Ok xs ->
    let t = decoder ~max_size ~max_blocked_streams in
    let instructions, blocks =
      List.partition (fun { Qif.stream_id; _ } -> Int64.equal stream_id 0L) xs
    in
    (match test_many t ~f:decode_instruction instructions with
    | Ok _ ->
      Alcotest.(check bool)
        "dynamic table has some entries"
        true
        (t.table.length > 0);
      (match test_many t ~f:decode_block blocks with
      | Ok headers ->
        Format.eprintf "got some! %d %d@." t.next_seq (List.length headers);
        Qif.encode_file (Filename.concat (Sys.getcwd ()) "foo.qif") headers;
        Alcotest.(check (list (list (pair qstring qstring))))
          "expected headers"
          expected
          headers
      | Error e ->
        Alcotest.fail e)
    | Error e ->
      Alcotest.fail e)
  | Error e ->
    Alcotest.fail e

let ( // ) = Filename.concat

let gen_suite ~qifs_dir encoded_filename =
  let encoded_basename = Filename.basename encoded_filename in
  match String.split_on_char '.' encoded_basename with
  | [ basename; "out"; max_size; max_blocked_streams; _ack_mode ] ->
    let max_size = int_of_string max_size in
    let max_blocked_streams = int_of_string max_blocked_streams in
    let expected = Qif.parse_file (qifs_dir // (basename ^ ".qif")) in
    ( encoded_basename
    , `Quick
    , test_case ~max_size ~max_blocked_streams ~expected encoded_filename )
  | _ ->
    Format.eprintf "grr: %s@." encoded_basename;
    assert false

let x =
  let cwd = Sys.getcwd () in
  let encoded_dir =
    cwd // "qpack" // "test" // "qifs" // "encoded" // "qpack-06" // "proxygen"
  in
  let qifs_dir = cwd // "qpack" // "test" // "qifs" // "qifs" in
  let encoded_files = Sys.readdir encoded_dir |> Array.to_list in
  List.map (fun f -> gen_suite ~qifs_dir (encoded_dir // f)) encoded_files

let suite = x
