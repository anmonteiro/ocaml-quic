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

let decode_instruction t { Qif.encoded; _ } =
  Angstrom.parse_string ~consume:All (Decoder.Instruction.parser t) encoded

let decode_block t { Qif.encoded; _ } =
  Angstrom.parse_string ~consume:All (Decoder.parser t) encoded

let test t ~f { Qif.stream_id; encoded } =
  if Int64.equal stream_id 0L then
    Decoder.Buffered.parse_instructions
      t
      (Bigstringaf.of_string ~off:0 ~len:(String.length encoded) encoded)
  else
    Decoder.Buffered.parse_header_block
      ~stream_id
      t
      (Bigstringaf.of_string ~off:0 ~len:(String.length encoded) encoded)
      f

let test_case ~max_size ~max_blocked_streams ~expected f () =
  let content = Qif.read_entire_file f in
  match Angstrom.(parse_string ~consume:Prefix (many Qif.parser) content) with
  | Ok xs ->
    let instructions, _ = List.partition (fun x -> x.Qif.stream_id = 0L) xs in
    let t = Decoder.Buffered.create ~max_size ~max_blocked_streams in
    let decoded_headers = ref [] in
    let f bs =
      match
        Angstrom.parse_bigstring
          ~consume:All
          (Decoder.decode_block t.decoder)
          bs
      with
      | Ok hs ->
        decoded_headers := hs :: !decoded_headers
      | Error e ->
        failwith e
    in
    List.iter (test t ~f) xs;
    let decoded_headers = List.rev !decoded_headers in
    Alcotest.(check bool)
      "dynamic table has some entries"
      true
      (t.decoder.table.length > 0 || List.length instructions = 0);
    Alcotest.(check (list (list (pair qstring qstring))))
      "expected headers"
      expected
      decoded_headers
  | Error e ->
    Alcotest.fail e

let gen_suite ~qifs_dir ~interop encoded_filename =
  let encoded_basename = Filename.basename encoded_filename in
  match String.split_on_char '.' encoded_basename with
  | [ basename; "out"; max_size; max_blocked_streams; _ack_mode ] ->
    let max_size = int_of_string max_size in
    let max_blocked_streams = int_of_string max_blocked_streams in
    let expected = Qif.parse_file (qifs_dir // (basename ^ ".qif")) in
    ( Format.asprintf "%s : %s" interop encoded_basename
    , `Quick
    , test_case ~max_size ~max_blocked_streams ~expected encoded_filename )
  | _ ->
    assert false

let is_dir f =
  match (Unix.lstat f).st_kind with Unix.S_DIR -> true | _ -> false

let suite =
  let cwd = Sys.getcwd () in
  let encoded_path =
    cwd // "qpack" // "test" // "qifs" // "encoded" // "qpack-06"
  in
  let encoded_dirs =
    Sys.readdir encoded_path
    |> Array.to_list
    |> List.filter_map (fun f ->
           let fname = encoded_path // f in
           if is_dir fname then Some fname else None)
  in
  let qifs_dir = cwd // "qpack" // "test" // "qifs" // "qifs" in
  List.concat_map
    (fun encoded_dir ->
      let encoded_files = Sys.readdir encoded_dir |> Array.to_list in
      List.map
        (fun f ->
          gen_suite
            ~interop:(Filename.basename encoded_dir)
            ~qifs_dir
            (encoded_dir // f))
        encoded_files)
    encoded_dirs
