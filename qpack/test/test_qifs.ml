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

let test t ~f { Qif.stream_id; encoded } =
  if Int64.equal stream_id 0L then (
    Decoder.Buffered.parse_instructions
      t
      (`Bigstring
        (Bigstringaf.of_string ~off:0 ~len:(String.length encoded) encoded))
    |> ignore;
    Decoder.Buffered.parse_instructions t `Eof |> ignore)
  else
    Decoder.Buffered.parse_header_block
      ~stream_id
      t
      (Bigstringaf.of_string ~off:0 ~len:(String.length encoded) encoded)
      (f ~stream_id)
    |> Result.get_ok

let test_case ~max_size ~max_blocked_streams ~expected f () =
  let content = Qif.read_entire_file f in
  match Angstrom.(parse_string ~consume:Prefix (many Qif.parser) content) with
  | Ok xs ->
    let instructions, _ = List.partition (fun x -> x.Qif.stream_id = 0L) xs in
    let t = Decoder.Buffered.create ~max_size ~max_blocked_streams in
    let decoded_headers = ref [] in
    let f ~stream_id bs =
      match
        Angstrom.parse_bigstring
          ~consume:All
          (Decoder.parser ~stream_id t.decoder)
          bs
      with
      | Ok (Ok (hs, _section_ack)) ->
        decoded_headers := hs :: !decoded_headers
      | Ok (Error _) ->
        assert false
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

let cwd = Sys.getcwd ()

let encoded_path = cwd // "qpack" // "test" // "qifs" // "encoded" // "qpack-06"

let qifs_dir = cwd // "qpack" // "test" // "qifs" // "qifs"

let mkdirp d =
  try Unix.mkdir d 0o755 with Unix.Unix_error (EEXIST, _, _) -> ()

type ack_mode =
  | None
  | Immediate

let gen_ocaml t f ~ack_mode ~stream_id_gen headers =
  let stream_id = !stream_id_gen in
  let encoder_buffer = Faraday.create 0x100 in
  let block_buffer = Faraday.create 0x400 in
  Encoder.encode_headers
    t
    ~stream_id
    ~encoder_buffer
    block_buffer
    (List.map (fun (name, value) -> header name value) headers);
  let encoder_s = Faraday.serialize_to_string encoder_buffer in
  if String.length encoder_s > 0 then
    Qif.serialize f { encoded = encoder_s; stream_id = 0L };
  let block_s = Faraday.serialize_to_string block_buffer in
  assert (String.length block_s > 0);
  Qif.serialize f { encoded = block_s; stream_id = !stream_id_gen };
  (match ack_mode with
  | Immediate ->
    let sackf = Faraday.create 0x10 in
    Decoder.Instruction.encode_section_acknowledgement
      sackf
      ~stream_id:(Int64.to_int stream_id);
    let sack = Faraday.serialize_to_string sackf in
    (match
       Angstrom.parse_string ~consume:All (Encoder.Instruction.parser t) sack
     with
    | Ok (Ok instruction) ->
      assert (instruction = Encoder.Instruction.Section_ack stream_id)
    | Ok (Error _) ->
      assert false
    | Error e ->
      failwith e)
  | None ->
    ());
  stream_id_gen := Int64.succ !stream_id_gen

let write_ocaml_qif_output () =
  mkdirp (encoded_path // "ocaml-qpack");
  let files = Sys.readdir qifs_dir |> Array.to_list in
  List.iter
    (fun fname ->
      let blocks = Qif.parse_file (qifs_dir // fname) in
      List.iter
        (fun (max_size, ack_mode) ->
          let stream_id_gen = ref 1L in
          let t = Encoder.create max_size in
          let f = Faraday.create 0x1000 in
          List.iter (gen_ocaml t f ~ack_mode ~stream_id_gen) blocks;
          let qif_ch =
            open_out_bin
              (encoded_path
              // "ocaml-qpack"
              // Format.asprintf
                   "%s.out.%d.0.%d"
                   (Filename.chop_extension (Filename.basename fname))
                   max_size
                   (match ack_mode with Immediate -> 1 | None -> 0))
          in
          output_string qif_ch (Faraday.serialize_to_string f);
          close_out qif_ch)
        (combine [ 0; 256; 512; 4096 ] [ Immediate; None ]))
    files

let suite =
  write_ocaml_qif_output ();
  let encoded_dirs =
    Sys.readdir encoded_path
    |> Array.to_list
    |> List.filter_map (fun f ->
           let fname = encoded_path // f in
           if is_dir fname then Some fname else None)
  in
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
