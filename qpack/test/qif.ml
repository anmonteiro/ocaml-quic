(* https://github.com/quicwg/base-drafts/wiki/QPACK-Offline-Interop *)

let input_lines =
  let rec loop ic acc =
    match input_line ic with
    | exception End_of_file ->
      List.rev acc
    | line ->
      loop ic (line :: acc)
  in
  fun ic -> loop ic []

let read_entire_file f =
  let ch = open_in_bin f in
  let ret = really_input_string ch (in_channel_length ch) in
  close_in ch;
  ret

let parse_file f : (string * string) list list =
  let ch = open_in_bin f in
  let lines = input_lines ch in
  close_in ch;
  let ret =
    List.fold_left
      (fun acc line ->
        if line = "" then (* new header block *)
          [] :: acc
        else if line.[0] = '#' then (* comment *)
          acc
        else
          let hs = List.hd acc in
          match String.split_on_char '\t' line with
          | [ name; value ] ->
            ((name, value) :: hs) :: List.tl acc
          | _ ->
            assert false)
      [ [] ]
      lines
  in
  List.fold_left
    (fun acc item -> if item = [] then acc else List.rev item :: acc)
    []
    ret

let encode_file f (headers : (string * string) list list) =
  let ch = open_out_bin f in
  List.iter
    (fun hs ->
      List.iter
        (fun (name, value) ->
          output_string ch name;
          output_char ch '\t';
          output_string ch value;
          output_char ch '\n')
        hs;
      output_char ch '\n')
    headers;
  close_out ch

type qif =
  { stream_id : int64
  ; encoded : string
  }

let parser =
  let open Angstrom in
  BE.any_int64 >>= fun stream_id ->
  BE.any_int32 >>= fun length ->
  lift (fun encoded -> { stream_id; encoded }) (take (Int32.to_int length))
