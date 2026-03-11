module C = Configurator.V1

let split_words s =
  String.split_on_char ' ' s |> List.filter (fun x -> x <> "")

let file_exists path =
  try Sys.file_exists path with _ -> false

let find_first_map f xs =
  let rec go = function
    | [] -> None
    | x :: xs ->
      (match f x with
      | Some _ as y -> y
      | None -> go xs)
  in
  go xs

let dylib_names = [ "libssl.dylib"; "libcrypto.dylib" ]
let so_names = [ "libssl.so"; "libcrypto.so" ]

let find_openssl_dir_from_nix_ldflags () =
  match Sys.getenv_opt "NIX_LDFLAGS" with
  | None -> None
  | Some flags ->
    split_words flags
    |> find_first_map (fun token ->
           match String.starts_with ~prefix:"-L" token with
           | false -> None
           | true ->
             let dir = String.sub token 2 (String.length token - 2) in
             let has names =
               List.for_all (fun name -> file_exists (Filename.concat dir name)) names
             in
             if has dylib_names || has so_names then Some dir else None)

let lib_paths dir =
  let pick names =
    List.find_map
      (fun name ->
        let path = Filename.concat dir name in
        if file_exists path then Some path else None)
      names
  in
  match pick [ "libssl.dylib"; "libssl.so" ], pick [ "libcrypto.dylib"; "libcrypto.so" ] with
  | Some ssl, Some crypto -> Some [ "-cclib"; ssl; "-cclib"; crypto ]
  | _ -> None

let default c =
  match find_openssl_dir_from_nix_ldflags () with
  | Some dir ->
    (match lib_paths dir with
    | Some flags -> flags
    | None -> [ "-cclib"; "-lssl"; "-cclib"; "-lcrypto" ])
  | None ->
    if C.ocaml_config_var_exn c "system" = "macosx"
    then
      let dir = "/usr/local/opt/openssl/lib" in
      (match lib_paths dir with
      | Some flags -> flags
      | None -> [ "-cclib"; "-lssl"; "-cclib"; "-lcrypto" ])
    else [ "-cclib"; "-lssl"; "-cclib"; "-lcrypto" ]

let () =
  C.main ~name:"quic-openssl-link-flags" (fun c ->
      C.Flags.write_sexp "openssl_link_flags.sexp" (default c))
