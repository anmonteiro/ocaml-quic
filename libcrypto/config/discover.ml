module C = Configurator.V1

let file_exists path =
  try Sys.file_exists path with _ -> false

let find_map f xs =
  let rec go = function
    | [] -> None
    | x :: xs ->
      (match f x with
      | Some _ as y -> y
      | None -> go xs)
  in
  go xs

let lib_paths dir =
  let pick names =
    List.find_map
      (fun name ->
        let path = Filename.concat dir name in
        if file_exists path then Some path else None)
      names
  in
  match pick [ "libssl.dylib"; "libssl.so" ], pick [ "libcrypto.dylib"; "libcrypto.so" ] with
  | Some ssl, Some crypto -> Some [ ssl; crypto ]
  | _ -> None

let normalize_libs libs =
  let dirs =
    List.filter_map
      (fun flag ->
        if String.starts_with ~prefix:"-L" flag
        then Some (String.sub flag 2 (String.length flag - 2))
        else None)
      libs
  in
  match find_map lib_paths dirs with
  | Some libs -> libs
  | None -> libs

let default c =
  if C.ocaml_config_var_exn c "system" = "macosx"
  then
    let dir = "/usr/local/opt/openssl/lib" in
    (match lib_paths dir with
    | Some libs -> libs
    | None -> [ "-lssl"; "-lcrypto" ])
  else [ "-lssl"; "-lcrypto" ]

let cflags_default c : C.Pkg_config.package_conf =
  if C.ocaml_config_var_exn c "system" = "macosx"
  then
    if Sys.file_exists "/usr/local/opt/openssl/include"
    then
      { libs = []; cflags = [ "-I/usr/local/opt/openssl/include" ] }
    else { libs = []; cflags = [] }
  else { libs = []; cflags = [] }

let cflags c =
  let default = cflags_default c in
  match C.Pkg_config.get c with
  | None -> default.cflags
  | Some pc ->
    (match C.Pkg_config.query pc ~package:"openssl" with
    | Some s -> s.cflags
    | None -> default.cflags)

let () =
  C.main ~name:"quic-openssl-crypto" (fun c ->
      let default = default c in
      let libs =
        match C.Pkg_config.get c with
        | None -> default
        | Some pc ->
          (match C.Pkg_config.query pc ~package:"openssl" with
          | Some s -> normalize_libs s.libs
          | None -> default)
      in
      C.Flags.write_sexp "c_library_flags.sexp" libs;
      C.Flags.write_sexp
        "link_flags.sexp"
        (List.concat_map (fun flag -> [ "-cclib"; flag ]) libs);
      C.Flags.write_sexp "c_flags.sexp" (cflags c))
