let read_file path =
  let ic = open_in_bin path in
  let contents = really_input_string ic (in_channel_length ic) in
  close_in ic;
  Cstruct.of_string contents

let private_of_pems ~cert ~priv_key =
  let pem = read_file cert in
  let certs =
    match X509.Certificate.decode_pem_multiple pem with
    | Ok cs -> cs
    | Error (`Msg m) -> invalid_arg ("failed to parse certificates " ^ m)
  in
  (* (o failure @@ Printf.sprintf "Private certificates (%s): %s" cert) *)
  let pem = read_file priv_key in
  let pk =
    match X509.Private_key.decode_pem pem with
    | Ok k -> k
    | Error (`Msg m) -> invalid_arg ("failed to parse private key " ^ m)
    (* (o failure @@ Printf.sprintf "Private key (%s): %s" priv_key) *)
  in
  certs, pk
