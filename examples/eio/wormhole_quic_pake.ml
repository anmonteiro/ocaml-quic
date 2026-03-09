(* open Eio.Std *)

type role =
  | Sender
  | Receiver

let role_to_string = function Sender -> "sender" | Receiver -> "receiver"
let peer_role = function Sender -> Receiver | Receiver -> Sender

let role_of_string = function
  | "sender" -> Some Sender
  | "receiver" -> Some Receiver
  | _ -> None

let split_words s =
  String.split_on_char ' ' (String.trim s) |> List.filter (fun x -> x <> "")

let parse_int64 s =
  try Int64.of_string s with _ -> failwith ("invalid int64: " ^ s)

(* Keep hex-encoded DATA control lines under typical QUIC packet size.
   Ciphertext is sent as hex (2x expansion), so large plaintext chunks can
   exceed the current packetization limit in this example transport path. *)
let data_chunk_size = 512

let int64_to_be n =
  let b = Bytes.create 8 in
  Bytes.set_int64_be b 0 n;
  Bytes.unsafe_to_string b

let constant_time_equal a b =
  let la = String.length a in
  let lb = String.length b in
  if la <> lb
  then false
  else
    let x = ref 0 in
    for i = 0 to la - 1 do
      x := !x lor (Char.code a.[i] lxor Char.code b.[i])
    done;
    !x = 0

let hex_of_string s =
  let hexdig = "0123456789abcdef" in
  let out = Bytes.create (2 * String.length s) in
  for i = 0 to String.length s - 1 do
    let c = Char.code s.[i] in
    Bytes.set out (2 * i) hexdig.[c lsr 4];
    Bytes.set out ((2 * i) + 1) hexdig.[c land 0x0f]
  done;
  Bytes.unsafe_to_string out

let int_of_hexdig = function
  | '0' .. '9' as c -> Char.code c - Char.code '0'
  | 'a' .. 'f' as c -> 10 + Char.code c - Char.code 'a'
  | 'A' .. 'F' as c -> 10 + Char.code c - Char.code 'A'
  | c -> failwith ("invalid hex char: " ^ String.make 1 c)

let string_of_hex s =
  let len = String.length s in
  if len mod 2 <> 0 then failwith "hex string has odd length";
  let out = Bytes.create (len / 2) in
  for i = 0 to (len / 2) - 1 do
    let hi = int_of_hexdig s.[2 * i] in
    let lo = int_of_hexdig s.[(2 * i) + 1] in
    Bytes.set out i (Char.chr ((hi lsl 4) lor lo))
  done;
  Bytes.unsafe_to_string out

let random_bytes n = Mirage_crypto_rng.generate n
let sha256_raw s = Digestif.SHA256.(to_raw_string (digest_string s))
let sha256_hex s = Digestif.SHA256.(to_hex (digest_string s))

let hmac_sha256_raw ~key s =
  Digestif.SHA256.(to_raw_string (hmac_string ~key s))

let xor_with_keystream ~key ~nonce plaintext =
  let len = String.length plaintext in
  let out = Bytes.create len in
  let rec loop block_index off =
    if off < len
    then (
      let counter = int64_to_be (Int64.of_int block_index) in
      let block = hmac_sha256_raw ~key (nonce ^ counter) in
      let take = min 32 (len - off) in
      for i = 0 to take - 1 do
        let x = Char.code plaintext.[off + i] lxor Char.code block.[i] in
        Bytes.set out (off + i) (Char.chr x)
      done;
      loop (block_index + 1) (off + take))
  in
  loop 0 0;
  Bytes.unsafe_to_string out

module Line_channel = struct
  type t =
    { stream : Quic.Stream.t
    ; lines : string option Eio.Stream.t
    }

  let write_line t line =
    Quic.Stream.write_string t.stream line;
    Quic.Stream.write_char t.stream '\n';
    Quic.Stream.flush t.stream ignore

  let write_line_raw stream line =
    Quic.Stream.write_string stream line;
    Quic.Stream.write_char stream '\n';
    Quic.Stream.flush stream ignore

  let drain_lines buf push =
    let data = Buffer.contents buf in
    let n = String.length data in
    let rec loop start =
      match String.index_from_opt data start '\n' with
      | None ->
        Buffer.clear buf;
        Buffer.add_substring buf data start (n - start)
      | Some i ->
        let raw = String.sub data start (i - start) in
        let line =
          if raw <> "" && raw.[String.length raw - 1] = '\r'
          then String.sub raw 0 (String.length raw - 1)
          else raw
        in
        push line;
        loop (i + 1)
    in
    loop 0

  let of_stream stream =
    let lines = Eio.Stream.create max_int in
    let buf = Buffer.create 4096 in
    let rec pump () =
      Quic.Stream.schedule_read
        stream
        ~on_eof:(fun () ->
          drain_lines buf (fun line -> Eio.Stream.add lines (Some line));
          Eio.Stream.add lines None)
        ~on_read:(fun bs ~off ~len ->
          Buffer.add_string buf (Bigstringaf.substring bs ~off ~len);
          drain_lines buf (fun line -> Eio.Stream.add lines (Some line));
          pump ())
    in
    pump ();
    { stream; lines }

  let read_line t = Eio.Stream.take t.lines
end

module Pake = struct
  type session =
    { enc_key : string
    ; mac_key : string
    ; nonce_prefix : string
    }

  type hello =
    { nonce : string
    ; pub : string
    }

  let hkdf_extract ?salt ikm = Hkdf.extract ~hash:`SHA256 ?salt ikm
  let hkdf_expand ~prk ~info len = Hkdf.expand ~hash:`SHA256 ~prk ~info len

  let transcript ~room ~sender ~receiver =
    let sender_blob =
      "sender:" ^ hex_of_string sender.nonce ^ ":" ^ hex_of_string sender.pub
    in
    let receiver_blob =
      "receiver:"
      ^ hex_of_string receiver.nonce
      ^ ":"
      ^ hex_of_string receiver.pub
    in
    String.concat
      "|"
      [ "quic-wormhole-pake-v1"; room; sender_blob; receiver_blob ]

  let derive ~room ~password ~my_role ~my_secret ~my_hello ~peer_hello =
    let sender, receiver =
      match my_role with
      | Sender -> my_hello, peer_hello
      | Receiver -> peer_hello, my_hello
    in
    let transcript = transcript ~room ~sender ~receiver in
    let dh =
      match Mirage_crypto_ec.X25519.key_exchange my_secret peer_hello.pub with
      | Ok shared -> shared
      | Error e ->
        failwith
          (Format.asprintf
             "x25519 key exchange failed: %a"
             Mirage_crypto_ec.pp_error
             e)
    in
    let pwd_prk =
      hkdf_extract ~salt:("quic-wormhole-pake-v1/password/" ^ room) password
    in
    let hs_prk = hkdf_extract ~salt:pwd_prk dh in
    let send_auth_key =
      hkdf_expand ~prk:hs_prk ~info:("auth/" ^ role_to_string my_role) 32
    in
    let recv_auth_key =
      hkdf_expand
        ~prk:hs_prk
        ~info:("auth/" ^ role_to_string (peer_role my_role))
        32
    in
    let my_auth = hmac_sha256_raw ~key:send_auth_key transcript in
    let verify_auth peer_auth =
      constant_time_equal
        peer_auth
        (hmac_sha256_raw ~key:recv_auth_key transcript)
    in
    let session_prk = hkdf_extract ~salt:hs_prk transcript in
    let session =
      { enc_key = hkdf_expand ~prk:session_prk ~info:"file/enc" 32
      ; mac_key = hkdf_expand ~prk:session_prk ~info:"file/mac" 32
      ; nonce_prefix = hkdf_expand ~prk:session_prk ~info:"file/nonce-prefix" 16
      }
    in
    my_auth, verify_auth, session

  let chunk_nonce t seq = t.nonce_prefix ^ int64_to_be seq

  let encrypt_chunk t ~seq plaintext =
    let nonce = chunk_nonce t seq in
    let ciphertext = xor_with_keystream ~key:t.enc_key ~nonce plaintext in
    let tag = hmac_sha256_raw ~key:t.mac_key (int64_to_be seq ^ ciphertext) in
    ciphertext, tag

  let decrypt_chunk t ~seq ~ciphertext ~tag =
    let expected =
      hmac_sha256_raw ~key:t.mac_key (int64_to_be seq ^ ciphertext)
    in
    if not (constant_time_equal tag expected)
    then Error "bad chunk authenticator"
    else
      let nonce = chunk_nonce t seq in
      Ok (xor_with_keystream ~key:t.enc_key ~nonce ciphertext)
end

module Relay = struct
  type peer =
    { stream : Quic.Stream.t
    ; mutable room_name : string option
    ; mutable role : role option
    }

  type room =
    { mutable sender : peer option
    ; mutable receiver : peer option
    }

  type state = { rooms : (string, room) Hashtbl.t }

  let create_state () = { rooms = Hashtbl.create 16 }

  let send stream line =
    try Line_channel.write_line_raw stream line with _ -> ()

  let room_of_state t room_name =
    match Hashtbl.find_opt t.rooms room_name with
    | Some room -> room
    | None ->
      let room = { sender = None; receiver = None } in
      Hashtbl.add t.rooms room_name room;
      room

  let partner room role =
    match role with Sender -> room.receiver | Receiver -> room.sender

  let remove_peer t peer =
    match peer.room_name, peer.role with
    | Some room_name, Some role ->
      (match Hashtbl.find_opt t.rooms room_name with
      | Some room ->
        (match role with
        | Sender ->
          (match room.sender with
          | Some p when p == peer -> room.sender <- None
          | _ -> ())
        | Receiver ->
          (match room.receiver with
          | Some p when p == peer -> room.receiver <- None
          | _ -> ()));
        (match partner room role with
        | Some p -> send p.stream "PEER_LEFT"
        | None -> ());
        if room.sender = None && room.receiver = None
        then Hashtbl.remove t.rooms room_name
      | None -> ());
      peer.room_name <- None;
      peer.role <- None
    | _ -> ()

  let maybe_notify_ready room =
    match room.sender, room.receiver with
    | Some sender, Some receiver ->
      send sender.stream "READY receiver";
      send receiver.stream "READY sender"
    | _ -> ()

  let register_peer t peer room_name role =
    let room = room_of_state t room_name in
    let slot =
      match role with Sender -> room.sender | Receiver -> room.receiver
    in
    match slot with
    | Some _ ->
      send peer.stream "ERROR room role already occupied";
      Quic.Stream.close_writer peer.stream
    | None ->
      (match role with
      | Sender -> room.sender <- Some peer
      | Receiver -> room.receiver <- Some peer);
      peer.room_name <- Some room_name;
      peer.role <- Some role;
      send peer.stream "JOINED";
      (match partner room role with
      | Some _ -> ()
      | None -> send peer.stream "WAITING");
      maybe_notify_ready room

  let handle_line t peer line =
    match peer.room_name, peer.role with
    | None, None ->
      (match split_words line with
      | [ "JOIN"; room_name; role_name ] ->
        (match role_of_string role_name with
        | Some role -> register_peer t peer room_name role
        | None ->
          send peer.stream "ERROR role must be sender or receiver";
          Quic.Stream.close_writer peer.stream)
      | _ ->
        send peer.stream "ERROR expected: JOIN <code> <sender|receiver>";
        Quic.Stream.close_writer peer.stream)
    | Some room_name, Some role ->
      (match Hashtbl.find_opt t.rooms room_name with
      | Some room ->
        (match partner room role with
        | Some p -> send p.stream line
        | None -> send peer.stream "WAITING")
      | None -> send peer.stream "ERROR room disappeared")
    | _ ->
      send peer.stream "ERROR invalid peer state";
      Quic.Stream.close_writer peer.stream

  let attach_parser t peer =
    let buf = Buffer.create 4096 in
    let rec pump () =
      Quic.Stream.schedule_read
        peer.stream
        ~on_eof:(fun () ->
          Line_channel.drain_lines buf (fun line -> handle_line t peer line);
          remove_peer t peer)
        ~on_read:(fun bs ~off ~len ->
          Buffer.add_string buf (Bigstringaf.substring bs ~off ~len);
          Line_channel.drain_lines buf (fun line -> handle_line t peer line);
          pump ())
    in
    pump ()

  let connection_handler t ~cid:_ ~start_stream:_ =
    Quic.Transport.F
      (fun stream ->
        let peer = { stream; room_name = None; role = None } in
        attach_parser t peer;
        { on_error = (fun _ -> remove_peer t peer) })

  let run env ~sw ~port =
    let certificates =
      let cert = "./certificates/server.pem" in
      let priv_key = "./certificates/server.key" in
      `Single (Qx509.private_of_pems ~cert ~priv_key)
    in
    let config =
      { Quic.Config.certificates
      ; alpn_protocols = [ "wormhole-relay-v1" ]
      ; transport_parameters = Quic.Config.default_transport_parameters
      }
    in
    let state = create_state () in
    Format.printf "relay listening on udp port %d@." port;
    Quic_eio.Server.establish_server
      env
      ~sw
      ~config
      (`Udp (Eio.Net.Ipaddr.V4.any, port))
      (connection_handler state)
end

module Client = struct
  type opts =
    { host : string
    ; port : int
    ; code : string
    ; password : string
    }

  let resolve_udp_address host port =
    let addrs =
      Eio_unix.run_in_systhread (fun () ->
        Unix.getaddrinfo host (string_of_int port) [ Unix.(AI_FAMILY PF_INET) ])
    in
    let addrs =
      List.filter_map
        (fun (addr : Unix.addr_info) ->
           match addr.ai_addr with
           | Unix.ADDR_UNIX _ -> None
           | Unix.ADDR_INET (inet, p) -> Some (inet, p))
        addrs
    in
    match addrs with
    | [] -> failwith ("could not resolve host: " ^ host)
    | (inet, p) :: _ -> `Udp (Eio_unix.Net.Ipaddr.of_unix inet, p)

  let config () =
    let cert = "./certificates/server.pem" in
    let priv_key = "./certificates/server.key" in
    let certificates = `Single (Qx509.private_of_pems ~cert ~priv_key) in
    { Quic.Config.certificates
    ; alpn_protocols = [ "wormhole-relay-v1" ]
    ; transport_parameters = Quic.Config.default_transport_parameters
    }

  let connect env ~sw ~(opts : opts) =
    let on_connect_p, on_connect_u = Eio.Promise.create () in
    let t =
      Quic_eio.Client.create
        env
        ~sw
        ~config:(config ())
        (fun ~cid:_ ~start_stream:_ ->
           Quic.Transport.F (fun _ -> { on_error = ignore }))
    in
    let address = resolve_udp_address opts.host opts.port in
    let tls_host =
      try
        let _ = Unix.inet_addr_of_string opts.host in
        "localhost"
      with
      | Failure _ -> opts.host
    in
    Quic_eio.connect t ~address ~host:tls_host (fun ~cid:_ ~start_stream ->
      Eio.Promise.resolve on_connect_u start_stream;
      Quic.Transport.F (fun _ -> { on_error = ignore }));
    let start_stream = Eio.Promise.await on_connect_p in
    t, start_stream Quic.Direction.Bidirectional

  let wait_for_line_or_fail ch =
    match Line_channel.read_line ch with
    | Some line -> line
    | None -> failwith "relay stream closed"

  let rec wait_for_ready ch =
    match wait_for_line_or_fail ch with
    | "WAITING" -> wait_for_ready ch
    | "JOINED" -> wait_for_ready ch
    | line when String.starts_with ~prefix:"READY" line -> ()
    | "PEER_LEFT" -> failwith "peer disconnected before setup completed"
    | line when String.starts_with ~prefix:"ERROR " line -> failwith line
    | _ -> wait_for_ready ch

  let perform_pake ~opts ~role ch =
    let my_secret, my_pub = Mirage_crypto_ec.X25519.gen_key () in
    let my_hello = { Pake.nonce = random_bytes 16; pub = my_pub } in
    let hello_msg =
      Printf.sprintf
        "HELLO %s %s %s"
        (role_to_string role)
        (hex_of_string my_hello.nonce)
        (hex_of_string my_hello.pub)
    in
    Line_channel.write_line ch hello_msg;
    let rec wait_for_hello () =
      match split_words (wait_for_line_or_fail ch) with
      | [ "HELLO"; peer_role_name; nonce_hex; pub_hex ] ->
        let expected = role_to_string (peer_role role) in
        if peer_role_name <> expected then failwith "peer announced wrong role";
        { Pake.nonce = string_of_hex nonce_hex; pub = string_of_hex pub_hex }
      | [ "PEER_LEFT" ] -> failwith "peer disconnected during PAKE hello"
      | [ "WAITING" ] -> wait_for_hello ()
      | "ERROR" :: msg -> failwith ("ERROR " ^ String.concat " " msg)
      | _ -> wait_for_hello ()
    in
    let peer_hello = wait_for_hello () in
    let my_auth, verify_auth, session =
      Pake.derive
        ~room:opts.code
        ~password:opts.password
        ~my_role:role
        ~my_secret
        ~my_hello
        ~peer_hello
    in
    Line_channel.write_line ch ("AUTH " ^ hex_of_string my_auth);
    let rec wait_for_auth () =
      match split_words (wait_for_line_or_fail ch) with
      | [ "AUTH"; auth_hex ] ->
        if not (verify_auth (string_of_hex auth_hex))
        then failwith "PAKE authentication failed (wrong password?)"
      | [ "PEER_LEFT" ] -> failwith "peer disconnected during PAKE auth"
      | [ "WAITING" ] -> wait_for_auth ()
      | _ -> wait_for_auth ()
    in
    wait_for_auth ();
    session

  let do_send env ~sw ~opts ~file =
    let t, stream = connect env ~sw ~opts in
    Fun.protect
      ~finally:(fun () ->
        Quic.Stream.close_writer stream;
        Quic_eio.shutdown t)
      (fun () ->
         let ch = Line_channel.of_stream stream in
         Line_channel.write_line
           ch
           (Printf.sprintf "JOIN %s %s" opts.code (role_to_string Sender));
         wait_for_ready ch;
         let session = perform_pake ~opts ~role:Sender ch in
         let stat = Unix.stat file in
         let total_size = Int64.of_int stat.Unix.st_size in
         let filename = Filename.basename file in
         Line_channel.write_line
           ch
           (Printf.sprintf "META %s %Ld" (hex_of_string filename) total_size);
         let rec wait_meta_ok () =
           match wait_for_line_or_fail ch with
           | "META-OK" -> ()
           | "PEER_LEFT" ->
             failwith "peer disconnected before receiving metadata"
           | _ -> wait_meta_ok ()
         in
         wait_meta_ok ();
         let ic = open_in_bin file in
         Fun.protect
           ~finally:(fun () -> close_in_noerr ic)
           (fun () ->
              let digest = ref Digestif.SHA256.empty in
              let buf = Bytes.create data_chunk_size in
              let rec loop seq sent_bytes =
                let n = input ic buf 0 (Bytes.length buf) in
                if n = 0
                then (
                  let digest_hex = Digestif.SHA256.(to_hex (get !digest)) in
                  Line_channel.write_line
                    ch
                    (Printf.sprintf "DONE %Ld %s" sent_bytes digest_hex);
                  let rec wait_ack () =
                    match wait_for_line_or_fail ch with
                    | "RECV-OK" ->
                      Format.printf
                        "sent %Ld bytes from %s successfully@."
                        sent_bytes
                        file
                    | line when String.starts_with ~prefix:"RECV-BAD" line ->
                      failwith ("receiver reported integrity failure: " ^ line)
                    | "PEER_LEFT" ->
                      failwith "peer disconnected before final ack"
                    | _ -> wait_ack ()
                  in
                  wait_ack ())
                else
                  let plain = Bytes.sub_string buf 0 n in
                  digest := Digestif.SHA256.feed_string !digest plain;
                  let ciphertext, tag = Pake.encrypt_chunk session ~seq plain in
                  Line_channel.write_line
                    ch
                    (Printf.sprintf
                       "DATA %Ld %s %s"
                       seq
                       (hex_of_string ciphertext)
                       (hex_of_string tag));
                  let sent = Int64.add sent_bytes (Int64.of_int n) in
                  if Int64.rem sent 0x100000L = 0L
                  then Format.printf "sent %Ld/%Ld bytes@." sent total_size;
                  loop (Int64.succ seq) sent
              in
              loop 0L 0L))

  let do_recv env ~sw ~opts ~output =
    let t, stream = connect env ~sw ~opts in
    Fun.protect
      ~finally:(fun () ->
        Quic.Stream.close_writer stream;
        Quic_eio.shutdown t)
      (fun () ->
         let ch = Line_channel.of_stream stream in
         Line_channel.write_line
           ch
           (Printf.sprintf "JOIN %s %s" opts.code (role_to_string Receiver));
         wait_for_ready ch;
         let session = perform_pake ~opts ~role:Receiver ch in
         let rec wait_meta () =
           match split_words (wait_for_line_or_fail ch) with
           | [ "META"; name_hex; size_s ] ->
             string_of_hex name_hex, parse_int64 size_s
           | [ "PEER_LEFT" ] -> failwith "peer disconnected before metadata"
           | _ -> wait_meta ()
         in
         let sender_name, expected_size = wait_meta () in
         let out_path = Option.value output ~default:("recv-" ^ sender_name) in
         let oc = open_out_bin out_path in
         Fun.protect
           ~finally:(fun () -> close_out_noerr oc)
           (fun () ->
              Format.printf
                "receiving %s (%Ld bytes) into %s@."
                sender_name
                expected_size
                out_path;
              Line_channel.write_line ch "META-OK";
              let digest = ref Digestif.SHA256.empty in
              let rec loop next_seq written =
                match split_words (wait_for_line_or_fail ch) with
                | [ "DATA"; seq_s; ciphertext_hex; tag_hex ] ->
                  let seq = parse_int64 seq_s in
                  if seq <> next_seq then failwith "out-of-order DATA chunk";
                  let ciphertext = string_of_hex ciphertext_hex in
                  let tag = string_of_hex tag_hex in
                  let plain =
                    match Pake.decrypt_chunk session ~seq ~ciphertext ~tag with
                    | Ok x -> x
                    | Error e -> failwith ("decrypt/auth failure: " ^ e)
                  in
                  output_string oc plain;
                  digest := Digestif.SHA256.feed_string !digest plain;
                  let written =
                    Int64.add written (Int64.of_int (String.length plain))
                  in
                  if Int64.rem written 0x100000L = 0L
                  then
                    Format.printf
                      "received %Ld/%Ld bytes@."
                      written
                      expected_size;
                  loop (Int64.succ next_seq) written
                | [ "DONE"; total_s; digest_hex ] ->
                  let total = parse_int64 total_s in
                  let got_digest = Digestif.SHA256.(to_hex (get !digest)) in
                  if
                    total <> written || not (String.equal digest_hex got_digest)
                  then (
                    Line_channel.write_line
                      ch
                      (Printf.sprintf
                         "RECV-BAD total=%Ld digest=%s"
                         total
                         got_digest);
                    failwith "integrity check failed")
                  else (
                    Line_channel.write_line ch "RECV-OK";
                    Eio.Time.sleep (Eio.Stdenv.clock env) 0.1;
                    Format.printf "received %Ld bytes successfully@." written)
                | [ "PEER_LEFT" ] ->
                  failwith "peer disconnected during transfer"
                | _ -> loop next_seq written
              in
              loop 0L 0L))
end

type relay_opts = { relay_port : int }

type send_opts =
  { host : string
  ; port : int
  ; code : string option
  ; password : string option
  ; file : string option
  }

type recv_opts =
  { host : string
  ; port : int
  ; code : string option
  ; password : string option
  ; output : string option
  }

let default_send_opts =
  { host = "localhost"; port = 4443; code = None; password = None; file = None }

let default_recv_opts =
  { host = "localhost"
  ; port = 4443
  ; code = None
  ; password = None
  ; output = None
  }

let parse_relay_args argv =
  let port = ref 4443 in
  let current = ref 1 in
  Arg.parse_argv
    ~current
    argv
    [ "-p", Arg.Set_int port, " Relay UDP port (default: 4443)" ]
    (fun _ -> raise (Arg.Bad "relay does not accept positional arguments"))
    "wormhole_quic_pake relay [-p PORT]";
  { relay_port = !port }

let parse_send_args argv =
  let opts = ref default_send_opts in
  let set f v = opts := f !opts v in
  let current = ref 1 in
  Arg.parse_argv
    ~current
    argv
    [ ( "-host"
      , Arg.String (fun v -> set (fun o x -> { o with host = x }) v)
      , " Relay hostname" )
    ; ( "-p"
      , Arg.Int (fun v -> set (fun o x -> { o with port = x }) v)
      , " Relay UDP port" )
    ; ( "-code"
      , Arg.String (fun v -> set (fun o x -> { o with code = Some x }) v)
      , " Rendezvous code" )
    ; ( "-password"
      , Arg.String (fun v -> set (fun o x -> { o with password = Some x }) v)
      , " Shared password for PAKE" )
    ; ( "-file"
      , Arg.String (fun v -> set (fun o x -> { o with file = Some x }) v)
      , " Path to file to send" )
    ]
    (fun _ -> raise (Arg.Bad "send does not accept positional arguments"))
    "wormhole_quic_pake send -code CODE -password PASS -file PATH [-host HOST] \
     [-p PORT]";
  !opts

let parse_recv_args argv =
  let opts = ref default_recv_opts in
  let set f v = opts := f !opts v in
  let current = ref 1 in
  Arg.parse_argv
    ~current
    argv
    [ ( "-host"
      , Arg.String (fun v -> set (fun o x -> { o with host = x }) v)
      , " Relay hostname" )
    ; ( "-p"
      , Arg.Int (fun v -> set (fun o x -> { o with port = x }) v)
      , " Relay UDP port" )
    ; ( "-code"
      , Arg.String (fun v -> set (fun o x -> { o with code = Some x }) v)
      , " Rendezvous code" )
    ; ( "-password"
      , Arg.String (fun v -> set (fun o x -> { o with password = Some x }) v)
      , " Shared password for PAKE" )
    ; ( "-out"
      , Arg.String (fun v -> set (fun o x -> { o with output = Some x }) v)
      , " Output path (default: recv-<name>)" )
    ]
    (fun _ -> raise (Arg.Bad "recv does not accept positional arguments"))
    "wormhole_quic_pake recv -code CODE -password PASS [-out PATH] [-host \
     HOST] [-p PORT]";
  !opts

let get_required name = function
  | Some v -> v
  | None -> failwith ("missing required argument: -" ^ name)

let usage () =
  Printf.eprintf
    "Usage:\n\
    \  wormhole_quic_pake relay [-p PORT]\n\
    \  wormhole_quic_pake send -code CODE -password PASS -file PATH [-host \
     HOST] [-p PORT]\n\
    \  wormhole_quic_pake recv -code CODE -password PASS [-out PATH] [-host \
     HOST] [-p PORT]\n";
  exit 2

let () =
  Mirage_crypto_rng_unix.use_default ();
  Sys.(set_signal sigpipe Signal_ignore);
  let run () =
    if Array.length Sys.argv < 2 then usage ();
    match Sys.argv.(1) with
    | "relay" ->
      let relay_opts = parse_relay_args Sys.argv in
      Eio_main.run (fun env ->
        Eio.Switch.run (fun sw -> Relay.run env ~sw ~port:relay_opts.relay_port))
    | "send" ->
      let send_opts = parse_send_args Sys.argv in
      let opts =
        { Client.host = send_opts.host
        ; port = send_opts.port
        ; code = get_required "code" send_opts.code
        ; password = get_required "password" send_opts.password
        }
      in
      let file = get_required "file" send_opts.file in
      Eio_main.run (fun env ->
        Eio.Switch.run (fun sw -> Client.do_send env ~sw ~opts ~file))
    | "recv" ->
      let recv_opts = parse_recv_args Sys.argv in
      let opts =
        { Client.host = recv_opts.host
        ; port = recv_opts.port
        ; code = get_required "code" recv_opts.code
        ; password = get_required "password" recv_opts.password
        }
      in
      Eio_main.run (fun env ->
        Eio.Switch.run (fun sw ->
          Client.do_recv env ~sw ~opts ~output:recv_opts.output))
    | _ -> usage ()
  in
  try run () with
  | Arg.Bad msg ->
    prerr_endline msg;
    usage ()
  | Arg.Help msg ->
    print_endline msg;
    exit 0
  | Failure msg ->
    prerr_endline ("error: " ^ msg);
    exit 1
