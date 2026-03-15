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

let parse_int s =
  try int_of_string s with _ -> failwith ("invalid int: " ^ s)

module Transfer_stats = struct
  type t =
    { label : string
    ; total : int64 option
    ; started_at : float
    ; mutable first_byte_at : float option
    ; mutable bytes : int64
    ; mutable reported : bool
    }

  let now_s () = Unix.gettimeofday ()

  let create ?total ~label () =
    { label
    ; total
    ; started_at = now_s ()
    ; first_byte_at = None
    ; bytes = 0L
    ; reported = false
    }

  let on_bytes t n =
    if n > 0
    then (
      if Option.is_none t.first_byte_at then t.first_byte_at <- Some (now_s ());
      t.bytes <- Int64.add t.bytes (Int64.of_int n))

  let report t ~status =
    if not t.reported
    then (
      t.reported <- true;
      let ended_at = now_s () in
      let duration_s = max 1e-6 (ended_at -. t.started_at) in
      let mib_per_s = (Int64.to_float t.bytes /. (1024. *. 1024.)) /. duration_s in
      let mbps = (Int64.to_float t.bytes *. 8. /. 1_000_000.) /. duration_s in
      let first_byte_latency_ms =
        match t.first_byte_at with
        | None -> "n/a"
        | Some ts -> Printf.sprintf "%.1f ms" ((ts -. t.started_at) *. 1000.)
      in
      let size =
        match t.total with
        | None -> Printf.sprintf "%Ld bytes" t.bytes
        | Some total -> Printf.sprintf "%Ld/%Ld bytes" t.bytes total
      in
      Printf.printf
        "\n%s stats: status=%s, size=%s, first-byte-latency=%s, duration=%.3fs, \
         throughput=%.2f MiB/s (%.2f Mbit/s)\n%!"
        t.label
        status
        size
        first_byte_latency_ms
        duration_s
        mib_per_s
        mbps)
end

type progress =
  { label : string
  ; total : int64
  ; width : int
  ; mutable last_percent : int
  }

let create_progress ~label ~total =
  { label; total; width = 30; last_percent = -1 }

let progress_percent ~current ~total =
  if total <= 0L
  then 100
  else
    int_of_float
      (max
         0.
         (min 100. ((Int64.to_float current *. 100.) /. Int64.to_float total)))

let render_progress t ~current ~percent =
  let filled = (percent * t.width) / 100 in
  let bar = Bytes.make t.width '-' in
  for i = 0 to filled - 1 do
    Bytes.set bar i '#'
  done;
  Printf.printf
    "\r%s [%s] %3d%% (%Ld/%Ld bytes)%!"
    t.label
    (Bytes.unsafe_to_string bar)
    percent
    current
    t.total

let update_progress t current =
  let percent = progress_percent ~current ~total:t.total in
  if percent <> t.last_percent || current = t.total
  then (
    t.last_percent <- percent;
    render_progress t ~current ~percent)

let finish_progress t current =
  update_progress t current;
  Printf.printf "\n%!"

(* Keep hex-encoded DATA control lines under typical QUIC packet size.
   Ciphertext is sent as hex (2x expansion), so large plaintext chunks can
   exceed the current packetization limit in this example transport path. *)
let data_chunk_size = 512
let ack_interval_chunks = 256L
let max_inflight_chunks = 1024L

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

  let write_line_raw stream line =
    let payload = line ^ "\n" in
    let bs =
      Bigstringaf.of_string ~off:0 ~len:(String.length payload) payload
    in
    Quic.Stream.schedule_bigstring stream bs;
    Quic.Stream.flush stream ignore

  let write_line t line = write_line_raw t.stream line

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

module Direct = struct
  let alpn = "h3"
  let upload_chunk_size = 16384
  let flush_batch_bytes = 256 * 1024

  let auth_token (session : Pake.session) =
    hmac_sha256_raw
      ~key:session.mac_key
      "wormhole-direct-h3-upload-v1"
    |> hex_of_string

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
    ; alpn_protocols = [ alpn ]
    ; transport_parameters = Quic.Config.default_transport_parameters
    ; max_datagram_size = Quic.Config.default_max_datagram_size
    }

  let candidate_hosts ?advertise_host () =
    let hosts = Hashtbl.create 8 in
    let add host =
      if host <> "" then Hashtbl.replace hosts host ()
    in
    (match advertise_host with
    | Some host -> add host
    | None -> ());
    add "127.0.0.1";
    let hostname = Unix.gethostname () in
    let infos =
      try Unix.getaddrinfo hostname "" [ Unix.(AI_FAMILY PF_INET) ] with _ -> []
    in
    List.iter
      (fun (info : Unix.addr_info) ->
         match info.ai_addr with
         | Unix.ADDR_INET (inet, _) -> add (Unix.string_of_inet_addr inet)
         | Unix.ADDR_UNIX _ -> ())
      infos;
    Hashtbl.to_seq_keys hosts |> List.of_seq |> List.sort_uniq String.compare

  type receiver_listener =
    { completion : ((Transfer_stats.t * string), exn) result Eio.Promise.t
    ; port : int
    ; hosts : string list
    }

  let start_receiver env ~sw ~port ~advertise_host ~session ~output =
    let completion_p, completion_u = Eio.Promise.create () in
    let resolved = ref false in
    let resolve_once result =
      if not !resolved
      then (
        resolved := true;
        Eio.Promise.resolve completion_u result)
    in
    let request_handler reqd =
      let request = H3.Reqd.request reqd in
      let auth_ok =
        match H3.Headers.get request.H3.Request.headers "x-wormhole-auth" with
        | Some token -> constant_time_equal token (auth_token session)
        | None -> false
      in
      match request.H3.Request.meth, request.H3.Request.target, auth_ok with
      | `POST, "/upload", true ->
        let sender_name =
          match H3.Headers.get request.H3.Request.headers "x-wormhole-name" with
          | Some name_hex ->
            (try string_of_hex name_hex with _ -> "upload.bin")
          | None -> "upload.bin"
        in
        let out_path = Option.value output ~default:("recv-" ^ sender_name) in
        let request_body = H3.Reqd.request_body reqd in
        let expected_len =
          match H3.Request.body_length request with
          | `Fixed len -> Some len
          | `Unknown | `Error _ -> None
        in
        let stats =
          Transfer_stats.create ~label:"direct recv" ?total:expected_len ()
        in
        let progress =
          Option.map
            (fun total -> create_progress ~label:"receiving" ~total)
            expected_len
        in
        Printf.printf
          "receiving %s (%s) into %s\n%!"
          sender_name
          (match expected_len with
          | Some len -> Printf.sprintf "%Ld bytes" len
          | None -> "unknown size")
          out_path;
        Option.iter (fun p -> update_progress p 0L) progress;
        let oc = open_out_bin out_path in
        let finished = ref false in
        let finalize ok =
          if not !finished
          then (
            finished := true;
            (match progress with
            | Some p -> finish_progress p stats.bytes
            | None -> ());
            close_out_noerr oc;
            if ok
            then (
              H3.Reqd.respond_with_string reqd (H3.Response.create `OK) "ok";
              resolve_once (Ok (stats, out_path)))
            else (
              H3.Reqd.respond_with_string
                reqd
                (H3.Response.create `Internal_server_error)
                "upload failed";
              resolve_once (Error (Failure "direct upload failed"))))
        in
        let rec read_body () =
          H3.Body.Reader.schedule_read
            request_body
            ~on_eof:(fun () -> finalize true)
            ~on_read:(fun bigstring ~off ~len ->
              try
                output_string oc (Bigstringaf.substring bigstring ~off ~len);
                Transfer_stats.on_bytes stats len;
                Option.iter (fun p -> update_progress p stats.bytes) progress;
                (match expected_len with
                | Some expected when Int64.compare stats.bytes expected >= 0 ->
                  finalize true
                | _ -> read_body ())
              with
              | exn ->
                close_out_noerr oc;
                resolve_once (Error exn);
                raise exn)
        in
        read_body ()
      | `POST, "/upload", false ->
        H3.Reqd.respond_with_string
          reqd
          (H3.Response.create `Forbidden)
          "forbidden"
      | _ ->
        H3.Reqd.respond_with_string
          reqd
          (H3.Response.create `Not_found)
          "not found"
    in
    let connection_handler = H3.Server_connection.create request_handler in
    Eio.Fiber.fork ~sw (fun () ->
      Quic_eio.Server.establish_server
        env
        ~sw
        ~config:(config ())
        (`Udp (Eio.Net.Ipaddr.V4.any, port))
        connection_handler);
    { completion = completion_p
    ; port
    ; hosts = candidate_hosts ?advertise_host ()
    }

  let await_completion t =
    match Eio.Promise.await t.completion with
    | Ok result -> result
    | Error exn -> raise exn

  let upload_via_candidate env ~sw ~session ~file (host, port) =
    Eio.Switch.run (fun direct_sw ->
      let on_connect_p, on_connect_u = Eio.Promise.create () in
      let done_p, done_u = Eio.Promise.create () in
      let resolved = ref false in
      let resolve_once result =
        if not !resolved
        then (
          resolved := true;
          Eio.Promise.resolve done_u result)
      in
      let error_handler : H3.Client_connection.error_handler = function
        | `Protocol_error (_e, msg) -> resolve_once (Error (Failure msg))
        | _ -> resolve_once (Error (Failure "direct h3 client error"))
      in
      let t =
        Quic_eio.Client.create
          env
          ~sw:direct_sw
          ~config:(config ())
          (fun ~cid:_ ~start_stream:_ ->
             Quic.Transport.F (fun _ -> { on_error = ignore }))
      in
      Fun.protect
        ~finally:(fun () -> Quic_eio.shutdown t)
        (fun () ->
          let address = resolve_udp_address host port in
          let tls_host =
            try
              let _ = Unix.inet_addr_of_string host in
              "localhost"
            with
            | Failure _ -> host
          in
          Quic_eio.connect t ~address ~host:tls_host (fun ~cid ~start_stream ->
            let conn, stream_handler =
              H3.Client_connection.create ~error_handler ~cid ~start_stream
            in
            Eio.Promise.resolve on_connect_u conn;
            stream_handler);
          let client = Eio.Promise.await on_connect_p in
          let stat = Unix.stat file in
          let total_size = Int64.of_int stat.Unix.st_size in
          let filename = Filename.basename file in
          let stats =
            Transfer_stats.create ~label:"direct send" ~total:total_size ()
          in
          let progress =
            create_progress ~label:"sending  " ~total:total_size
          in
          let response_handler response response_body =
            let status = H3.Status.to_code response.H3.Response.status in
            if 200 <= status && status < 300
            then resolve_once (Ok stats)
            else (
              let rec drain () =
                H3.Body.Reader.schedule_read
                  response_body
                  ~on_eof:(fun () ->
                    resolve_once
                      (Error
                         (Failure
                            (Printf.sprintf
                               "direct upload failed with HTTP status %d"
                               status))))
                  ~on_read:(fun _ ~off:_ ~len:_ -> drain ())
              in
              drain ())
          in
          let headers =
            H3.Headers.of_list
              [ ":authority", tls_host
              ; "content-type", "application/octet-stream"
              ; "content-length", Int64.to_string total_size
              ; "x-wormhole-auth", auth_token session
              ; "x-wormhole-name", hex_of_string filename
              ]
          in
          let request =
            H3.Request.create ~scheme:"https" ~headers `POST "/upload"
          in
          let request_body =
            H3.Client_connection.request
              client
              request
              ~error_handler
              ~response_handler
          in
          let ic = open_in_bin file in
          Fun.protect
            ~finally:(fun () -> close_in_noerr ic)
            (fun () ->
              update_progress progress 0L;
              let buf = Bytes.create upload_chunk_size in
              let rec pump () =
                let rec fill_batch batched_bytes =
                  match input ic buf 0 (Bytes.length buf) with
                  | 0 -> `Eof batched_bytes
                  | n ->
                    H3.Body.Writer.write_string
                      request_body
                      ~off:0
                      ~len:n
                      (Bytes.unsafe_to_string buf);
                    Transfer_stats.on_bytes stats n;
                    update_progress progress stats.bytes;
                    let batched_bytes = batched_bytes + n in
                    if batched_bytes >= flush_batch_bytes
                    then `Flushed batched_bytes
                    else fill_batch batched_bytes
                in
                match fill_batch 0 with
                | `Eof 0 ->
                  finish_progress progress stats.bytes;
                  H3.Body.Writer.close request_body
                | `Eof _ ->
                  finish_progress progress stats.bytes;
                  H3.Body.Writer.flush request_body (fun () ->
                    H3.Body.Writer.close request_body)
                | `Flushed _ ->
                  H3.Body.Writer.flush request_body pump
              in
              pump ();
              Eio.Time.with_timeout_exn
                (Eio.Stdenv.clock env)
                10.0
                (fun () -> Eio.Promise.await done_p))))

  let upload env ~sw ~session ~file candidates =
    let rec loop = function
      | [] -> None
      | candidate :: rest ->
        let result =
          try
            Some (upload_via_candidate env ~sw ~session ~file candidate)
          with
          | _ -> None
        in
        (match result with
        | Some (Ok stats) -> Some stats
        | Some (Error _) | None -> loop rest)
    in
    loop candidates
end

module Relay = struct
  let observed_udp_candidate stream =
    match Quic.Stream.peer_address stream with
    | None -> None
    | Some encoded ->
      (match Quic_eio.Addr.parse encoded with
      | `Udp (host, port) ->
        Some (Unix.string_of_inet_addr (Eio_unix.Net.Ipaddr.to_unix host), port)
      | `Unix _ -> None)

  type peer =
    { stream : Quic.Stream.t
    ; mutable room_name : string option
    ; mutable role : role option
    ; observed_candidate : (string * int) option
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
      (match peer.observed_candidate with
      | Some (host, port) ->
        send
          peer.stream
          (Printf.sprintf "OBSERVED %s %d" (hex_of_string host) port)
      | None -> ());
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
        let peer =
          { stream
          ; room_name = None
          ; role = None
          ; observed_candidate = observed_udp_candidate stream
          }
        in
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
      ; max_datagram_size = Quic.Config.default_max_datagram_size
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

module Relay_h3 = struct
  let alpn = "h3"
  let upload_chunk_size = 16384
  let flush_batch_bytes = 256 * 1024

  let config () =
    let cert = "./certificates/server.pem" in
    let priv_key = "./certificates/server.key" in
    let certificates = `Single (Qx509.private_of_pems ~cert ~priv_key) in
    { Quic.Config.certificates
    ; alpn_protocols = [ alpn ]
    ; transport_parameters = Quic.Config.default_transport_parameters
    ; max_datagram_size = Quic.Config.default_max_datagram_size
    }

  let relay_data_port port = port + 1

  let error_message_of_client_error = function
    | `Protocol_error (_e, msg) -> msg
    | `Malformed_response msg -> "malformed response: " ^ msg
    | `Exn exn -> Printexc.to_string exn
    | `Invalid_response_body_length _ -> "invalid response body length"

  type transfer =
    { mutable upload_path : string option
    ; mutable filename_hex : string option
    ; mutable content_length : string option
    ; mutable content_type : string option
    ; mutable downloader : H3.Reqd.t option
    ; mutable upload_complete : bool
    ; mutable download_started : bool
    }

  type state = { transfers : (string, transfer) Hashtbl.t }

  let create_state () = { transfers = Hashtbl.create 16 }

  let get_transfer t transfer_id =
    match Hashtbl.find_opt t.transfers transfer_id with
    | Some x -> x
    | None ->
      let x =
        { upload_path = None
        ; filename_hex = None
        ; content_length = None
        ; content_type = None
        ; downloader = None
        ; upload_complete = false
        ; download_started = false
        }
      in
      Hashtbl.add t.transfers transfer_id x;
      x

  let maybe_cleanup t transfer_id transfer =
    if transfer.upload_complete && transfer.downloader = None
    then (
      Option.iter
        (fun path -> try Unix.unlink path with _ -> ())
        transfer.upload_path;
      Hashtbl.remove t.transfers transfer_id)

  let transfer_headers transfer =
    let headers =
      ref
        [ "content-type"
        , Option.value transfer.content_type ~default:"application/octet-stream"
        ]
    in
    (match transfer.content_length with
    | Some v -> headers := ("content-length", v) :: !headers
    | None -> ());
    (match transfer.filename_hex with
    | Some v -> headers := ("x-wormhole-name", v) :: !headers
    | None -> ());
    H3.Headers.of_list (List.rev !headers)

  let start_download_if_ready t transfer_id transfer =
    match
      transfer.download_started,
      transfer.upload_complete,
      transfer.upload_path,
      transfer.downloader
    with
    | false, true, Some upload_path, Some download_reqd ->
      transfer.download_started <- true;
      let response =
        H3.Response.create ~headers:(transfer_headers transfer) `OK
      in
      let response_body = H3.Reqd.respond_with_streaming download_reqd response in
      let ic = open_in_bin upload_path in
      let buf = Bytes.create upload_chunk_size in
      let finalize () =
        close_in_noerr ic;
        H3.Body.Writer.close response_body;
        transfer.downloader <- None;
        maybe_cleanup t transfer_id transfer
      in
      let rec pump () =
        let rec fill_batch batched_bytes =
          match input ic buf 0 (Bytes.length buf) with
          | 0 -> `Eof batched_bytes
          | n ->
            H3.Body.Writer.write_string
              response_body
              ~off:0
              ~len:n
              (Bytes.unsafe_to_string buf);
            let batched_bytes = batched_bytes + n in
            if batched_bytes >= flush_batch_bytes
            then `Flushed batched_bytes
            else fill_batch batched_bytes
          | exception exn ->
            finalize ();
            raise exn
        in
        match fill_batch 0 with
        | `Eof 0 -> finalize ()
        | `Eof _ -> H3.Body.Writer.flush response_body finalize
        | `Flushed _ -> H3.Body.Writer.flush response_body pump
      in
      pump ()
    | _ -> ()

  let request_handler t reqd =
    let request = H3.Reqd.request reqd in
    let parts =
      request.H3.Request.target
      |> String.split_on_char '/'
      |> List.filter (fun x -> x <> "")
    in
    match request.H3.Request.meth, parts with
    | `POST, [ "relay"; "upload"; transfer_id ] ->
      let transfer = get_transfer t transfer_id in
      (match transfer.upload_path with
      | Some _ ->
        H3.Reqd.respond_with_string
          reqd
          (H3.Response.create `Conflict)
          "upload already exists"
      | None ->
        let temp_path =
          Filename.temp_file ("wormhole-relay-" ^ transfer_id ^ "-") ".upload"
        in
        let oc = open_out_bin temp_path in
        let request_body = H3.Reqd.request_body reqd in
        let finished = ref false in
        let finalize ok =
          if not !finished
          then (
            finished := true;
            close_out_noerr oc;
            if ok
            then (
              transfer.upload_complete <- true;
              H3.Reqd.respond_with_string reqd (H3.Response.create `OK) "ok";
              start_download_if_ready t transfer_id transfer)
            else (
              (try Unix.unlink temp_path with _ -> ());
              transfer.upload_path <- None;
              transfer.filename_hex <- None;
              transfer.content_length <- None;
              transfer.content_type <- None;
              H3.Reqd.respond_with_string
                reqd
                (H3.Response.create `Internal_server_error)
                "upload failed";
              maybe_cleanup t transfer_id transfer))
        in
        transfer.upload_path <- Some temp_path;
        transfer.filename_hex <-
          H3.Headers.get request.H3.Request.headers "x-wormhole-name";
        transfer.content_length <-
          H3.Headers.get request.H3.Request.headers "content-length";
        transfer.content_type <-
          H3.Headers.get request.H3.Request.headers "content-type";
        transfer.upload_complete <- false;
        transfer.download_started <- false;
        let rec read_body () =
          H3.Body.Reader.schedule_read
            request_body
            ~on_eof:(fun () -> finalize true)
            ~on_read:(fun bs ~off ~len ->
              try
                output_string oc (Bigstringaf.substring bs ~off ~len);
                read_body ()
              with
              | _ ->
                finalize false)
        in
        read_body ())
    | `GET, [ "relay"; "download"; transfer_id ] ->
      let transfer = get_transfer t transfer_id in
      (match transfer.downloader with
      | Some _ ->
        H3.Reqd.respond_with_string
          reqd
          (H3.Response.create `Conflict)
          "download already exists"
      | None ->
        transfer.downloader <- Some reqd;
        start_download_if_ready t transfer_id transfer)
    | _ ->
      H3.Reqd.respond_with_string
        reqd
        (H3.Response.create `Not_found)
        "not found"

  let connection_handler t = H3.Server_connection.create (request_handler t)

  let run env ~sw ~port =
    let data_port = relay_data_port port in
    let state = create_state () in
    Format.printf "relay h3 data plane listening on udp port %d@." data_port;
    Quic_eio.Server.establish_server
      env
      ~sw
      ~config:(config ())
      (`Udp (Eio.Net.Ipaddr.V4.any, data_port))
      (connection_handler state)

  let connect_h3 env ~sw ~host ~port =
    let on_connect_p, on_connect_u = Eio.Promise.create () in
    let t =
      Quic_eio.Client.create
        env
        ~sw
        ~config:(config ())
        (fun ~cid:_ ~start_stream:_ ->
           Quic.Transport.F (fun _ -> { on_error = ignore }))
    in
    let address = Direct.resolve_udp_address host port in
    let tls_host =
      try
        let _ = Unix.inet_addr_of_string host in
        "localhost"
      with
      | Failure _ -> host
    in
    Quic_eio.connect t ~address ~host:tls_host (fun ~cid ~start_stream ->
      let conn, stream_handler =
        H3.Client_connection.create
          ~error_handler:(function
            | `Protocol_error (_e, msg) -> failwith msg
            | _ -> failwith "relay h3 client error")
          ~cid
          ~start_stream
      in
      Eio.Promise.resolve on_connect_u (conn, tls_host);
      stream_handler);
    let conn, tls_host = Eio.Promise.await on_connect_p in
    t, conn, tls_host

  let upload env ~sw ~host ~port ~transfer_id ~file =
    let t, client, tls_host = connect_h3 env ~sw ~host ~port:(relay_data_port port) in
    Fun.protect
      ~finally:(fun () -> Quic_eio.shutdown t)
      (fun () ->
        let stat = Unix.stat file in
        let total_size = Int64.of_int stat.Unix.st_size in
        let filename = Filename.basename file in
        let stats = Transfer_stats.create ~label:"relay send" ~total:total_size () in
        let progress = create_progress ~label:"sending  " ~total:total_size in
        let done_p, done_u = Eio.Promise.create () in
        let response_handler response response_body =
          let status = H3.Status.to_code response.H3.Response.status in
          let rec drain () =
            H3.Body.Reader.schedule_read
              response_body
              ~on_eof:(fun () ->
                if 200 <= status && status < 300
                then Eio.Promise.resolve done_u ()
                else failwith (Printf.sprintf "relay upload failed with HTTP status %d" status))
              ~on_read:(fun _ ~off:_ ~len:_ -> drain ())
          in
          drain ()
        in
        let headers =
          H3.Headers.of_list
            [ ":authority", tls_host
            ; "content-type", "application/octet-stream"
            ; "content-length", Int64.to_string total_size
            ; "x-wormhole-name", hex_of_string filename
            ]
        in
        let request =
          H3.Request.create
            ~scheme:"https"
            ~headers
            `POST
            ("/relay/upload/" ^ transfer_id)
        in
        let request_body =
          H3.Client_connection.request
            client
            request
            ~error_handler:(fun error ->
              failwith (error_message_of_client_error error))
            ~response_handler
        in
        let ic = open_in_bin file in
        Fun.protect
          ~finally:(fun () -> close_in_noerr ic)
          (fun () ->
            update_progress progress 0L;
            let buf = Bytes.create Direct.upload_chunk_size in
            let rec pump () =
              let rec fill_batch batched_bytes =
                match input ic buf 0 (Bytes.length buf) with
                | 0 -> `Eof batched_bytes
                | n ->
                  H3.Body.Writer.write_string
                    request_body
                    ~off:0
                    ~len:n
                    (Bytes.unsafe_to_string buf);
                  Transfer_stats.on_bytes stats n;
                  update_progress progress stats.bytes;
                  let batched_bytes = batched_bytes + n in
                  if batched_bytes >= Direct.flush_batch_bytes
                  then `Flushed batched_bytes
                  else fill_batch batched_bytes
              in
              match fill_batch 0 with
              | `Eof 0 ->
                finish_progress progress stats.bytes;
                H3.Body.Writer.close request_body
              | `Eof _ ->
                finish_progress progress stats.bytes;
                H3.Body.Writer.flush request_body (fun () ->
                  H3.Body.Writer.close request_body)
              | `Flushed _ ->
                H3.Body.Writer.flush request_body pump
            in
            pump ();
            Eio.Promise.await done_p;
            stats)
      )

  let download env ~sw ~host ~port ~transfer_id ~output =
    let t, client, tls_host = connect_h3 env ~sw ~host ~port:(relay_data_port port) in
    Fun.protect
      ~finally:(fun () -> Quic_eio.shutdown t)
      (fun () ->
        let done_p, done_u = Eio.Promise.create () in
        let stats_ref = ref None in
        let response_handler response response_body =
          let status = H3.Status.to_code response.H3.Response.status in
          if status < 200 || status >= 300
          then failwith (Printf.sprintf "relay download failed with HTTP status %d" status)
          else
            let expected_len =
              match H3.Response.body_length response with
              | `Fixed len -> Some len
              | `Unknown | `Error _ -> None
            in
            let sender_name =
              match H3.Headers.get response.H3.Response.headers "x-wormhole-name" with
              | Some name_hex -> (try string_of_hex name_hex with _ -> "download.bin")
              | None -> "download.bin"
            in
            let out_path = Option.value output ~default:("recv-" ^ sender_name) in
            let stats = Transfer_stats.create ~label:"relay recv" ?total:expected_len () in
            stats_ref := Some stats;
            let progress =
              Option.map (fun total -> create_progress ~label:"receiving" ~total) expected_len
            in
            Printf.printf
              "receiving %s (%s) into %s\n%!"
              sender_name
              (match expected_len with
              | Some len -> Printf.sprintf "%Ld bytes" len
              | None -> "unknown size")
              out_path;
            Option.iter (fun p -> update_progress p 0L) progress;
            let oc = open_out_bin out_path in
            let rec read_body () =
              H3.Body.Reader.schedule_read
                response_body
                ~on_eof:(fun () ->
                  Option.iter (fun p -> finish_progress p stats.bytes) progress;
                  close_out_noerr oc;
                  Eio.Promise.resolve done_u (stats, out_path))
                ~on_read:(fun bs ~off ~len ->
                  output_string oc (Bigstringaf.substring bs ~off ~len);
                  Transfer_stats.on_bytes stats len;
                  Option.iter (fun p -> update_progress p stats.bytes) progress;
                  read_body ())
            in
            read_body ()
        in
        let headers = H3.Headers.of_list [ ":authority", tls_host ] in
        let request =
          H3.Request.create
            ~scheme:"https"
            ~headers
            `GET
            ("/relay/download/" ^ transfer_id)
        in
        let request_body =
          H3.Client_connection.request
            client
            request
            ~error_handler:(fun error ->
              failwith (error_message_of_client_error error))
            ~response_handler
        in
        H3.Body.Writer.close request_body;
        Eio.Promise.await done_p)
end

let run_relay env ~sw ~port =
  Eio.Fiber.both
    (fun () -> Relay.run env ~sw ~port)
    (fun () -> Relay_h3.run env ~sw ~port)

module Client = struct
  type opts =
    { host : string
    ; port : int
    ; code : string
    ; password : string
    }

  type direct_offer =
    | No_direct
    | Direct_candidates of (string * int) list

  type rendezvous =
    { observed_host : string option
    }

  type transfer_mode =
    | Use_direct
    | Use_relay_h3 of string

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

  let relay_config () =
    let cert = "./certificates/server.pem" in
    let priv_key = "./certificates/server.key" in
    let certificates = `Single (Qx509.private_of_pems ~cert ~priv_key) in
    { Quic.Config.certificates
    ; alpn_protocols = [ "wormhole-relay-v1" ]
    ; transport_parameters = Quic.Config.default_transport_parameters
    ; max_datagram_size = Quic.Config.default_max_datagram_size
    }

  let connect_with_config env ~sw ~config ~(opts : opts) =
    let on_connect_p, on_connect_u = Eio.Promise.create () in
    let t =
      Quic_eio.Client.create
        env
        ~sw
        ~config
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

  let connect env ~sw ~(opts : opts) =
    connect_with_config env ~sw ~config:(relay_config ()) ~opts

  let wait_for_line_or_fail ch =
    match Line_channel.read_line ch with
    | Some line -> line
    | None -> failwith "relay stream closed"

  let wait_for_ready ch =
    let rec loop observed_host =
      match split_words (wait_for_line_or_fail ch) with
      | [ "WAITING" ] -> loop observed_host
      | [ "JOINED" ] -> loop observed_host
      | [ "OBSERVED"; host_hex; port_s ] ->
        let _ = port_s in
        loop (Some (string_of_hex host_hex))
      | [ "READY"; _ ] ->
        { observed_host }
      | [ "PEER_LEFT" ] -> failwith "peer disconnected before setup completed"
      | "ERROR" :: msg -> failwith ("ERROR " ^ String.concat " " msg)
      | _ -> loop observed_host
    in
    loop None

  let rec wait_for_direct_offer ch acc =
    match split_words (wait_for_line_or_fail ch) with
    | [ "NO-DIRECT" ] -> No_direct
    | [ "DIRECT"; host_hex; port_s ] ->
      wait_for_direct_offer ch ((string_of_hex host_hex, parse_int port_s) :: acc)
    | [ "DIRECT-DONE" ] -> Direct_candidates (List.rev acc)
    | [ "PEER_LEFT" ] -> failwith "peer disconnected before direct offer"
    | line when line = [ "WAITING" ] || line = [ "JOINED" ] -> wait_for_direct_offer ch acc
    | _ -> wait_for_direct_offer ch acc

  let send_direct_candidates ch candidates =
    match candidates with
    | [] -> Line_channel.write_line ch "NO-DIRECT"
    | _ ->
      List.iter
        (fun (host, port) ->
           Line_channel.write_line
             ch
             (Printf.sprintf "DIRECT %s %d" (hex_of_string host) port))
        candidates;
      Line_channel.write_line ch "DIRECT-DONE"

  let wait_for_mode_or_fail ch =
    let rec loop () =
      match split_words (wait_for_line_or_fail ch) with
      | [ "USE-DIRECT" ] -> Use_direct
      | [ "USE-RELAY-H3"; transfer_id ] -> Use_relay_h3 transfer_id
      | [ "PEER_LEFT" ] -> failwith "peer disconnected before transfer mode selected"
      | _ -> loop ()
    in
    loop ()

  let direct_connect env ~sw candidates =
    let rec try_candidates = function
      | [] -> None
      | (host, port) :: rest ->
        let opts = { host; port; code = ""; password = "" } in
        let attempt () =
          let t, stream =
            connect_with_config env ~sw ~config:(Direct.config ()) ~opts
          in
          let ch = Line_channel.of_stream stream in
          Some (t, ch)
        in
        let result =
          try
            Eio.Time.with_timeout_exn (Eio.Stdenv.clock env) 2.0 attempt
          with
          | _ -> None
        in
        (match result with
        | Some _ as ok -> ok
        | None -> try_candidates rest)
    in
    try_candidates candidates

  let send_transfer ~yield ~ch ~session ~file =
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
    let stats = Transfer_stats.create ~label:"send" ~total:total_size () in
    let ic = open_in_bin file in
    Fun.protect
      ~finally:(fun () -> close_in_noerr ic)
      (fun () ->
         let digest = ref Digestif.SHA256.empty in
         let buf = Bytes.create data_chunk_size in
         let progress =
           create_progress ~label:"sending  " ~total:total_size
         in
         update_progress progress 0L;
         let acked_seq = ref (-1L) in
         let rec wait_for_ack target_seq =
           if Int64.compare !acked_seq target_seq >= 0
           then ()
           else
             match split_words (wait_for_line_or_fail ch) with
             | [ "ACK"; seq_s ] ->
               let seq = parse_int64 seq_s in
               if Int64.compare seq !acked_seq > 0 then acked_seq := seq;
               wait_for_ack target_seq
             | [ "RECV-OK" ] ->
               acked_seq := target_seq
             | line when String.starts_with ~prefix:"RECV-BAD" (String.concat " " line) ->
               failwith ("receiver reported integrity failure: " ^ String.concat " " line)
             | [ "PEER_LEFT" ] ->
               failwith "peer disconnected before final ack"
             | _ -> wait_for_ack target_seq
         in
         let rec loop chunks_since_yield seq sent_bytes =
           let n = input ic buf 0 (Bytes.length buf) in
           if n = 0
           then (
             finish_progress progress sent_bytes;
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
             wait_ack ();
             stats)
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
             Transfer_stats.on_bytes stats n;
             let sent = Int64.add sent_bytes (Int64.of_int n) in
             update_progress progress sent;
             if
               Int64.compare
                 (Int64.sub (Int64.succ seq) !acked_seq)
                 max_inflight_chunks
               > 0
             then wait_for_ack (Int64.sub (Int64.succ seq) (Int64.div max_inflight_chunks 2L));
             let chunks_since_yield = chunks_since_yield + 1 in
             if chunks_since_yield >= 256 then yield ();
             loop
               (if chunks_since_yield >= 256 then 0 else chunks_since_yield)
               (Int64.succ seq)
               sent
         in
         loop 0 0L 0L)

  let recv_transfer ~ch ~session ~output =
    let rec wait_meta () =
      match split_words (wait_for_line_or_fail ch) with
      | [ "META"; name_hex; size_s ] ->
        string_of_hex name_hex, parse_int64 size_s
      | [ "PEER_LEFT" ] -> failwith "peer disconnected before metadata"
      | _ -> wait_meta ()
    in
    let sender_name, expected_size = wait_meta () in
    let out_path = Option.value output ~default:("recv-" ^ sender_name) in
    let stats =
      Transfer_stats.create ~label:"recv" ~total:expected_size ()
    in
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
         let progress =
           create_progress ~label:"receiving" ~total:expected_size
         in
         update_progress progress 0L;
         let rec loop next_seq written =
           match split_words (wait_for_line_or_fail ch) with
           | [ "DATA"; seq_s; ciphertext_hex; tag_hex ] ->
             let seq = parse_int64 seq_s in
             if seq < next_seq
             then loop next_seq written
             else if seq > next_seq
             then
               failwith
                 (Printf.sprintf
                    "out-of-order DATA chunk: expected=%Ld got=%Ld"
                    next_seq
                    seq)
             else
               let ciphertext = string_of_hex ciphertext_hex in
               let tag = string_of_hex tag_hex in
               let plain =
                 match Pake.decrypt_chunk session ~seq ~ciphertext ~tag with
                 | Ok x -> x
                 | Error e -> failwith ("decrypt/auth failure: " ^ e)
               in
               output_string oc plain;
               digest := Digestif.SHA256.feed_string !digest plain;
               let n = String.length plain in
               Transfer_stats.on_bytes stats n;
               let written = Int64.add written (Int64.of_int n) in
               update_progress progress written;
               if Int64.rem (Int64.succ seq) ack_interval_chunks = 0L
               then Line_channel.write_line ch (Printf.sprintf "ACK %Ld" seq);
               loop (Int64.succ next_seq) written
           | [ "DONE"; total_s; digest_hex ] ->
             let total = parse_int64 total_s in
             let got_digest = Digestif.SHA256.(to_hex (get !digest)) in
             if
               total <> written || not (String.equal digest_hex got_digest)
             then (
               finish_progress progress written;
               Line_channel.write_line
                 ch
                 (Printf.sprintf
                    "RECV-BAD total=%Ld digest=%s"
                    total
                    got_digest);
               failwith "integrity check failed")
             else (
               finish_progress progress written;
               Line_channel.write_line ch "RECV-OK";
               stats)
           | [ "PEER_LEFT" ] ->
             failwith "peer disconnected during transfer"
           | _ -> loop next_seq written
         in
         loop 0L 0L)

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

  let do_send env ~sw ~opts ~file ~direct =
    let t, stream = connect env ~sw ~opts in
    let transfer_stats : Transfer_stats.t option ref = ref None in
    let report_stats status =
      match !transfer_stats with
      | None -> ()
      | Some s -> Transfer_stats.report s ~status
    in
    Fun.protect
      ~finally:(fun () ->
        Quic.Stream.close_writer stream;
        Quic_eio.shutdown t)
      (fun () ->
         try
           let ch = Line_channel.of_stream stream in
           Line_channel.write_line
             ch
             (Printf.sprintf "JOIN %s %s" opts.code (role_to_string Sender));
           let _rendezvous = wait_for_ready ch in
           let session = perform_pake ~opts ~role:Sender ch in
           if direct
           then (
             match wait_for_direct_offer ch [] with
             | No_direct -> ()
             | Direct_candidates candidates ->
               (match Direct.upload env ~sw ~session ~file candidates with
               | Some stats ->
                 transfer_stats := Some stats;
                 Format.printf
                   "using direct peer-to-peer transfer (%d candidates)@."
                   (List.length candidates);
                 Line_channel.write_line ch "USE-DIRECT"
               | None -> ()));
           if !transfer_stats = None
           then (
             let transfer_id = hex_of_string (random_bytes 16) in
             Line_channel.write_line
               ch
               (Printf.sprintf "USE-RELAY-H3 %s" transfer_id);
             let stats =
               Relay_h3.upload env ~sw ~host:opts.host ~port:opts.port ~transfer_id ~file
             in
             transfer_stats := Some stats);
           report_stats "completed"
         with
         | Sys.Break ->
           report_stats "interrupted";
           raise Sys.Break
         | exn ->
           report_stats "failed";
           raise exn)

  let do_recv env ~sw ~opts ~output ~direct_port ~direct_host =
    let t, stream = connect env ~sw ~opts in
    let transfer_stats : Transfer_stats.t option ref = ref None in
    let report_stats status =
      match !transfer_stats with
      | None -> ()
      | Some s -> Transfer_stats.report s ~status
    in
    Fun.protect
      ~finally:(fun () ->
        Quic.Stream.close_writer stream;
        Quic_eio.shutdown t)
      (fun () ->
         try
           let ch = Line_channel.of_stream stream in
           Line_channel.write_line
             ch
             (Printf.sprintf "JOIN %s %s" opts.code (role_to_string Receiver));
           let rendezvous = wait_for_ready ch in
           let session = perform_pake ~opts ~role:Receiver ch in
           let direct_listener =
             Option.map
               (fun port ->
                  Direct.start_receiver
                    env
                    ~sw
                    ~port
                    ~advertise_host:direct_host
                    ~session
                    ~output)
               direct_port
           in
           (match direct_listener with
            | None -> Line_channel.write_line ch "NO-DIRECT"
            | Some listener ->
             Eio.Time.sleep (Eio.Stdenv.clock env) 0.1;
             let candidates =
               List.map (fun host -> host, listener.port) listener.hosts
             in
             let candidates =
               match rendezvous.observed_host with
               | None -> candidates
               | Some host ->
                 let observed = host, listener.port in
                 observed
                 :: List.filter (fun candidate -> candidate <> observed) candidates
             in
             Format.printf
               "awaiting direct peer connection on udp port %d@."
               listener.port;
             send_direct_candidates ch candidates);
           Printf.printf "waiting for sender to start transfer...\n%!";
           let recv_ch =
             match direct_listener with
             | None ->
               (match wait_for_mode_or_fail ch with
               | Use_relay_h3 transfer_id ->
                 let stats, _out_path =
                   Relay_h3.download
                     env
                     ~sw
                     ~host:opts.host
                     ~port:opts.port
                     ~transfer_id
                     ~output
                 in
                 transfer_stats := Some stats;
                 None
               | Use_direct ->
                 failwith "sender selected direct mode but receiver has no direct listener")
             | Some listener ->
               (match
                  Eio.Fiber.first
                    (fun () -> `Mode (wait_for_mode_or_fail ch))
                    (fun () ->
                      let stats, out_path = Direct.await_completion listener in
                      `Direct_done (stats, out_path))
                with
                | `Direct_done (stats, out_path) ->
                  transfer_stats := Some stats;
                  Format.printf "received direct upload into %s@." out_path;
                  None
                | `Mode (Use_relay_h3 transfer_id) ->
                  let stats, _out_path =
                    Relay_h3.download
                      env
                      ~sw
                      ~host:opts.host
                      ~port:opts.port
                      ~transfer_id
                      ~output
                  in
                  transfer_stats := Some stats;
                  None
                | `Mode Use_direct ->
                  let stats, out_path = Direct.await_completion listener in
                  transfer_stats := Some stats;
                  Format.printf "received direct upload into %s@." out_path;
                  None)
           in
           (match recv_ch with
           | Some recv_ch ->
             let stats = recv_transfer ~ch:recv_ch ~session ~output in
             transfer_stats := Some stats
           | None -> ());
           Eio.Time.sleep (Eio.Stdenv.clock env) 0.1;
           (match !transfer_stats with
           | Some stats ->
             Format.printf "received %Ld bytes successfully@." stats.bytes
           | None -> ());
           report_stats "completed"
         with
         | Sys.Break ->
           report_stats "interrupted";
           raise Sys.Break
         | exn ->
           report_stats "failed";
           raise exn)
end

type relay_opts = { relay_port : int }

type send_opts =
  { host : string
  ; port : int
  ; code : string option
  ; password : string option
  ; file : string option
  ; direct : bool
  }

type recv_opts =
  { host : string
  ; port : int
  ; code : string option
  ; password : string option
  ; output : string option
  ; direct_port : int option
  ; direct_host : string option
  }

let default_send_opts =
  { host = "localhost"
  ; port = 4443
  ; code = None
  ; password = None
  ; file = None
  ; direct = false
  }

let default_recv_opts =
  { host = "localhost"
  ; port = 4443
  ; code = None
  ; password = None
  ; output = None
  ; direct_port = None
  ; direct_host = None
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
    ; "-direct", Arg.Unit (fun () -> opts := { !opts with direct = true }), " Attempt direct peer-to-peer transfer first"
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
    ; ( "-direct-port"
      , Arg.Int (fun v -> set (fun o x -> { o with direct_port = Some x }) v)
      , " Listen on this UDP port for direct peer-to-peer transfer" )
    ; ( "-direct-host"
      , Arg.String (fun v -> set (fun o x -> { o with direct_host = Some x }) v)
      , " Additional host/IP candidate to advertise for direct transfer" )
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
  Sys.catch_break true;
  let run () =
    if Array.length Sys.argv < 2 then usage ();
    match Sys.argv.(1) with
    | "relay" ->
      let relay_opts = parse_relay_args Sys.argv in
      Eio_main.run (fun env ->
        Eio.Switch.run (fun sw -> run_relay env ~sw ~port:relay_opts.relay_port))
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
        Eio.Switch.run (fun sw ->
          Client.do_send env ~sw ~opts ~file ~direct:send_opts.direct))
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
          Client.do_recv
            env
            ~sw
            ~opts
            ~output:recv_opts.output
            ~direct_port:recv_opts.direct_port
            ~direct_host:recv_opts.direct_host))
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
  | Sys.Break ->
    prerr_endline "interrupted";
    exit 130
