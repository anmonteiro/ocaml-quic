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

let wormhole_max_datagram_size =
  match Sys.getenv_opt "WORMHOLE_MAX_DATAGRAM_SIZE" with
  | Some value ->
    (match int_of_string_opt value with
    | Some value when value > 0 -> value
    | Some _ -> failwith "WORMHOLE_MAX_DATAGRAM_SIZE must be > 0"
    | None -> failwith ("invalid WORMHOLE_MAX_DATAGRAM_SIZE: " ^ value))
  | None -> 1452

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

module Flush_profile = struct
  type t =
    { label : string
    ; enabled : bool
    ; started_at : float
    ; mutable flushes : int
    ; mutable bytes : int64
    ; mutable max_bytes : int
    ; mutable wait_s : float
    ; mutable max_wait_s : float
    }

  let enabled () =
    match Sys.getenv_opt "WORMHOLE_PROFILE_FLUSH" with
    | Some ("1" | "true" | "TRUE" | "yes" | "YES") -> true
    | _ -> false

  let now_s () = Unix.gettimeofday ()

  let create ~label =
    { label
    ; enabled = enabled ()
    ; started_at = now_s ()
    ; flushes = 0
    ; bytes = 0L
    ; max_bytes = 0
    ; wait_s = 0.
    ; max_wait_s = 0.
    }

  let flush t ~bytes do_flush k =
    if (not t.enabled) || bytes <= 0
    then do_flush k
    else (
      let started = now_s () in
      t.flushes <- t.flushes + 1;
      t.bytes <- Int64.add t.bytes (Int64.of_int bytes);
      t.max_bytes <- max t.max_bytes bytes;
      do_flush (fun () ->
        let waited = now_s () -. started in
        t.wait_s <- t.wait_s +. waited;
        t.max_wait_s <- max t.max_wait_s waited;
        k ()))

  let report t =
    if t.enabled
    then (
      let elapsed_s = max 1e-6 (now_s () -. t.started_at) in
      let avg_bytes =
        if t.flushes = 0 then 0. else Int64.to_float t.bytes /. float_of_int t.flushes
      in
      Printf.printf
        "%s flush profile: flushes=%d, bytes=%Ld, avg-bytes=%.0f, max-bytes=%d, \
         wait=%.3fs, max-wait=%.3fs, wait-share=%.1f%%\n%!"
        t.label
        t.flushes
        t.bytes
        avg_bytes
        t.max_bytes
        t.wait_s
        t.max_wait_s
        ((t.wait_s /. elapsed_s) *. 100.))
end

type progress =
  { label : string
  ; total : int64
  ; width : int
  ; mutable last_percent : int
  ; mutable last_rendered_at : float
  }

let create_progress ~label ~total =
  { label; total; width = 30; last_percent = -1; last_rendered_at = 0. }

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
  let now = Unix.gettimeofday () in
  if current = t.total || ((percent <> t.last_percent) && now -. t.last_rendered_at >= 0.2)
  then (
    t.last_percent <- percent;
    t.last_rendered_at <- now;
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

let int32_to_be n =
  let b = Bytes.create 4 in
  Bytes.set_int32_be b 0 n;
  Bytes.unsafe_to_string b

let be_to_int32 s off = Bytes.get_int32_be (Bytes.unsafe_of_string s) off

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

let sha256_hex_file path =
  let ic = open_in_bin path in
  Fun.protect
    ~finally:(fun () -> close_in_noerr ic)
    (fun () ->
      let buf = Bytes.create (256 * 1024) in
      let digest = ref Digestif.SHA256.empty in
      let rec loop () =
        match input ic buf 0 (Bytes.length buf) with
        | 0 -> Digestif.SHA256.(to_hex (get !digest))
        | n ->
          digest := Digestif.SHA256.feed_bytes !digest buf ~off:0 ~len:n;
          loop ()
      in
      loop ())

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

module Binary_transfer = struct
  let chunk_size = 256 * 1024
  let flush_batch_bytes =
    match Sys.getenv_opt "WORMHOLE_FLUSH_BATCH_BYTES" with
    | Some value ->
      (match int_of_string_opt value with
      | Some value when value > 0 -> value
      | Some _ -> failwith "WORMHOLE_FLUSH_BATCH_BYTES must be > 0"
      | None -> failwith ("invalid WORMHOLE_FLUSH_BATCH_BYTES: " ^ value))
    | None -> 1024 * 1024
  let sender_max_inflight_flushes =
    match Sys.getenv_opt "WORMHOLE_SENDER_MAX_INFLIGHT_FLUSHES" with
    | Some value ->
      (match int_of_string_opt value with
      | Some value when value > 0 -> value
      | Some _ -> failwith "WORMHOLE_SENDER_MAX_INFLIGHT_FLUSHES must be > 0"
      | None ->
        failwith ("invalid WORMHOLE_SENDER_MAX_INFLIGHT_FLUSHES: " ^ value))
    | None -> 4

  let send_file ~yield ~stream ~file =
    let stat = Unix.stat file in
    let total_size = Int64.of_int stat.Unix.st_size in
    let stats = Transfer_stats.create ~label:"relay send" ~total:total_size () in
    let flush_profile = Flush_profile.create ~label:"relay send" in
    let progress = create_progress ~label:"sending  " ~total:total_size in
    let ic = open_in_bin file in
    let done_p, done_u = Eio.Promise.create () in
    let digest = ref Digestif.SHA256.empty in
    Fun.protect
      ~finally:(fun () -> close_in_noerr ic)
      (fun () ->
        let buf = Bytes.create chunk_size in
        let scratch = Bigstringaf.create chunk_size in
        let chunks_since_yield = ref 0 in
        let batched_bytes = ref 0 in
        let pending_flushes = ref 0 in
        let eof = ref false in
        let finished = ref false in
        let pumping = ref false in
        update_progress progress 0L;
        let rec maybe_finish () =
          if !eof && !pending_flushes = 0 && !batched_bytes = 0 && not !finished
          then (
            finished := true;
            Quic.Stream.close_writer stream;
            Eio.Promise.resolve done_u (Digestif.SHA256.(to_hex (get !digest)), stats))
        and flush_current_batch () =
          if !batched_bytes > 0
          then (
            let bytes = !batched_bytes in
            batched_bytes := 0;
            incr pending_flushes;
            Flush_profile.flush
              flush_profile
              ~bytes
              (Quic.Stream.flush stream)
              (fun () ->
                 decr pending_flushes;
                 if !eof
                 then maybe_finish ()
                 else if not !pumping
                 then resume_pump ()))
        and pump () =
          if !eof || !pending_flushes >= sender_max_inflight_flushes
          then maybe_finish ()
          else
            match input ic buf 0 (Bytes.length buf) with
            | 0 ->
              eof := true;
              finish_progress progress stats.bytes;
              flush_current_batch ();
              maybe_finish ()
            | n ->
              digest := Digestif.SHA256.feed_bytes !digest buf ~off:0 ~len:n;
              Bigstringaf.blit_from_bytes buf ~src_off:0 scratch ~dst_off:0 ~len:n;
              Quic.Stream.write_bigstring_copy stream ~off:0 ~len:n scratch;
              Transfer_stats.on_bytes stats n;
              update_progress progress stats.bytes;
              batched_bytes := !batched_bytes + n;
              incr chunks_since_yield;
              if !chunks_since_yield >= 64
              then (
                yield ();
                chunks_since_yield := 0);
              if !batched_bytes >= flush_batch_bytes then flush_current_batch ();
              pump ()
        and resume_pump () =
          if (not !finished) && not !pumping
          then (
            pumping := true;
            Fun.protect ~finally:(fun () -> pumping := false) pump)
        in
        resume_pump ();
        let result = Eio.Promise.await done_p in
        Flush_profile.report flush_profile;
        result)

  let recv_file ~stream ~output ~expected_name ~expected_size =
    let out_path = Option.value output ~default:("recv-" ^ expected_name) in
    let stats = Transfer_stats.create ~label:"relay recv" ~total:expected_size () in
    let progress = create_progress ~label:"receiving" ~total:expected_size in
    let oc = open_out_bin out_path in
    let done_p, done_u = Eio.Promise.create () in
    let digest = ref Digestif.SHA256.empty in
    let finished = ref false in
    let finalize result =
      if not !finished
      then (
        finished := true;
        close_out_noerr oc;
        Eio.Promise.resolve done_u result)
    in
    let scratch = ref (Bytes.create chunk_size) in
    let ensure_scratch len =
      if len > Bytes.length !scratch
      then scratch := Bytes.create (max len (2 * Bytes.length !scratch))
    in
    Printf.printf "receiving %s (%Ld bytes) into %s\n%!" expected_name expected_size out_path;
    update_progress progress 0L;
    let rec read_stream () =
      Quic.Stream.schedule_read
        stream
        ~on_eof:(fun () ->
          try
            if stats.bytes <> expected_size
            then
              failwith
                (Printf.sprintf
                   "size mismatch: expected=%Ld got=%Ld"
                   expected_size
                   stats.bytes);
            finish_progress progress stats.bytes;
            finalize (Ok (Digestif.SHA256.(to_hex (get !digest)), stats, out_path))
          with
          | exn -> finalize (Error exn))
        ~on_read:(fun bs ~off ~len ->
          try
            ensure_scratch len;
            Bigstringaf.blit_to_bytes bs ~src_off:off !scratch ~dst_off:0 ~len;
            Stdlib.output oc !scratch 0 len;
            digest := Digestif.SHA256.feed_bytes !digest !scratch ~off:0 ~len;
            Transfer_stats.on_bytes stats len;
            update_progress progress stats.bytes;
            read_stream ()
          with
          | exn -> finalize (Error exn))
    in
    read_stream ();
    match Eio.Promise.await done_p with
    | Ok result -> result
    | Error exn -> raise exn
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
    { start_stream : Quic.Transport.start_stream
    ; mutable control_stream : Quic.Stream.t option
    ; mutable room_name : string option
    ; mutable role : role option
    ; mutable observed_candidate : (string * int) option
    ; mutable pending_outgoing_transfer : string option
    }
  and transfer =
    { transfer_id : string
    ; sender : peer
    ; receiver : peer
    ; mutable sender_stream_bound : bool
    }

  type room =
    { mutable sender : peer option
    ; mutable receiver : peer option
    ; transfers : (string, transfer) Hashtbl.t
    }

  type state = { rooms : (string, room) Hashtbl.t }

  let create_state () = { rooms = Hashtbl.create 16 }

  let control_stream_exn peer =
    match peer.control_stream with
    | Some stream -> stream
    | None -> failwith "relay peer has no control stream"

  let send stream line =
    try Line_channel.write_line_raw stream line with _ -> ()

  let send_peer peer line =
    match peer.control_stream with
    | Some stream -> send stream line
    | None -> ()

  let room_of_state t room_name =
    match Hashtbl.find_opt t.rooms room_name with
    | Some room -> room
    | None ->
      let room = { sender = None; receiver = None; transfers = Hashtbl.create 4 } in
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
        | Some p -> send_peer p "PEER_LEFT"
        | None -> ());
        Hashtbl.filter_map_inplace
          (fun _ (transfer : transfer) ->
             if transfer.sender == peer || transfer.receiver == peer then None else Some transfer)
          room.transfers;
        if room.sender = None && room.receiver = None
        then Hashtbl.remove t.rooms room_name
      | None -> ());
      peer.room_name <- None;
      peer.role <- None
    | _ -> ()

  let maybe_notify_ready room =
    match room.sender, room.receiver with
    | Some sender, Some receiver ->
      send_peer sender "READY receiver";
      send_peer receiver "READY sender"
    | _ -> ()

  let register_peer t peer room_name role =
    let room = room_of_state t room_name in
    let slot =
      match role with Sender -> room.sender | Receiver -> room.receiver
    in
    match slot with
    | Some _ ->
      send_peer peer "ERROR room role already occupied";
      Quic.Stream.close_writer (control_stream_exn peer)
    | None ->
      (match role with
      | Sender -> room.sender <- Some peer
      | Receiver -> room.receiver <- Some peer);
      peer.room_name <- Some room_name;
      peer.role <- Some role;
      (match peer.observed_candidate with
      | Some (host, port) ->
        send_peer
          peer
          (Printf.sprintf "OBSERVED %s %d" (hex_of_string host) port)
      | None -> ());
      send_peer peer "JOINED";
      (match partner room role with
      | Some _ -> ()
      | None -> send_peer peer "WAITING");
      maybe_notify_ready room

  let bind_transfer_stream t peer transfer_id stream =
    match peer.room_name with
    | Some room_name ->
      (match Hashtbl.find_opt t.rooms room_name with
      | Some room ->
      (match Hashtbl.find_opt room.transfers transfer_id with
      | Some transfer when transfer.sender == peer && not transfer.sender_stream_bound ->
        transfer.sender_stream_bound <- true;
        let receiver_stream = transfer.receiver.start_stream Quic.Direction.Unidirectional in
        let flush_profile = Flush_profile.create ~label:"relay forward" in
        let pending = ref (Bigstringaf.create Binary_transfer.flush_batch_bytes) in
        let pending_bytes = ref 0 in
        let flush_pending k =
          if !pending_bytes = 0
          then k ()
          else (
            let payload = !pending in
            let len = !pending_bytes in
            pending_bytes := 0;
            Quic.Stream.write_bigstring_copy receiver_stream ~off:0 ~len payload;
            Flush_profile.flush
              flush_profile
              ~bytes:len
              (Quic.Stream.flush receiver_stream)
              k)
        in
        let rec proxy () =
          Quic.Stream.schedule_read
            stream
            ~on_eof:(fun () ->
              flush_pending (fun () ->
                Flush_profile.report flush_profile;
                Quic.Stream.close_writer receiver_stream;
                Hashtbl.remove room.transfers transfer_id))
            ~on_read:(fun bs ~off ~len ->
              let rec enqueue off len =
                if len = 0
                then if !pending_bytes >= Binary_transfer.flush_batch_bytes
                then flush_pending proxy
                else proxy ()
                else (
                  let space = Binary_transfer.flush_batch_bytes - !pending_bytes in
                  if space = 0
                  then flush_pending (fun () -> enqueue off len)
                  else (
                    let take = min len space in
                    Bigstringaf.blit
                      bs
                      ~src_off:off
                      !pending
                      ~dst_off:!pending_bytes
                      ~len:take;
                    pending_bytes := !pending_bytes + take;
                    enqueue (off + take) (len - take)))
              in
              enqueue off len)
        in
        proxy ()
      | _ -> Quic.Stream.close_reader stream)
      | None -> Quic.Stream.close_reader stream)
    | None -> Quic.Stream.close_reader stream

  let handle_line t peer line =
    match peer.room_name, peer.role with
    | None, None ->
      (match split_words line with
      | [ "JOIN"; room_name; role_name ] ->
        (match role_of_string role_name with
        | Some role -> register_peer t peer room_name role
        | None ->
          send_peer peer "ERROR role must be sender or receiver";
          Quic.Stream.close_writer (control_stream_exn peer))
      | _ ->
        send_peer peer "ERROR expected: JOIN <code> <sender|receiver>";
        Quic.Stream.close_writer (control_stream_exn peer))
    | Some room_name, Some role ->
      (match Hashtbl.find_opt t.rooms room_name with
      | Some room ->
        (match split_words line, partner room role with
        | [ "USE-RELAY"; transfer_id; _filename_hex; _total_s ], Some receiver
          when role = Sender ->
          let transfer =
            { transfer_id
            ; sender = peer
            ; receiver
            ; sender_stream_bound = false
            }
          in
          Hashtbl.replace room.transfers transfer_id transfer;
          peer.pending_outgoing_transfer <- Some transfer_id;
          send_peer receiver line;
          send_peer peer ("RELAY-READY " ^ transfer_id)
        | [ "USE-RELAY"; transfer_id; filename_hex; total_s; digest_hex ], Some receiver
          when role = Sender ->
          let transfer =
            { transfer_id
            ; sender = peer
            ; receiver
            ; sender_stream_bound = false
            }
          in
          Hashtbl.replace room.transfers transfer_id transfer;
          peer.pending_outgoing_transfer <- Some transfer_id;
          send_peer receiver line;
          send_peer peer ("RELAY-READY " ^ transfer_id)
        | _line, Some p -> send_peer p line
        | _, None -> send_peer peer "WAITING")
      | None -> send_peer peer "ERROR room disappeared")
    | _ ->
      send_peer peer "ERROR invalid peer state";
      Quic.Stream.close_writer (control_stream_exn peer)

  let attach_parser t peer =
    let buf = Buffer.create 4096 in
    let rec pump () =
      Quic.Stream.schedule_read
        (control_stream_exn peer)
        ~on_eof:(fun () ->
          Line_channel.drain_lines buf (fun line -> handle_line t peer line);
          remove_peer t peer)
        ~on_read:(fun bs ~off ~len ->
          Buffer.add_string buf (Bigstringaf.substring bs ~off ~len);
          Line_channel.drain_lines buf (fun line -> handle_line t peer line);
          pump ())
    in
    pump ()

  let handle_stream t peer stream =
    match peer.control_stream, Quic.Stream.direction stream with
    | None, Quic.Direction.Bidirectional ->
      peer.control_stream <- Some stream;
      attach_parser t peer
    | Some _, Quic.Direction.Unidirectional ->
      (match peer.pending_outgoing_transfer with
      | Some transfer_id ->
        peer.pending_outgoing_transfer <- None;
        bind_transfer_stream t peer transfer_id stream
      | None -> Quic.Stream.close_reader stream)
    | None, Quic.Direction.Unidirectional
    | Some _, Quic.Direction.Bidirectional ->
      Quic.Stream.close_reader stream

  let connection_handler t ~cid:_ ~start_stream =
    let peer =
      { start_stream
      ; control_stream = None
      ; room_name = None
      ; role = None
      ; observed_candidate = None
      ; pending_outgoing_transfer = None
      }
    in
    Quic.Transport.F
      (fun stream ->
        (match peer.observed_candidate with
        | None -> peer.observed_candidate <- observed_udp_candidate stream
        | Some _ -> ());
        handle_stream t peer stream;
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
      ; max_datagram_size = wormhole_max_datagram_size
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

let run_relay env ~sw ~port =
  Relay.run env ~sw ~port

module Client = struct
  type opts =
    { host : string
    ; port : int
    ; code : string
    ; password : string
    }

  type rendezvous =
    { observed_host : string option
    }

  type relay_connection =
    { transport : Quic_eio.t
    ; control_stream : Quic.Stream.t
    ; start_stream : Quic.Transport.start_stream
    ; incoming_streams : Quic.Stream.t Eio.Stream.t
    }

  type transfer_mode =
    | Use_relay of
        { transfer_id : string
        ; filename : string option
        ; total_size : int64 option
        ; digest_hex : string option
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

  let relay_config () =
    let cert = "./certificates/server.pem" in
    let priv_key = "./certificates/server.key" in
    let certificates = `Single (Qx509.private_of_pems ~cert ~priv_key) in
    { Quic.Config.certificates
    ; alpn_protocols = [ "wormhole-relay-v1" ]
    ; transport_parameters = Quic.Config.default_transport_parameters
    ; max_datagram_size = wormhole_max_datagram_size
    }

  let connect_with_config env ~sw ~config ~(opts : opts) =
    let on_connect_p, on_connect_u = Eio.Promise.create () in
    let incoming_streams = Eio.Stream.create max_int in
    let stream_handler =
      Quic.Transport.F (fun stream ->
        Eio.Stream.add incoming_streams stream;
        { on_error = ignore })
    in
    let t =
      Quic_eio.Client.create
        env
        ~sw
        ~config
        (fun ~cid:_ ~start_stream:_ -> stream_handler)
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
      stream_handler);
    let start_stream = Eio.Promise.await on_connect_p in
    { transport = t
    ; control_stream = start_stream Quic.Direction.Bidirectional
    ; start_stream
    ; incoming_streams
    }

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

  let wait_for_mode_or_fail ch =
    let rec loop () =
      match split_words (wait_for_line_or_fail ch) with
      | [ "USE-RELAY"; transfer_id ] ->
        Use_relay { transfer_id; filename = None; total_size = None; digest_hex = None }
      | [ "USE-RELAY"; transfer_id; filename_hex; total_s; digest_hex ] ->
        Use_relay
          { transfer_id
          ; filename = Some (string_of_hex filename_hex)
          ; total_size = Some (parse_int64 total_s)
          ; digest_hex = Some digest_hex
          }
      | [ "USE-RELAY"; transfer_id; filename_hex; total_s ] ->
        Use_relay
          { transfer_id
          ; filename = Some (string_of_hex filename_hex)
          ; total_size = Some (parse_int64 total_s)
          ; digest_hex = None
          }
      | [ "PEER_LEFT" ] -> failwith "peer disconnected before transfer mode selected"
      | [ "RELAY-READY"; _ ] -> loop ()
      | _ -> loop ()
    in
    loop ()

  let wait_for_relay_result ch =
    let rec loop () =
      match split_words (wait_for_line_or_fail ch) with
      | [ "RECV-OK" ] | [ "RECV-OK"; _ ] -> ()
      | "RECV-BAD" :: msg ->
        failwith ("receiver reported integrity failure: " ^ String.concat " " msg)
      | [ "PEER_LEFT" ] -> failwith "peer disconnected before final ack"
      | _ -> loop ()
    in
    loop ()

  let wait_for_relay_digest ch transfer_id =
    let rec loop () =
      match split_words (wait_for_line_or_fail ch) with
      | [ "RELAY-DIGEST"; digest_transfer_id; digest_hex ]
        when String.equal digest_transfer_id transfer_id -> digest_hex
      | [ "PEER_LEFT" ] -> failwith "peer disconnected before relay digest arrived"
      | _ -> loop ()
    in
    loop ()

  let relay_send ~yield ~conn ~ch ~session ~file ~transfer_id =
    let stat = Unix.stat file in
    let total_size = Int64.of_int stat.Unix.st_size in
    let filename = Filename.basename file in
    let _ = session in
    Line_channel.write_line
      ch
      (Printf.sprintf
         "USE-RELAY %s %s %Ld"
         transfer_id
         (hex_of_string filename)
         total_size);
    let rec wait_ready () =
      match split_words (wait_for_line_or_fail ch) with
      | [ "RELAY-READY"; ready_id ] when String.equal ready_id transfer_id ->
        ()
      | [ "RELAY-READY"; ready_id ] ->
        wait_ready ()
      | [ "PEER_LEFT" ] -> failwith "peer disconnected before relay transfer started"
      | "ERROR" :: msg -> failwith ("ERROR " ^ String.concat " " msg)
      | _ -> wait_ready ()
    in
    wait_ready ();
    let data_stream = conn.start_stream Quic.Direction.Unidirectional in
    let digest_hex, stats =
      Binary_transfer.send_file ~yield ~stream:data_stream ~file
    in
    Line_channel.write_line
      ch
      (Printf.sprintf "RELAY-DIGEST %s %s" transfer_id digest_hex);
    wait_for_relay_result ch;
    stats

  let relay_recv ~conn ~ch ~session ~output ~transfer_id ~filename ~total_size ~expected_digest =
    let data_stream =
      let rec await () =
        match Eio.Stream.take conn.incoming_streams with
        | stream when Quic.Stream.direction stream = Quic.Direction.Unidirectional -> stream
        | _ -> await ()
      in
      await ()
    in
    let _ = session in
    try
      let digest_hex, stats, _out_path =
        Binary_transfer.recv_file
          ~stream:data_stream
          ~output
          ~expected_name:filename
          ~expected_size:total_size
      in
      let expected_digest =
        match expected_digest with
        | Some digest_hex -> digest_hex
        | None -> wait_for_relay_digest ch transfer_id
      in
      if not (String.equal digest_hex expected_digest)
      then (
        Line_channel.write_line
          ch
          (Printf.sprintf "RECV-BAD digest expected=%s got=%s" expected_digest digest_hex);
        failwith "digest mismatch")
      else (
        Line_channel.write_line ch ("RECV-OK " ^ digest_hex);
        stats)
    with
    | exn ->
      Line_channel.write_line ch ("RECV-BAD " ^ hex_of_string (Printexc.to_string exn));
      raise exn

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

  let do_send env ~sw ~opts ~file =
    let conn = connect env ~sw ~opts in
    let transfer_stats : Transfer_stats.t option ref = ref None in
    let report_stats status =
      match !transfer_stats with
      | None -> ()
      | Some s -> Transfer_stats.report s ~status
    in
    Fun.protect
      ~finally:(fun () ->
        Quic.Stream.close_writer conn.control_stream;
        Quic_eio.shutdown conn.transport)
      (fun () ->
         try
           let ch = Line_channel.of_stream conn.control_stream in
           Line_channel.write_line
             ch
             (Printf.sprintf "JOIN %s %s" opts.code (role_to_string Sender));
           let _rendezvous = wait_for_ready ch in
           let session = perform_pake ~opts ~role:Sender ch in
           let transfer_id = hex_of_string (random_bytes 16) in
           let stats =
             relay_send ~yield:Eio.Fiber.yield ~conn ~ch ~session ~file ~transfer_id
           in
           transfer_stats := Some stats;
           report_stats "completed"
         with
         | Sys.Break ->
           report_stats "interrupted";
           raise Sys.Break
         | exn ->
           report_stats "failed";
           raise exn)

  let do_recv env ~sw ~opts ~output =
    let conn = connect env ~sw ~opts in
    let transfer_stats : Transfer_stats.t option ref = ref None in
    let report_stats status =
      match !transfer_stats with
      | None -> ()
      | Some s -> Transfer_stats.report s ~status
    in
    Fun.protect
      ~finally:(fun () ->
        Quic.Stream.close_writer conn.control_stream;
        Quic_eio.shutdown conn.transport)
      (fun () ->
         try
           let ch = Line_channel.of_stream conn.control_stream in
           Line_channel.write_line
             ch
             (Printf.sprintf "JOIN %s %s" opts.code (role_to_string Receiver));
           let _rendezvous = wait_for_ready ch in
           let session = perform_pake ~opts ~role:Receiver ch in
           Printf.printf "waiting for sender to start transfer...\n%!";
           (match wait_for_mode_or_fail ch with
            | Use_relay { transfer_id; filename; total_size; digest_hex } ->
               let stats =
                 relay_recv
                   ~conn
                   ~ch
                   ~session
                   ~output
                   ~transfer_id
                   ~filename:(Option.value filename ~default:"download.bin")
                   ~total_size:(Option.value total_size ~default:0L)
                   ~expected_digest:digest_hex
                 in
                transfer_stats := Some stats);
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
  }

type recv_opts =
  { host : string
  ; port : int
  ; code : string option
  ; password : string option
  ; output : string option
  }

let default_send_opts =
  { host = "localhost"
  ; port = 4443
  ; code = None
  ; password = None
  ; file = None
  }

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

let getenv_int_opt name =
  match Sys.getenv_opt name with
  | None -> None
  | Some value ->
    (match int_of_string_opt value with
    | Some v -> Some v
    | None -> failwith (Printf.sprintf "invalid integer for %s: %s" name value))

let tune_gc () =
  let gc = Gc.get () in
  let target_minor_heap_size =
    match getenv_int_opt "WORMHOLE_MINOR_HEAP_SIZE_MB" with
    | Some mb when mb > 0 -> mb * 1024 * 1024
    | Some _ -> failwith "WORMHOLE_MINOR_HEAP_SIZE_MB must be > 0"
    | None -> 8 * 1024 * 1024
  in
  if gc.Gc.minor_heap_size < target_minor_heap_size
  then Gc.set { gc with minor_heap_size = target_minor_heap_size }

let () =
  Mirage_crypto_rng_unix.use_default ();
  Sys.(set_signal sigpipe Signal_ignore);
  Sys.catch_break true;
  tune_gc ();
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
        Eio.Switch.run (fun sw -> Client.do_recv env ~sw ~opts ~output:recv_opts.output))
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
