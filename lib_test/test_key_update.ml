module Quic = Quic__
open Quic

let read_file path =
  let ic = open_in_bin path in
  Fun.protect
    ~finally:(fun () -> close_in_noerr ic)
    (fun () ->
       let n = in_channel_length ic in
       really_input_string ic n)

let server_certificates () =
  let cert = "./certificates/server.pem" in
  let priv_key = "./certificates/server.key" in
  let certchain =
    let pem = read_file cert in
    match X509.Certificate.decode_pem_multiple pem with
    | Ok certchain -> certchain
    | Error (`Msg m) -> failwith m
  in
  let priv_key =
    let pem = read_file priv_key in
    match X509.Private_key.decode_pem pem with
    | Ok x -> x
    | Error (`Msg m) -> failwith m
  in
  `Single (certchain, priv_key)

let noop_connection_handler ~cid:_ ~start_stream:_ : Transport.stream_handler =
  Transport.F (fun _stream -> { Transport.on_error = (fun _ -> ()) })

let iovecs_to_bigstring iovecs =
  let len = IOVec.lengthv iovecs in
  let bs = Bigstringaf.create len in
  let dst_off = ref 0 in
  List.iter
    (fun { IOVec.buffer; off = src_off; len } ->
       Bigstringaf.blit buffer ~src_off bs ~dst_off:!dst_off ~len;
       dst_off := !dst_off + len)
    iovecs;
  bs, len

let next_datagram_as_bigstring writer =
  match Serialize.Writer.next writer with
  | `Write iovecs -> iovecs_to_bigstring iovecs
  | `Yield | `Close _ -> Alcotest.fail "expected generated packet datagram"

let make_short_header_datagram
      ~encrypter
      ~packet_number
      ~key_phase
      ~source_cid
      ~dest_cid
      frames
  =
  let writer = Serialize.Writer.create 0x1000 in
  let header_info =
    Serialize.Writer.make_header_info
      ~encrypter
      ~packet_number
      ~encryption_level:Application_data
      ~key_phase
      ~source_cid
      ~token:""
      dest_cid
  in
  Serialize.Writer.write_frames_packet writer ~header_info frames;
  next_datagram_as_bigstring writer

let pop_write t =
  match Transport.next_write_operation t with
  | `Writev (iovecs, _peer_address, cid) ->
    let datagram, len = iovecs_to_bigstring iovecs in
    Some (datagram, len, cid)
  | `Yield _ | `Close _ -> None

let transfer_one ~src ~dst ~client_address =
  match pop_write src with
  | None -> false
  | Some (datagram, len, cid) ->
    let consumed = Transport.read dst ~client_address datagram ~off:0 ~len in
    Alcotest.(check int) "consume full datagram" len consumed;
    Transport.report_write_result src ~cid (`Ok len);
    true

let rec drain ~src ~dst ~client_address =
  if transfer_one ~src ~dst ~client_address
  then 1 + drain ~src ~dst ~client_address
  else 0

let pump_bidi ~client ~server =
  let c2s = drain ~src:client ~dst:server ~client_address:"client-address" in
  let s2c = drain ~src:server ~dst:client ~client_address:"server-address" in
  c2s + s2c

let unique_connections (t : Transport.t) =
  Transport.Connection.Table.fold
    (fun _cid conn acc ->
       if List.exists (fun existing -> existing == conn) acc
       then acc
       else conn :: acc)
    t.connections
    []

let single_connection side (t : Transport.t) =
  match unique_connections t with
  | [ conn ] -> conn
  | [] -> Alcotest.failf "%s side has no active connection" side
  | conns ->
    Alcotest.failf
      "%s side expected exactly one connection, got %d"
      side
      (List.length conns)

let connection_has_application_keys (c : Transport.Connection.t) =
  Option.is_some c.application_tx_secret
  && Option.is_some c.application_rx_secret
  &&
  match Encryption_level.find Application_data c.encdec with
  | Some { Crypto.decrypter = Some _; _ } -> true
  | Some { decrypter = None; _ } | None -> false

let key_update_error_to_string = function
  | `Handshake_not_confirmed -> "handshake not confirmed"
  | `Awaiting_current_phase_ack -> "awaiting current phase ack"
  | `Current_phase_not_acknowledged -> "current phase not acknowledged"
  | `Missing_application_keys -> "missing application keys"

let rec drive_until_ready ~rounds ~client ~server =
  if rounds = 0
  then Alcotest.fail "handshake did not reach application keys"
  else
    let progressed = pump_bidi ~client ~server in
    let client_ready =
      match unique_connections client with
      | [ c ] -> connection_has_application_keys c
      | _ -> false
    in
    let server_ready =
      match unique_connections server with
      | [ c ] -> connection_has_application_keys c
      | _ -> false
    in
    if client_ready && server_ready
    then ()
    else if progressed = 0
    then Alcotest.fail "transport stalled before handshake completion"
    else drive_until_ready ~rounds:(rounds - 1) ~client ~server

let rec drain_until_idle ~rounds ~client ~server =
  if rounds = 0
  then Alcotest.fail "transport did not become idle"
  else
    let progressed = pump_bidi ~client ~server in
    if progressed = 0
    then ()
    else drain_until_idle ~rounds:(rounds - 1) ~client ~server

let test_key_update_receive_path () =
  let now =
    let now_ms = ref 0L in
    fun () ->
      let current = !now_ms in
      now_ms := Int64.succ current;
      current
  in
  let config =
    { Quic.Config.certificates = server_certificates ()
    ; alpn_protocols = [ "h3" ]
    }
  in
  let server =
    Transport.Server.create ~now_ms:now ~config noop_connection_handler
  in

  let server_cid = CID.generate () in
  let client_cid = CID.generate () in
  let tls_state =
    Qtls.server ~certificates:(server_certificates ()) ~alpn_protocols:[ "h3" ]
  in
  let connection =
    Transport.Connection.create
      ~mode:Server
      ~peer_address:"client-address"
      ~tls_state
      ~now_ms:now
      ~wakeup_writer:(fun () -> ())
      ~shutdown:(fun _ -> ())
      ~connection_handler:noop_connection_handler
      server_cid
  in

  let ciphersuite = `AES_128_GCM_SHA256 in
  let initial_rx_secret = String.make 32 '\x11' in
  let next_rx_secret =
    Transport.derive_next_application_secret ~ciphersuite initial_rx_secret
  in
  let current_aead = Crypto.AEAD.make ~ciphersuite initial_rx_secret in
  let next_aead = Crypto.AEAD.make ~ciphersuite next_rx_secret in

  connection.application_ciphersuite <- Some ciphersuite;
  connection.application_rx_secret <- Some initial_rx_secret;
  connection.application_tx_secret <- Some initial_rx_secret;
  connection.peer_application_key_phase <- false;
  connection.application_key_phase <- false;
  connection.dest_cid <- client_cid;

  Encryption_level.add
    Application_data
    { Crypto.encrypter = current_aead; decrypter = Some current_aead }
    connection.encdec;
  connection.encdec.current <- Application_data;

  Transport.register_connection_id server ~cid:server_cid ~connection;

  let writer = Serialize.Writer.create 0x1000 in
  let header_info =
    Serialize.Writer.make_header_info
      ~encrypter:next_aead
      ~packet_number:0L
      ~encryption_level:Application_data
      ~key_phase:true
      ~source_cid:client_cid
      ~token:""
      server_cid
  in
  Serialize.Writer.write_frames_packet writer ~header_info [ Frame.Ping ];
  let datagram, len = next_datagram_as_bigstring writer in
  let datagram_s = Bigstringaf.substring datagram ~off:0 ~len in
  let parsed_header, payload_length =
    match
      Angstrom.parse_string
        ~consume:Prefix
        Parse.Packet.protected_header
        datagram_s
    with
    | Ok (header, payload_length) -> header, payload_length
    | Error e -> Alcotest.failf "failed to parse generated packet header: %s" e
  in
  let parsed_dest_cid =
    match parsed_header with
    | Packet.Header.Short { dest_cid; _ } -> dest_cid
    | Packet.Header.Initial _ | Packet.Header.Long _ ->
      Alcotest.fail "expected generated packet to use short header"
  in
  Alcotest.(check bool)
    "generated packet carries expected destination CID"
    true
    (CID.equal parsed_dest_cid server_cid);
  Alcotest.(check bool)
    "server has destination CID in table"
    true
    (Transport.Connection.Table.mem server.connections parsed_dest_cid);
  let decrypted =
    Crypto.AEAD.decrypt_packet
      next_aead
      ~payload_length
      ~largest_pn:(-1L)
      datagram_s
  in
  Alcotest.(check bool)
    "sanity: generated packet decrypts with sender key"
    true
    (Option.is_some decrypted);

  let consumed =
    Transport.read server ~client_address:"client-address" datagram ~off:0 ~len
  in
  Alcotest.(check int) "consume full key-update datagram" len consumed;
  Alcotest.(check int64)
    "server tracked application packet number"
    0L
    connection.packet_number_spaces.application_data.received;
  Alcotest.(check bool)
    "server did not close on key update packet"
    false
    connection.did_send_connection_close;
  Alcotest.(check bool)
    "server accepted new key phase"
    true
    connection.peer_application_key_phase;
  Alcotest.(check string)
    "server rotated receive secret"
    next_rx_secret
    (Option.get connection.application_rx_secret);
  Alcotest.(check (option int64))
    "server tracked first packet number in new receive phase"
    (Some 0L)
    connection.first_received_pn_current_key_phase

let test_key_update_receive_path_accepts_reordered_old_packet () =
  let now =
    let now_ms = ref 0L in
    fun () ->
      let current = !now_ms in
      now_ms := Int64.succ current;
      current
  in
  let config =
    { Quic.Config.certificates = server_certificates ()
    ; alpn_protocols = [ "h3" ]
    }
  in
  let server =
    Transport.Server.create ~now_ms:now ~config noop_connection_handler
  in
  let server_cid = CID.generate () in
  let client_cid = CID.generate () in
  let tls_state =
    Qtls.server ~certificates:(server_certificates ()) ~alpn_protocols:[ "h3" ]
  in
  let connection =
    Transport.Connection.create
      ~mode:Server
      ~peer_address:"client-address"
      ~tls_state
      ~now_ms:now
      ~wakeup_writer:(fun () -> ())
      ~shutdown:(fun _ -> ())
      ~connection_handler:noop_connection_handler
      server_cid
  in
  let ciphersuite = `AES_128_GCM_SHA256 in
  let initial_secret = String.make 32 '\x41' in
  let next_secret =
    Transport.derive_next_application_secret ~ciphersuite initial_secret
  in
  let current_aead = Crypto.AEAD.make ~ciphersuite initial_secret in
  let next_aead = Crypto.AEAD.make ~ciphersuite next_secret in
  connection.application_ciphersuite <- Some ciphersuite;
  connection.application_rx_secret <- Some initial_secret;
  connection.application_tx_secret <- Some initial_secret;
  connection.peer_application_key_phase <- false;
  connection.application_key_phase <- false;
  connection.dest_cid <- client_cid;
  Encryption_level.add
    Application_data
    { Crypto.encrypter = current_aead; decrypter = Some current_aead }
    connection.encdec;
  connection.encdec.current <- Application_data;
  Transport.register_connection_id server ~cid:server_cid ~connection;

  let datagram_new, len_new =
    make_short_header_datagram
      ~encrypter:next_aead
      ~packet_number:10L
      ~key_phase:true
      ~source_cid:client_cid
      ~dest_cid:server_cid
      [ Frame.Ping ]
  in
  let consumed_new =
    Transport.read
      server
      ~client_address:"client-address"
      datagram_new
      ~off:0
      ~len:len_new
  in
  Alcotest.(check int) "consume key-update datagram" len_new consumed_new;
  Alcotest.(check bool)
    "peer phase promoted"
    true
    connection.peer_application_key_phase;
  Alcotest.(check (option int64))
    "boundary tracks first new-phase packet number"
    (Some 10L)
    connection.first_received_pn_current_key_phase;

  let datagram_old, len_old =
    make_short_header_datagram
      ~encrypter:current_aead
      ~packet_number:9L
      ~key_phase:false
      ~source_cid:client_cid
      ~dest_cid:server_cid
      [ Frame.Ping ]
  in
  let consumed_old =
    Transport.read
      server
      ~client_address:"client-address"
      datagram_old
      ~off:0
      ~len:len_old
  in
  Alcotest.(check int)
    "consume reordered old-phase datagram"
    len_old
    consumed_old;
  Alcotest.(check bool)
    "reordered old-phase packet does not close connection"
    false
    connection.did_send_connection_close;
  Alcotest.(check bool)
    "current peer key phase remains the promoted phase"
    true
    connection.peer_application_key_phase

let test_key_update_receive_path_rejects_old_packet_past_boundary () =
  let now =
    let now_ms = ref 0L in
    fun () ->
      let current = !now_ms in
      now_ms := Int64.succ current;
      current
  in
  let config =
    { Quic.Config.certificates = server_certificates ()
    ; alpn_protocols = [ "h3" ]
    }
  in
  let server =
    Transport.Server.create ~now_ms:now ~config noop_connection_handler
  in
  let server_cid = CID.generate () in
  let client_cid = CID.generate () in
  let tls_state =
    Qtls.server ~certificates:(server_certificates ()) ~alpn_protocols:[ "h3" ]
  in
  let connection =
    Transport.Connection.create
      ~mode:Server
      ~peer_address:"client-address"
      ~tls_state
      ~now_ms:now
      ~wakeup_writer:(fun () -> ())
      ~shutdown:(fun _ -> ())
      ~connection_handler:noop_connection_handler
      server_cid
  in
  let ciphersuite = `AES_128_GCM_SHA256 in
  let initial_secret = String.make 32 '\x51' in
  let next_secret =
    Transport.derive_next_application_secret ~ciphersuite initial_secret
  in
  let current_aead = Crypto.AEAD.make ~ciphersuite initial_secret in
  let next_aead = Crypto.AEAD.make ~ciphersuite next_secret in
  connection.application_ciphersuite <- Some ciphersuite;
  connection.application_rx_secret <- Some initial_secret;
  connection.application_tx_secret <- Some initial_secret;
  connection.peer_application_key_phase <- false;
  connection.application_key_phase <- false;
  connection.dest_cid <- client_cid;
  Encryption_level.add
    Application_data
    { Crypto.encrypter = current_aead; decrypter = Some current_aead }
    connection.encdec;
  connection.encdec.current <- Application_data;
  Transport.register_connection_id server ~cid:server_cid ~connection;

  let datagram_new, len_new =
    make_short_header_datagram
      ~encrypter:next_aead
      ~packet_number:10L
      ~key_phase:true
      ~source_cid:client_cid
      ~dest_cid:server_cid
      [ Frame.Ping ]
  in
  let consumed_new =
    Transport.read
      server
      ~client_address:"client-address"
      datagram_new
      ~off:0
      ~len:len_new
  in
  Alcotest.(check int) "consume key-update datagram" len_new consumed_new;

  let datagram_old, len_old =
    make_short_header_datagram
      ~encrypter:current_aead
      ~packet_number:10L
      ~key_phase:false
      ~source_cid:client_cid
      ~dest_cid:server_cid
      [ Frame.Ping ]
  in
  let consumed_old =
    Transport.read
      server
      ~client_address:"client-address"
      datagram_old
      ~off:0
      ~len:len_old
  in
  Alcotest.(check int)
    "invalid old-phase packet is consumed by connection close path"
    len_old
    consumed_old;
  Alcotest.(check bool)
    "old-phase packet at or beyond boundary closes connection"
    true
    connection.did_send_connection_close

let test_key_update_receive_path_discards_old_keys_after_three_pto () =
  let now_ms = ref 0L in
  let now () = !now_ms in
  let config =
    { Quic.Config.certificates = server_certificates ()
    ; alpn_protocols = [ "h3" ]
    }
  in
  let server =
    Transport.Server.create ~now_ms:now ~config noop_connection_handler
  in
  let server_cid = CID.generate () in
  let client_cid = CID.generate () in
  let tls_state =
    Qtls.server ~certificates:(server_certificates ()) ~alpn_protocols:[ "h3" ]
  in
  let connection =
    Transport.Connection.create
      ~mode:Server
      ~peer_address:"client-address"
      ~tls_state
      ~now_ms:now
      ~wakeup_writer:(fun () -> ())
      ~shutdown:(fun _ -> ())
      ~connection_handler:noop_connection_handler
      server_cid
  in
  let ciphersuite = `AES_128_GCM_SHA256 in
  let initial_secret = String.make 32 '\x61' in
  let next_secret =
    Transport.derive_next_application_secret ~ciphersuite initial_secret
  in
  let current_aead = Crypto.AEAD.make ~ciphersuite initial_secret in
  let next_aead = Crypto.AEAD.make ~ciphersuite next_secret in
  connection.application_ciphersuite <- Some ciphersuite;
  connection.application_rx_secret <- Some initial_secret;
  connection.application_tx_secret <- Some initial_secret;
  connection.peer_application_key_phase <- false;
  connection.application_key_phase <- false;
  connection.dest_cid <- client_cid;
  Encryption_level.add
    Application_data
    { Crypto.encrypter = current_aead; decrypter = Some current_aead }
    connection.encdec;
  connection.encdec.current <- Application_data;
  Transport.register_connection_id server ~cid:server_cid ~connection;

  let datagram_new, len_new =
    make_short_header_datagram
      ~encrypter:next_aead
      ~packet_number:10L
      ~key_phase:true
      ~source_cid:client_cid
      ~dest_cid:server_cid
      [ Frame.Ping ]
  in
  let consumed_new =
    Transport.read
      server
      ~client_address:"client-address"
      datagram_new
      ~off:0
      ~len:len_new
  in
  Alcotest.(check int) "consume key-update datagram" len_new consumed_new;
  Alcotest.(check bool)
    "previous decrypter retained immediately after promotion"
    true
    (Option.is_some connection.previous_application_decrypter);
  ignore (pop_write server : (Bigstringaf.t * int * string) option);

  let discard_interval =
    Recovery.key_update_old_key_discard_interval_ms connection.recovery
  in
  now_ms := Int64.add !now_ms discard_interval;

  let datagram_old, len_old =
    make_short_header_datagram
      ~encrypter:current_aead
      ~packet_number:9L
      ~key_phase:false
      ~source_cid:client_cid
      ~dest_cid:server_cid
      [ Frame.Ping ]
  in
  let consumed_old =
    Transport.read
      server
      ~client_address:"client-address"
      datagram_old
      ~off:0
      ~len:len_old
  in
  Alcotest.(check int)
    "expired old-key datagram is consumed at transport boundary"
    len_old
    consumed_old;
  Alcotest.(check bool)
    "previous decrypter discarded after three PTO"
    false
    (Option.is_some connection.previous_application_decrypter);
  Alcotest.(check int64)
    "expired old-key packet does not advance largest received packet number"
    10L
    connection.packet_number_spaces.application_data.received;
  Alcotest.(check bool)
    "expired old-key packet does not generate an ACK"
    true
    (Option.is_none (pop_write server));
  Alcotest.(check bool)
    "expired old-key packet does not close connection"
    false
    connection.did_send_connection_close

let test_key_update_send_path_updates_ack_keys () =
  let now =
    let now_ms = ref 0L in
    fun () ->
      let current = !now_ms in
      now_ms := Int64.succ current;
      current
  in
  let config =
    { Quic.Config.certificates = server_certificates (); alpn_protocols = [ "h3" ] }
  in
  let server =
    Transport.Server.create ~now_ms:now ~config noop_connection_handler
  in
  let server_cid = CID.generate () in
  let client_cid = CID.generate () in
  let tls_state =
    Qtls.server
      ~certificates:(server_certificates ())
      ~alpn_protocols:[ "h3" ]
  in
  let connection =
    Transport.Connection.create
      ~mode:Server
      ~peer_address:"client-address"
      ~tls_state
      ~now_ms:now
      ~wakeup_writer:(fun () -> ())
      ~shutdown:(fun _ -> ())
      ~connection_handler:noop_connection_handler
      server_cid
  in
  let ciphersuite = `AES_128_GCM_SHA256 in
  let initial_rx_secret = String.make 32 '\x11' in
  let next_rx_secret =
    Transport.derive_next_application_secret ~ciphersuite initial_rx_secret
  in
  let current_aead = Crypto.AEAD.make ~ciphersuite initial_rx_secret in
  let next_aead = Crypto.AEAD.make ~ciphersuite next_rx_secret in
  connection.application_ciphersuite <- Some ciphersuite;
  connection.application_rx_secret <- Some initial_rx_secret;
  connection.application_tx_secret <- Some initial_rx_secret;
  connection.peer_application_key_phase <- false;
  connection.application_key_phase <- false;
  connection.dest_cid <- client_cid;
  Encryption_level.add
    Application_data
    { Crypto.encrypter = current_aead; decrypter = Some current_aead }
    connection.encdec;
  connection.encdec.current <- Application_data;
  Transport.register_connection_id server ~cid:server_cid ~connection;
  let writer = Serialize.Writer.create 0x1000 in
  let header_info =
    Serialize.Writer.make_header_info
      ~encrypter:next_aead
      ~packet_number:0L
      ~encryption_level:Application_data
      ~key_phase:true
      ~source_cid:client_cid
      ~token:""
      server_cid
  in
  Serialize.Writer.write_frames_packet writer ~header_info [ Frame.Ping ];
  let datagram, len = next_datagram_as_bigstring writer in
  let consumed =
    Transport.read server ~client_address:"client-address" datagram ~off:0 ~len
  in
  Alcotest.(check int) "consume key-update datagram" len consumed;

  let ack_dgram, ack_len, ack_cid =
    match pop_write server with
    | Some x -> x
    | None -> Alcotest.fail "expected ACK datagram from server"
  in
  let ack = Bigstringaf.substring ack_dgram ~off:0 ~len:ack_len in
  let ack_payload_length =
    match
      Angstrom.parse_string
        ~consume:Prefix
        Parse.Packet.protected_header
        ack
    with
    | Ok (_header, payload_length) -> payload_length
    | Error e -> Alcotest.failf "failed to parse ACK protected header: %s" e
  in
  let decrypt_old =
    Crypto.AEAD.decrypt_packet
      current_aead
      ~payload_length:ack_payload_length
      ~largest_pn:(-1L)
      ack
  in
  let decrypt_new =
    Crypto.AEAD.decrypt_packet
      next_aead
      ~payload_length:ack_payload_length
      ~largest_pn:(-1L)
      ack
  in
  Alcotest.(check bool)
    "ACK no longer decrypts with old send key"
    true
    (Option.is_none decrypt_old);
  Alcotest.(check bool)
    "ACK decrypts with updated send key"
    true
    (Option.is_some decrypt_new);
  let ack_key_phase =
    Transport.short_header_key_phase
      (String.get_uint8 (Option.get decrypt_new).Crypto.AEAD.header 0)
  in
  Alcotest.(check bool)
    "ACK key phase updated"
    true
    ack_key_phase;
  Transport.report_write_result server ~cid:ack_cid (`Ok ack_len)

let test_server13_established_keyupdate_protocol_violation () =
  let now =
    let now_ms = ref 0L in
    fun () ->
      let current = !now_ms in
      now_ms := Int64.succ current;
      current
  in
  let config =
    { Quic.Config.certificates = server_certificates (); alpn_protocols = [ "h3" ] }
  in
  let server =
    Transport.Server.create ~now_ms:now ~config noop_connection_handler
  in
  let client =
    Transport.Client.create ~now_ms:now ~config noop_connection_handler
  in
  Transport.connect
    client
    ~address:"server-address"
    ~host:"localhost"
    noop_connection_handler;
  drive_until_ready ~rounds:200 ~client ~server;
  drain_until_idle ~rounds:50 ~client ~server;

  let client_conn = single_connection "client" client in
  let server_conn = single_connection "server" server in
  let key_update_handshake = "\x18\x00\x00\x01\x00" in
  let crypto_payload =
    Bigstringaf.of_string
      ~off:0
      ~len:(String.length key_update_handshake)
      key_update_handshake
  in
  Transport.Connection.send_frames
    client_conn
    ~encryption_level:Application_data
    [ Frame.Crypto
        { IOVec.off = 0
        ; len = String.length key_update_handshake
        ; buffer = crypto_payload
        }
    ];
  let datagram, len, cid =
    match pop_write client with
    | Some x -> x
    | None -> Alcotest.fail "expected client datagram carrying CRYPTO KeyUpdate"
  in
  let consumed =
    Transport.read server ~client_address:"client-address" datagram ~off:0 ~len
  in
  Alcotest.(check int) "consume keyupdate datagram" len consumed;
  Transport.report_write_result client ~cid (`Ok len);

  Alcotest.(check bool)
    "receiving post-handshake KeyUpdate closes connection"
    true
    server_conn.did_send_connection_close;
  let close_datagram, close_len =
    match Serialize.Writer.next server_conn.writer with
    | `Write iovecs -> iovecs_to_bigstring iovecs
    | `Yield | `Close _ ->
      Alcotest.fail "expected connection-close datagram after KeyUpdate"
  in
  let close_packet =
    Bigstringaf.substring close_datagram ~off:0 ~len:close_len
  in
  let close_payload_length =
    match
      Angstrom.parse_string
        ~consume:Prefix
        Parse.Packet.protected_header
        close_packet
    with
    | Ok (_header, payload_length) -> payload_length
    | Error e ->
      Alcotest.failf "failed to parse close packet protected header: %s" e
  in
  let close_decrypted =
    let server_send_aead =
      (Encryption_level.find_exn Application_data server_conn.encdec).encrypter
    in
    Crypto.AEAD.decrypt_packet
      server_send_aead
      ~payload_length:close_payload_length
      ~largest_pn:(-1L)
      close_packet
  in
  let close_plaintext =
    match close_decrypted with
    | Some decrypted -> decrypted.Crypto.AEAD.plaintext
    | None -> Alcotest.fail "failed to decrypt close packet"
  in
  match Angstrom.parse_string ~consume:Prefix Parse.Frame.frame close_plaintext with
  | Ok
      (Frame.Connection_close_quic
         { error_code = Protocol_violation; frame_type = Frame.Type.Crypto; _ }) ->
    ()
  | Ok frame ->
    Alcotest.failf
      "expected CONNECTION_CLOSE(PROTOCOL_VIOLATION, frame=CRYPTO), got frame type 0x%x"
      (Frame.Type.serialize (Frame.to_frame_type frame))
  | Error e ->
    Alcotest.failf "failed to parse close frame: %s" e

let test_local_key_update_requires_handshake_confirmation () =
  let now =
    let now_ms = ref 0L in
    fun () ->
      let current = !now_ms in
      now_ms := Int64.succ current;
      current
  in
  let server_cid = CID.generate () in
  let tls_state =
    Qtls.server ~certificates:(server_certificates ()) ~alpn_protocols:[ "h3" ]
  in
  let connection =
    Transport.Connection.create
      ~mode:Server
      ~peer_address:"client-address"
      ~tls_state
      ~now_ms:now
      ~wakeup_writer:(fun () -> ())
      ~shutdown:(fun _ -> ())
      ~connection_handler:noop_connection_handler
      server_cid
  in
  match Transport.Connection.initiate_key_update connection with
  | Error `Handshake_not_confirmed -> ()
  | Ok () ->
    Alcotest.fail "expected key update initiation to fail before handshake confirmation"
  | Error e ->
    Alcotest.failf
      "expected handshake_not_confirmed, got %s"
      (key_update_error_to_string e)

let test_local_key_update_send_path () =
  let now =
    let now_ms = ref 0L in
    fun () ->
      let current = !now_ms in
      now_ms := Int64.succ current;
      current
  in
  let server_cid = CID.generate () in
  let tls_state =
    Qtls.server ~certificates:(server_certificates ()) ~alpn_protocols:[ "h3" ]
  in
  let server_conn =
    Transport.Connection.create
      ~mode:Server
      ~peer_address:"client-address"
      ~tls_state
      ~now_ms:now
      ~wakeup_writer:(fun () -> ())
      ~shutdown:(fun _ -> ())
      ~connection_handler:noop_connection_handler
      server_cid
  in
  let ciphersuite = `AES_128_GCM_SHA256 in
  let initial_tx_secret = String.make 32 '\x31' in
  let initial_rx_secret = String.make 32 '\x22' in
  server_conn.application_ciphersuite <- Some ciphersuite;
  server_conn.application_tx_secret <- Some initial_tx_secret;
  server_conn.application_rx_secret <- Some initial_rx_secret;
  server_conn.handshake_confirmed <- true;
  server_conn.lowest_pn_sent_current_key_phase <- Some 7L;
  server_conn.largest_acked_application_data <- 7L;
  let app_encrypter = Crypto.AEAD.make ~ciphersuite initial_tx_secret in
  let app_decrypter = Crypto.AEAD.make ~ciphersuite initial_rx_secret in
  Encryption_level.add
    Application_data
    { Crypto.encrypter = app_encrypter; decrypter = Some app_decrypter }
    server_conn.encdec;
  server_conn.encdec.current <- Application_data;

  let old_tx_secret = Option.get server_conn.application_tx_secret in
  let expected_tx_secret_after_first_update =
    Transport.derive_next_application_secret ~ciphersuite old_tx_secret
  in
  (match Transport.Connection.initiate_key_update server_conn with
  | Ok () -> ()
  | Error e ->
    Alcotest.failf
      "expected first key update initiation to succeed, got %s"
      (key_update_error_to_string e));
  Alcotest.(check bool)
    "server switched key phase after local update"
    true
    server_conn.application_key_phase;
  Alcotest.(check bool)
    "server now waits for ACK before next update"
    true
    server_conn.local_key_update_waiting_for_ack;
  Alcotest.(check string)
    "server rotated send secret on local update"
    expected_tx_secret_after_first_update
    (Option.get server_conn.application_tx_secret);

  (match Transport.Connection.initiate_key_update server_conn with
  | Error `Awaiting_current_phase_ack -> ()
  | Ok () ->
    Alcotest.fail "expected second immediate key update initiation to be blocked"
  | Error e ->
    Alcotest.failf
      "expected awaiting_current_phase_ack, got %s"
      (key_update_error_to_string e));
  (* Simulate first packet sent in the updated phase and ACK processing. *)
  server_conn.lowest_pn_sent_current_key_phase <- Some 8L;
  let outgoing_frames = Transport.create_outgoing_frames ~current:Application_data in
  let packet_info : Transport.Connection.packet_info =
    { packet_number = 0L
    ; header =
        Packet.Header.Short
          { key_phase = server_conn.peer_application_key_phase
          ; dest_cid = CID.generate ()
          }
    ; outgoing_frames
    ; encryption_level = Application_data
    ; connection = server_conn
    }
  in
  Transport.Connection.process_ack_frame
    server_conn
    ~packet_info
    ~delay:0
    ~ranges:[ { Frame.Range.first = 7L; last = 7L } ];
  Alcotest.(check bool)
    "ACK gate remains until current phase packet is acknowledged"
    true
    server_conn.local_key_update_waiting_for_ack;
  Transport.Connection.process_ack_frame
    server_conn
    ~packet_info
    ~delay:0
    ~ranges:[ { Frame.Range.first = 8L; last = 8L } ];
  Alcotest.(check bool)
    "server cleared ACK gate after updated-phase ACK"
    false
    server_conn.local_key_update_waiting_for_ack;

  let tx_secret_after_first_update = Option.get server_conn.application_tx_secret in
  let expected_tx_secret_after_second_update =
    Transport.derive_next_application_secret
      ~ciphersuite
      tx_secret_after_first_update
  in
  (match Transport.Connection.initiate_key_update server_conn with
  | Ok () -> ()
  | Error e ->
    Alcotest.failf
      "expected third key update initiation to succeed after ACK, got %s"
      (key_update_error_to_string e));
  Alcotest.(check bool)
    "server toggled key phase again"
    false
    server_conn.application_key_phase;
  Alcotest.(check string)
    "server rotated send secret again"
    expected_tx_secret_after_second_update
    (Option.get server_conn.application_tx_secret)

let suites =
  [ "key update receive path", `Quick, test_key_update_receive_path
  ; ( "key update receive path accepts reordered old packet"
    , `Quick
    , test_key_update_receive_path_accepts_reordered_old_packet )
  ; ( "key update receive path rejects old packet past boundary"
    , `Quick
    , test_key_update_receive_path_rejects_old_packet_past_boundary )
  ; ( "key update receive path discards old keys after three PTO"
    , `Quick
    , test_key_update_receive_path_discards_old_keys_after_three_pto )
  ; ( "send keys are updated in response to key update"
    , `Quick
    , test_key_update_send_path_updates_ack_keys )
  ; ( "post-handshake KeyUpdate triggers protocol violation"
    , `Quick
    , test_server13_established_keyupdate_protocol_violation )
  ; ( "local key update requires handshake confirmation"
    , `Quick
    , test_local_key_update_requires_handshake_confirmation )
  ; "local key update send path", `Quick, test_local_key_update_send_path
  ]

let setup_logging ?style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level level

let () =
  (* setup_logging (Some Debug); *)
  Mirage_crypto_rng_unix.use_default ();
  Alcotest.run "key-update" [ "key-update", suites ]
