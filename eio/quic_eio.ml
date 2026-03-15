(*----------------------------------------------------------------------------
 *  Copyright (c) 2017 Inhabited Type LLC.
 *  Copyright (c) 2020 Antonio N. Monteiro.
 *
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  3. Neither the name of the author nor the names of his contributors
 *     may be used to endorse or promote products derived from this software
 *     without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS ``AS IS'' AND ANY EXPRESS
 *  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 *  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 *  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 *  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *---------------------------------------------------------------------------*)

open Eio.Std
module Buffer = Gluten.Buffer

external send_msg_iovecs :
  Unix.file_descr -> Unix.sockaddr -> 'a Faraday.iovec list -> int
  = "ocaml_quic_eio_send_msg_iovecs"

external send_msg_iovecs_nb :
  Unix.file_descr -> Unix.sockaddr -> 'a Faraday.iovec list -> int
  = "ocaml_quic_eio_send_msg_iovecs_nb"

external send_msg_iovecs_connected :
  Unix.file_descr -> 'a Faraday.iovec list -> int
  = "ocaml_quic_eio_send_msg_iovecs_connected"

external send_msg_iovecs_connected_nb :
  Unix.file_descr -> 'a Faraday.iovec list -> int
  = "ocaml_quic_eio_send_msg_iovecs_connected_nb"

type recvfrom_into_nb_result =
  | No_data
  | Same_addr of int
  | New_addr of int * string

external recvfrom_into_nb :
  Unix.file_descr ->
  Bigstringaf.t ->
  int ->
  int ->
  string option ->
  recvfrom_into_nb_result
  = "ocaml_quic_eio_recvfrom_into_nb"

external recv_into_nb : Unix.file_descr -> Bigstringaf.t -> int -> int -> int option
  = "ocaml_quic_eio_recv_into_nb"

type drop_direction =
  [ `Receive
  | `Send
  ]

type drop_packet_kind =
  [ `Initial
  | `Zero_rtt
  | `Handshake
  | `Retry
  | `Short
  | `Unknown
  ]

type should_drop =
  direction:drop_direction -> packet_kind:drop_packet_kind -> seq_no:int -> len:int -> bool

module Addr = struct
  let parsed = Hashtbl.create 16
  let parsed_unix = Hashtbl.create 16
  let tag_unix = Char.chr 0
  let tag_v4 = Char.chr 4
  let tag_v6 = Char.chr 6

  let port_be s off =
    ((Char.code s.[off]) lsl 8) lor Char.code s.[off + 1]

  let encode ~tag raw port =
    let len = 1 + String.length raw + 2 in
    let buf = Bytes.create len in
    Bytes.set buf 0 tag;
    Bytes.blit_string raw 0 buf 1 (String.length raw);
    Bytes.set_uint16_be buf (1 + String.length raw) port;
    Bytes.unsafe_to_string buf

  (* Eio documents [Ipaddr.t] interoperability via raw octets, e.g.
     [Ipaddr.of_octets_exn (eio_ip :> string)]. The direct coercion is not
     accepted here, but the runtime representation is still the raw byte
     string. *)
  let raw_ip (ip : _ Eio.Net.Ipaddr.t) : string = Obj.magic ip

  let serialize : Eio.Net.Sockaddr.datagram -> string = function
    | `Unix path -> String.make 1 tag_unix ^ path
    | `Udp (host, port) ->
      Eio.Net.Ipaddr.fold
        host
        ~v4:(fun ip -> encode ~tag:tag_v4 (raw_ip ip) port)
        ~v6:(fun ip -> encode ~tag:tag_v6 (raw_ip ip) port)

  let decode s =
    match String.get s 0 with
    | tag when tag = tag_unix ->
      `Unix (String.sub s 1 (String.length s - 1))
    | tag when tag = tag_v4 ->
      let host = Eio.Net.Ipaddr.of_raw (String.sub s 1 4) in
      let port = port_be s 5 in
      `Udp (host, port)
    | tag when tag = tag_v6 ->
      let host = Eio.Net.Ipaddr.of_raw (String.sub s 1 16) in
      let port = port_be s 17 in
      `Udp (host, port)
    | _ -> invalid_arg "Quic_eio.Addr.decode"

  let parse (s : string) : Eio.Net.Sockaddr.datagram =
    match Hashtbl.find_opt parsed s with
    | Some addr -> addr
    | None ->
      let addr = decode s in
      Hashtbl.replace parsed s addr;
      addr

  let parse_unix (s : string) : Unix.sockaddr =
    match Hashtbl.find_opt parsed_unix s with
    | Some addr -> addr
    | None ->
      let addr =
        match parse s with
        | `Unix path -> Unix.ADDR_UNIX path
        | `Udp (host, port) ->
          Unix.ADDR_INET (Eio_unix.Net.Ipaddr.to_unix host, port)
      in
      Hashtbl.replace parsed_unix s addr;
      addr
end

module IO_loop = struct
  let now_ms clock = Int64.of_float (Eio.Time.now clock *. 1000.)
  let never_drop ~direction:_ ~packet_kind:_ ~seq_no:_ ~len:_ = false
  let udp_socket_buffer_bytes = 16 * 1024 * 1024

  let configure_udp_socket fd =
    match Eio_unix.Resource.fd_opt fd with
    | Some file_descr ->
      Eio_unix.Fd.use file_descr ~if_closed:(fun () -> ()) (fun fd ->
        Unix.setsockopt_int fd Unix.SO_SNDBUF udp_socket_buffer_bytes;
        Unix.setsockopt_int fd Unix.SO_RCVBUF udp_socket_buffer_bytes)
    | None -> ()

  let classify_received_packet_kind buf ~off ~len =
    if len <= 0
    then `Unknown
    else
      let first_byte = Char.code (Bigstringaf.get buf off) in
      let has_long_header = first_byte land 0x80 <> 0 in
      if not has_long_header
      then `Short
      else if first_byte land 0x40 = 0
      then `Unknown
      else
        match (first_byte lsr 4) land 0x03 with
        | 0 -> `Initial
        | 1 -> `Zero_rtt
        | 2 -> `Handshake
        | 3 -> `Retry
        | _ -> `Unknown

  let classify_sent_packet_kind iovecs =
    match iovecs with
    | [] -> `Unknown
    | { Faraday.buffer; off; len } :: _ ->
      if len <= 0
      then `Unknown
      else
        let first_byte = Char.code (Bigstringaf.get buffer off) in
        let has_long_header = first_byte land 0x80 <> 0 in
        if not has_long_header
        then `Short
        else if first_byte land 0x40 = 0
        then `Unknown
        else
          match (first_byte lsr 4) land 0x03 with
          | 0 -> `Initial
          | 1 -> `Zero_rtt
          | 2 -> `Handshake
          | 3 -> `Retry
          | _ -> `Unknown

  let iovecs_len iovecs =
    List.fold_left
      (fun acc ({ Faraday.len; _ } : _ Faraday.iovec) -> acc + len)
      0
      iovecs

  module Io = struct
    let env_disabled name =
      match Sys.getenv_opt name with
      | Some ("1" | "true" | "yes") -> true
      | _ -> false

    let env_enabled name =
      match Sys.getenv_opt name with
      | Some ("1" | "true" | "yes") -> true
      | _ -> false

    let running_on_linux =
      match Sys.os_type with
      | "Unix" -> Sys.file_exists "/proc/sys/kernel/ostype"
      | _ -> false

    let running_on_macos =
      match Sys.os_type with
      | "Unix" -> Sys.file_exists "/System/Library/CoreServices/SystemVersion.plist"
      | _ -> false

    let udp_fast_path_enabled = not (env_disabled "QUIC_EIO_DISABLE_UDP_FASTPATH")
    let udp_send_fast_path_enabled = udp_fast_path_enabled && not (env_disabled "QUIC_EIO_DISABLE_UDP_SEND_FASTPATH")
    let client_udp_send_fast_path_enabled =
      udp_send_fast_path_enabled
      && ((not running_on_macos) || env_enabled "QUIC_EIO_ENABLE_MACOS_CLIENT_UDP_SEND_FASTPATH")
    let udp_recv_fast_path_enabled =
      udp_fast_path_enabled
      && not (env_disabled "QUIC_EIO_DISABLE_UDP_RECV_FASTPATH")
      &&
      ((not running_on_linux) || env_enabled "QUIC_EIO_ENABLE_LINUX_UDP_RECV_FASTPATH")

    let send_msg_fast_threshold =
      match Sys.getenv_opt "QUIC_EIO_SEND_FAST_THRESHOLD" with
      | None -> 0
      | Some v -> int_of_string v

    let send_msg_nb_threshold =
      match Sys.getenv_opt "QUIC_EIO_SEND_NB_THRESHOLD" with
      | None -> 256
      | Some v -> int_of_string v

    let send_msg_blocking_fallback_threshold =
      match Sys.getenv_opt "QUIC_EIO_SEND_BLOCKING_FALLBACK_THRESHOLD" with
      | None -> max_int
      | Some v -> int_of_string v

    type read_result =
      [ `Read of int * string
      | `Would_block
      | `Exn of exn
      ]

    let read_once dsock buffer last_client_address connected_peer =
      let p, u = Promise.create () in
      (try
         Buffer.put
           ~f:(fun buf ~off ~len k ->
             match Eio_unix.Resource.fd_opt dsock with
             | Some fd when udp_recv_fast_path_enabled ->
                (match
                   Eio_unix.Fd.use fd ~if_closed:(fun () -> None) (fun fd ->
                     match !connected_peer with
                     | Some peer ->
                       Some
                         (match recv_into_nb fd buf off len with
                          | Some n -> New_addr (n, peer)
                          | None -> No_data)
                     | None ->
                       Some
                         (recvfrom_into_nb
                            fd
                            buf
                            off
                            len
                            !last_client_address))
                with
                | Some (New_addr (n, addr)) ->
                  last_client_address := Some addr;
                  Promise.resolve u (`Read (n, addr));
                  k n
                | Some (Same_addr n) ->
                  Promise.resolve u (`Read (n, Option.get !last_client_address));
                  k n
                | Some No_data ->
                  Promise.resolve u `Would_block;
                  raise_notrace Exit
                | None ->
                  Promise.resolve u (`Exn End_of_file);
                  raise End_of_file)
             | Some _ | None ->
               let cstruct = Cstruct.of_bigarray buf ~off ~len in
               match Eio.Net.recv dsock cstruct with
               | addr, n ->
                 Promise.resolve u (`Read (n, Addr.serialize addr));
                 k n
               | exception exn ->
                 Promise.resolve u (`Exn exn);
                 raise exn)
           buffer
           (fun _read -> ())
       with
       | Exit -> ());
      match Promise.await p with
      | `Read result -> result
      | `Would_block -> raise_notrace Exit
      | `Exn exn -> raise exn

    (* let close socket = *)
    (* match Lwt_unix.state socket with *)
    (* | Closed -> Lwt.return_unit *)
    (* | _ -> *)
    (* Lwt.catch *)
    (* (fun () -> *)
    (* Lwt_unix.shutdown socket SHUTDOWN_ALL; *)
    (* Lwt_unix.close socket) *)
    (* (fun _exn -> Lwt.return_unit) *)

    (* let read_inner dsock buffer = *)
    (* let p, u = Promise.create () in *)
    (* let addr_p, addr_u = Promise.create () in *)
    (* Buffer.put *)
    (* ~f:(fun buf ~off ~len k -> *)
    (* match Eio.Net.recv dsock (Cstruct.of_bigarray buf ~off ~len) with *)
    (* | addr, n -> *)
    (* Promise.resolve addr_u addr; *)
    (* k n *)
    (* | exception *)
    (* ( End_of_file *)
    (* | Unix.Unix_error (ENOTCONN, _, _) *)
    (* | Eio.Io (Eio.Net.E (Connection_reset _), _) ) -> *)
    (* (* TODO(anmonteiro): logging? *) *)
    (* k `Eof) *)
    (* buffer *)
    (* (Promise.resolve u); *)
    (* match Promise.await p with *)
    (* | `Eof -> `Eof *)
    (* | `Ok n -> `Ok (n, Promise.await addr_p) *)

    let read ?(connected_peer = ref None) =
      let last_client_address = ref None in
      let read_datagram flow buffer =
        match read_once flow buffer last_client_address connected_peer with
        | r -> r
        | exception Exit -> raise_notrace Exit
        | exception
            ( Unix.Unix_error (ENOTCONN, _, _)
            | Unix.Unix_error (ECONNREFUSED, _, _)
            | Eio.Io (Eio.Exn.X (Eio_unix.Unix_error (ENOTCONN, _, _)), _)
            | Eio.Io (Eio.Exn.X (Eio_unix.Unix_error (ECONNREFUSED, _, _)), _)
            | Eio.Io (Eio.Net.E (Connection_reset _), _) ) ->
          (* TODO(anmonteiro): logging? *)
          raise End_of_file
      in
      let rec read flow buffer =
        match read_datagram flow buffer with
        | r -> r
        | exception Exit ->
          Fiber.yield ();
          read flow buffer
      in
      read

    let writev
          dsock
          ~udp_send_fast_path_enabled
          ~connected_to_peer
          ~client_address
          iovecs
      =
      let lenv =
        List.fold_left (fun acc { Faraday.len; _ } -> acc + len) 0 iovecs
      in
      let fallback_send () =
        let iovecs =
          List.map
            (fun { Faraday.buffer; off; len } -> Cstruct.of_bigarray ~off ~len buffer)
            iovecs
        in
        match
          if connected_to_peer
          then Eio.Net.send dsock iovecs
          else Eio.Net.send dsock ~dst:(Addr.parse client_address) iovecs
        with
        | () -> `Ok lenv
        | exception End_of_file -> `Closed
      in
      if udp_send_fast_path_enabled && lenv >= send_msg_fast_threshold
      then
        match Eio_unix.Resource.fd_opt dsock with
        | Some fd ->
          (match
             Eio_unix.Fd.use fd ~if_closed:(fun () -> None) (fun fd ->
               let sockaddr = Addr.parse_unix client_address in
               if lenv <= send_msg_nb_threshold
               then (
                 try Some (`Ok (send_msg_iovecs_nb fd sockaddr iovecs))
                 with
                 | Unix.Unix_error (Unix.EAGAIN, _, _) ->
                   if lenv >= send_msg_blocking_fallback_threshold
                   then Some (`Ok (send_msg_iovecs fd sockaddr iovecs))
                   else Some `Would_block)
               else
                 try Some (`Ok (send_msg_iovecs_nb fd sockaddr iovecs))
                 with
                 | Unix.Unix_error (Unix.EAGAIN, _, _) ->
                   Some (`Ok (send_msg_iovecs fd sockaddr iovecs)))
           with
           | Some (`Ok _) -> `Ok lenv
           | Some `Would_block -> `Would_block
           | None -> `Closed)
        | None -> fallback_send ()
      else fallback_send ()
  end

  module Runtime = Quic.Transport

  exception Cancelled

  let start
        ~sw:_
        ~clock
        ~read_buffer_size
        ~cancel
        ~should_drop
        ~connect_on_first_peer
        ~connected_peer
        ~udp_send_fast_path_enabled
        t
        socket
    =
    let read_buffer = Buffer.create read_buffer_size in
    let recv_seq_no = ref 0 in
    let send_seq_no = ref 0 in
    let write_burst_limit = 64 in
    let read_once =
      match cancel with
      | None -> (fun () -> Io.read ~connected_peer socket read_buffer)
      | Some cancel ->
        (fun () ->
           Fiber.first
             (fun () -> Io.read ~connected_peer socket read_buffer)
             (fun () ->
                Promise.await cancel;
                raise Cancelled))
    in
    let rec read_loop () =
      let rec read_loop_step () =
        match Runtime.next_read_operation t with
        | `Read ->
          (match read_once () with
          | _n, client_address ->
            (match !connected_peer, connect_on_first_peer with
            | None, true ->
              (match Eio_unix.Resource.fd_opt socket with
              | Some file_descr when Io.udp_send_fast_path_enabled || Io.udp_recv_fast_path_enabled ->
                Eio_unix.Fd.use file_descr ~if_closed:(fun () -> ()) (fun fd ->
                  Unix.connect fd (Addr.parse_unix client_address);
                  connected_peer := Some client_address)
              | Some _ | None -> ())
            | _ -> ());
            let (_ : int) =
              Buffer.get read_buffer ~f:(fun buf ~off ~len ->
                let seq_no = !recv_seq_no in
                incr recv_seq_no;
                let packet_kind = classify_received_packet_kind buf ~off ~len in
                if should_drop ~direction:`Receive ~packet_kind ~seq_no ~len
                then len
                else Runtime.read ~client_address t buf ~off ~len)
            in
            ()
          | exception Cancelled -> ()
          | exception End_of_file ->
            let (_ : int) =
              Buffer.get read_buffer ~f:(fun buf ~off ~len ->
                Runtime.read_eof t buf ~off ~len)
              in
            ());
          read_loop_step ()
        | `Yield ->
          let p, u = Promise.create () in
          Runtime.yield_reader t (Promise.resolve u);
          (match cancel with
          | None -> Promise.await p
          | Some cancel ->
            Fiber.first
              (fun () -> Promise.await p)
              (fun () ->
                 Promise.await cancel;
                 raise Cancelled));
          `Continue
        | `Close -> `Stop
      in
      match read_loop_step () with
      | `Continue -> read_loop ()
      | `Stop -> ()
      | exception Cancelled -> ()
      | exception exn ->
        if Runtime.is_closed t
        then ()
        else (
          Runtime.report_exn t exn;
          Fiber.yield ();
          read_loop ())
    in
    let rec write_loop () =
      let rec write_loop_step writes_since_yield =
        match Runtime.next_write_operation t with
        | `Writev (io_vectors, client_address, cid) ->
          let sent_len = iovecs_len io_vectors in
          let seq_no = !send_seq_no in
          incr send_seq_no;
          let packet_kind = classify_sent_packet_kind io_vectors in
          let write_result =
            if
              should_drop
                ~direction:`Send
                ~packet_kind
                ~seq_no
                ~len:sent_len
            then `Ok sent_len
            else
              (match !connected_peer with
               | Some peer when udp_send_fast_path_enabled && String.equal peer client_address ->
                 (match Eio_unix.Resource.fd_opt socket with
                  | Some fd ->
                    Eio_unix.Fd.use fd ~if_closed:(fun () -> `Closed) (fun fd ->
                      if sent_len <= Io.send_msg_nb_threshold
                      then (
                        try `Ok (send_msg_iovecs_connected_nb fd io_vectors)
                        with
                        | Unix.Unix_error (Unix.EAGAIN, _, _) -> `Would_block
                        | Unix.Unix_error (Unix.ECONNREFUSED, _, _) -> `Would_block
                        | Unix.Unix_error (Unix.ECONNRESET, _, _) -> `Would_block)
                      else
                        try `Ok (send_msg_iovecs_connected_nb fd io_vectors)
                        with
                        | Unix.Unix_error (Unix.EAGAIN, _, _) ->
                          (try `Ok (send_msg_iovecs_connected fd io_vectors)
                           with
                           | Unix.Unix_error (Unix.ECONNREFUSED, _, _) -> `Would_block
                           | Unix.Unix_error (Unix.ECONNRESET, _, _) -> `Would_block)
                        | Unix.Unix_error (Unix.ECONNREFUSED, _, _) -> `Would_block
                        | Unix.Unix_error (Unix.ECONNRESET, _, _) -> `Would_block)
                  | None ->
                    Io.writev
                      ~udp_send_fast_path_enabled
                      ~connected_to_peer:true
                      ~client_address
                      socket
                      io_vectors)
               | _ ->
                 Io.writev
                   ~udp_send_fast_path_enabled
                   ~connected_to_peer:
                     (match !connected_peer with
                      | Some peer -> String.equal peer client_address
                      | None -> false)
                   ~client_address
                   socket
                   io_vectors)
          in
          (match write_result with
          | `Would_block ->
            Fiber.yield ();
            `Continue
          | (`Ok _ | `Closed) as write_result ->
            Runtime.report_write_result t ~cid write_result;
            let writes_since_yield = writes_since_yield + 1 in
            if writes_since_yield >= write_burst_limit
            then (
              Fiber.yield ();
              `Continue)
            else write_loop_step writes_since_yield)
        | `Yield timeout_ms ->
          let wake_p, wake_u = Promise.create () in
          Runtime.yield_writer t (Promise.resolve wake_u);
          let wait_for_timeout () =
            match timeout_ms with
            | None -> Promise.await wake_p
            | Some timeout_ms ->
              Fiber.first
                (fun () -> Promise.await wake_p)
                (fun () ->
                   let now = now_ms clock in
                   if Int64.compare now timeout_ms < 0
                   then
                     Eio.Time.sleep
                       clock
                       (Int64.to_float (Int64.sub timeout_ms now) /. 1000.);
                   Runtime.on_timeout t)
          in
          (match cancel with
          | None -> wait_for_timeout ()
          | Some cancel ->
            Fiber.first
              wait_for_timeout
              (fun () ->
                 Promise.await cancel;
                 raise Cancelled));
          `Continue
        | `Close _ -> `Stop
      in
      match write_loop_step 0 with
      | `Continue -> write_loop ()
      | `Stop -> ()
      | exception Cancelled -> ()
      | exception exn ->
        if Runtime.is_closed t
        then ()
        else (
          Runtime.report_exn t exn;
          Fiber.yield ();
          write_loop ())
    in
    Fiber.both read_loop write_loop
end

module Server = struct
  let establish_server
        env
        ~sw
        ?(should_drop = IO_loop.never_drop)
        ?(udp_connect_first_peer = false)
        ~config
        listen_address
        handler
    =
    let server_fd =
      Eio.Net.datagram_socket
        ~reuse_addr:true
        ~reuse_port:true
        ~sw
        (Eio.Stdenv.net env)
        listen_address
    in
    IO_loop.configure_udp_socket server_fd;
    let clock = Eio.Stdenv.clock env in
    let connection =
      Quic.Transport.Server.create
        ~now_ms:(fun () -> IO_loop.now_ms clock)
        ~config
        handler
    in
    IO_loop.start
      connection
      ~sw
      ~clock
      ~read_buffer_size:(max 0x1000 config.max_datagram_size)
      ~cancel:None
      ~should_drop
      ~connect_on_first_peer:udp_connect_first_peer
      ~connected_peer:(ref None)
      ~udp_send_fast_path_enabled:IO_loop.Io.udp_send_fast_path_enabled
      server_fd
end

type t =
  { transport : Quic.Transport.t
  ; config : Quic.Config.t
  ; shutdown_io : unit -> unit
  ; connect_udp : string -> unit
  }

module Client = struct
  let create
        env
        ~sw
        ?(should_drop = IO_loop.never_drop)
        ?(udp_connect = true)
        ~config
        handler
    =
    let fd =
      Eio.Net.datagram_socket
        ~reuse_addr:true
        ~reuse_port:true
        ~sw
        (Eio.Stdenv.net env)
        `UdpV4
    in
    IO_loop.configure_udp_socket fd;
    let clock = Eio.Stdenv.clock env in
    let connection =
      Quic.Transport.Client.create
        ~now_ms:(fun () -> IO_loop.now_ms clock)
        ~config
        handler
    in
    let connected_peer = ref None in
    let shutdown_io () =
      Quic.Transport.shutdown connection;
      Quic.Transport.ready_to_write connection ();
      try Eio.Resource.close fd with _ -> ()
    in
    let connect_udp address =
      if udp_connect && (IO_loop.Io.client_udp_send_fast_path_enabled || IO_loop.Io.udp_recv_fast_path_enabled)
      then
        match Eio_unix.Resource.fd_opt fd with
        | Some file_descr ->
          Eio_unix.Fd.use file_descr ~if_closed:(fun () -> ()) (fun fd ->
            Unix.connect fd (Addr.parse_unix address);
            connected_peer := Some address)
        | None -> ()
    in
    Fiber.fork ~sw (fun () ->
      IO_loop.start
        ~sw
        ~clock
        ~cancel:None
        ~read_buffer_size:(max 0x1000 config.max_datagram_size)
        ~should_drop
        ~connect_on_first_peer:false
        ~connected_peer
        ~udp_send_fast_path_enabled:IO_loop.Io.client_udp_send_fast_path_enabled
        connection
        fd);
    { transport = connection; config; shutdown_io; connect_udp }
end

let connect t ~address ~host f =
  let address = Addr.serialize address in
  t.connect_udp address;
  let max_datagram_size =
    if t.config.max_datagram_size <> Quic.Config.default_max_datagram_size
    then None
    else
      match Addr.parse address with
      | `Unix _ -> None
      | `Udp (host_ip, _port) ->
        Some
          (Eio.Net.Ipaddr.fold
             host_ip
             ~v4:(fun _ -> 1452)
             ~v6:(fun _ -> 1232))
  in
  Quic.Transport.connect ?max_datagram_size t.transport ~address ~host f

let shutdown t =
  t.shutdown_io ()
