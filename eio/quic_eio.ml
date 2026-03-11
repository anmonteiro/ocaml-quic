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
  (* type t = Eio.Net.Sockaddr.datagram *)

  let parse (s : string) : Eio.Net.Sockaddr.datagram = Marshal.from_string s 0

  let serialize (dgram : Eio.Net.Sockaddr.datagram) = Marshal.to_string dgram []
end

module IO_loop = struct
  let now_ms clock = Int64.of_float (Eio.Time.now clock *. 1000.)
  let never_drop ~direction:_ ~packet_kind:_ ~seq_no:_ ~len:_ = false

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
    let read_once dsock buffer =
      let p, u = Promise.create () in
      let addr_p, addr_u = Promise.create () in
      Buffer.put
        ~f:(fun buf ~off ~len k ->
          let cstruct = Cstruct.of_bigarray buf ~off ~len in
          match Eio.Net.recv dsock cstruct with
          | addr, n ->
            Promise.resolve addr_u addr;
            k n
          | exception exn ->
            Promise.resolve u (`Exn exn);
            raise exn)
        buffer
        (fun read -> Promise.resolve u (`Ok read));
      match Promise.await p with
      | `Ok n -> n, Promise.await addr_p
      | `Exn exn -> raise exn

    let read_datagram flow buffer =
      match read_once flow buffer with
      | r -> r
      | exception
          ( Unix.Unix_error (ENOTCONN, _, _)
          | Eio.Io (Eio.Exn.X (Eio_unix.Unix_error (ENOTCONN, _, _)), _)
          | Eio.Io (Eio.Net.E (Connection_reset _), _) ) ->
        (* TODO(anmonteiro): logging? *)
        raise End_of_file

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

    let rec read flow buffer =
      match read_datagram flow buffer with
      | r -> r
      | exception Unix.Unix_error (Unix.EAGAIN, _, _) ->
        Fiber.yield ();
        read flow buffer

    let writev dsock ~client_address iovecs =
      let lenv =
        List.fold_left (fun acc { Faraday.len; _ } -> acc + len) 0 iovecs
      in
      let cstruct = Cstruct.create lenv in
      let _ =
        List.fold_left
          (fun pos { Faraday.buffer; off; len } ->
             Cstruct.blit
               (Cstruct.of_bigarray ~off ~len buffer)
               0
               cstruct
               pos
               len;
             pos + len)
          0
          iovecs
      in
      match Eio.Net.send dsock ~dst:client_address [ cstruct ] with
      | () -> `Ok lenv
      | exception End_of_file -> `Closed
  end

  module Runtime = Quic.Transport

  exception Cancelled

  let start ~sw:_ ~clock ~read_buffer_size ~cancel ~should_drop t socket =
    let read_buffer = Buffer.create read_buffer_size in
    let recv_seq_no = ref 0 in
    let send_seq_no = ref 0 in
    let read_once =
      match cancel with
      | None -> (fun () -> Io.read socket read_buffer)
      | Some cancel ->
        (fun () ->
           Fiber.first
             (fun () -> Io.read socket read_buffer)
             (fun () ->
                Promise.await cancel;
                raise Cancelled))
    in
    let rec read_loop () =
      let rec read_loop_step () =
        match Runtime.next_read_operation t with
        | `Read ->
          (match read_once () with
          | _n, addr ->
            let (_ : int) =
              Buffer.get read_buffer ~f:(fun buf ~off ~len ->
                let seq_no = !recv_seq_no in
                incr recv_seq_no;
                let packet_kind = classify_received_packet_kind buf ~off ~len in
                if should_drop ~direction:`Receive ~packet_kind ~seq_no ~len
                then len
                else
                  let client_address = Addr.serialize addr in
                  Runtime.read ~client_address t buf ~off ~len)
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
      let rec write_loop_step () =
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
              Io.writev
                ~client_address:(Addr.parse client_address)
                socket
                io_vectors
          in
          Runtime.report_write_result t ~cid write_result;
          write_loop_step ()
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
      match write_loop_step () with
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
      ~read_buffer_size:0x1000
      ~cancel:None
      ~should_drop
      server_fd
end

type t =
  { transport : Quic.Transport.t
  ; shutdown_io : unit -> unit
  }

module Client = struct
  let create env ~sw ?(should_drop = IO_loop.never_drop) ~config handler =
    let fd =
      Eio.Net.datagram_socket
        ~reuse_addr:true
        ~reuse_port:true
        ~sw
        (Eio.Stdenv.net env)
        `UdpV4
    in
    let clock = Eio.Stdenv.clock env in
    let connection =
      Quic.Transport.Client.create
        ~now_ms:(fun () -> IO_loop.now_ms clock)
        ~config
        handler
    in
    let shutdown_io () =
      Quic.Transport.shutdown connection;
      Quic.Transport.ready_to_write connection ();
      try Eio.Resource.close fd with _ -> ()
    in
    Fiber.fork ~sw (fun () ->
      IO_loop.start
        ~sw
        ~clock
        ~cancel:None
        ~read_buffer_size:0x1000
        ~should_drop
        connection
        fd);
    { transport = connection; shutdown_io }
end

let connect t ~address ~host f =
  let address = Addr.serialize address in
  Quic.Transport.connect t.transport ~address ~host f

let shutdown t =
  t.shutdown_io ()
