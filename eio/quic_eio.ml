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

module Addr = struct
  (* type t = Eio.Net.Sockaddr.datagram *)

  let parse s =
    match String.split_on_char ':' s with
    | [] -> assert false
    | port :: xs ->
      `Udp (Eio.Net.Ipaddr.of_raw (String.concat "" xs), int_of_string port)

  let serialize (dgram : Eio.Net.Sockaddr.datagram) =
    match dgram with
    | `Udp (addr, port) ->
      Format.asprintf "%d:%s" port (Obj.magic addr : string)
    | `Unix _ -> failwith "NYI"
end

module IO_loop = struct
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
      | `Exn exn ->
        Format.eprintf "exn: %s@." (Printexc.to_string exn);
        assert false

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
               off
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

  let start :
     sw:Eio.Switch.t
    -> read_buffer_size:int
    -> cancel:unit Promise.t
    -> Runtime.t
    -> _ (* < Eio.Net.datagram_socket ; Eio.Flow.close > *)
    -> unit
    =
   fun ~sw:_ ~read_buffer_size ~cancel:_ t socket ->
    let read_buffer = Buffer.create read_buffer_size in
    let rec read_loop () =
      let rec read_loop_step () =
        match Runtime.next_read_operation t with
        | `Read ->
          (match Io.read socket read_buffer with
          | _n, addr ->
            let (_ : int) =
              Buffer.get read_buffer ~f:(fun buf ~off ~len ->
                let client_address = Addr.serialize addr in
                Runtime.read ~client_address t buf ~off ~len)
            in
            ()
          | exception End_of_file ->
            let (_ : int) =
              Buffer.get read_buffer ~f:(fun buf ~off ~len ->
                Runtime.read_eof t buf ~off ~len)
            in
            ());
          (* let read_result = Fiber.first (fun () -> Io.read socket
             read_buffer) (fun () -> Promise.await cancel; `Eof) in *)
          read_loop_step ()
        | `Yield ->
          let p, u = Promise.create () in
          Runtime.yield_reader t (Promise.resolve u);
          Promise.await p;
          read_loop ()
        | `Close -> ()
        (* shutdown socket `Receive *)
      in
      match read_loop_step () with
      | () -> ()
      | exception exn -> Runtime.report_exn t exn
    in
    let rec write_loop () =
      let rec write_loop_step () =
        match Runtime.next_write_operation t with
        | `Writev (io_vectors, client_address, cid) ->
          let write_result =
            Io.writev
              ~client_address:(Addr.parse client_address)
              socket
              io_vectors
          in
          Runtime.report_write_result t ~cid write_result;
          write_loop_step ()
        | `Yield ->
          let p, u = Promise.create () in
          Runtime.yield_writer t (Promise.resolve u);
          Promise.await p;
          write_loop ()
        | `Close _ -> ()
        (* shutdown socket `Send *)
      in
      match write_loop_step () with
      | () -> ()
      | exception exn -> Runtime.report_exn t exn
    in
    Fiber.both read_loop write_loop
end

module Server = struct
  let establish_server env ~sw ~config listen_address handler =
    let server_fd =
      Eio.Net.datagram_socket
        ~reuse_addr:true
        ~reuse_port:true
        ~sw
        (Eio.Stdenv.net env)
        listen_address
    in
    let never, _ = Promise.create () in
    let connection = Quic.Transport.Server.create ~config handler in
    IO_loop.start
      connection
      ~sw
      ~read_buffer_size:0x1000
      ~cancel:never
      server_fd
end

type t = Quic.Transport.t

module Client = struct
  let create env ~sw ~config handler =
    let fd =
      Eio.Net.datagram_socket
        ~reuse_addr:true
        ~reuse_port:true
        ~sw
        (Eio.Stdenv.net env)
        `UdpV4
    in
    let connection = Quic.Transport.Client.create ~config handler in
    let _shutdown_p, shutdown_u = Promise.create () in
    let cancel_reader, _resolve_cancel_reader = Promise.create () in
    Fiber.fork ~sw (fun () ->
      Fun.protect ~finally:(Promise.resolve shutdown_u) (fun () ->
        Switch.run (fun sw ->
          Fiber.fork ~sw (fun () ->
            IO_loop.start
              ~sw
              ~cancel:cancel_reader
              ~read_buffer_size:0x1000
              connection
              fd))));
    connection
end

let connect t ~address ~host f =
  let address = Addr.serialize address in
  Quic.Transport.connect t ~address ~host f

let shutdown t = Quic.Transport.shutdown t
