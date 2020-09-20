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

open Lwt.Infix

module Buffer : sig
  type t

  val create : int -> t

  val get : t -> f:(Bigstringaf.t -> off:int -> len:int -> int) -> int

  val put
    :  t
    -> f:
         (Bigstringaf.t
          -> off:int
          -> len:int
          -> [ `Eof | `Ok of int * Unix.sockaddr ] Lwt.t)
    -> [ `Eof | `Ok of int * Unix.sockaddr ] Lwt.t
end = struct
  type t =
    { buffer : Bigstringaf.t
    ; mutable off : int
    ; mutable len : int
    }

  let create size =
    let buffer = Bigstringaf.create size in
    { buffer; off = 0; len = 0 }

  let compress t =
    if t.len = 0 then (
      t.off <- 0;
      t.len <- 0)
    else if t.off > 0 then (
      Bigstringaf.blit t.buffer ~src_off:t.off t.buffer ~dst_off:0 ~len:t.len;
      t.off <- 0)

  let get t ~f =
    let n = f t.buffer ~off:t.off ~len:t.len in
    t.off <- t.off + n;
    t.len <- t.len - n;
    if t.len = 0 then
      t.off <- 0;
    n

  let put t ~f =
    compress t;
    f t.buffer ~off:(t.off + t.len) ~len:(Bigstringaf.length t.buffer - t.len)
    >|= function
    | `Eof ->
      `Eof
    | `Ok (n, _) as ret ->
      t.len <- t.len + n;
      ret
end

let _pp_addr = function
  | Lwt_unix.ADDR_UNIX s ->
    s
  | ADDR_INET (addr, port) ->
    Unix.string_of_inet_addr addr ^ ":" ^ string_of_int port

module IO_loop = struct
  module Io = struct
    let close socket =
      match Lwt_unix.state socket with
      | Closed ->
        Lwt.return_unit
      | _ ->
        Lwt.catch
          (fun () ->
            Lwt_unix.shutdown socket SHUTDOWN_ALL;
            Lwt_unix.close socket)
          (fun _exn -> Lwt.return_unit)

    let read socket bigstring ~off ~len =
      Lwt.catch
        (fun () ->
          Lwt_bytes.recvfrom socket bigstring off len [] >|= function
          | 0, _ ->
            `Eof
          | n, addr ->
            `Ok (n, addr))
        (function
          | Unix.Unix_error (Unix.EBADF, _, _) ->
            (* If the socket is closed we need to feed EOF to the state machine. *)
            Lwt.return `Eof
          | exn ->
            Lwt.async (fun () -> close socket);
            Lwt.fail exn)

    let writev fd ~client_address iovecs =
      Lwt.catch
        (fun () ->
          let lwt_iovecs = Lwt_unix.IO_vectors.create () in
          List.iter
            (fun { Faraday.buffer; off; len } ->
              Lwt_unix.IO_vectors.append_bigarray lwt_iovecs buffer off len)
            iovecs;
          Lwt_unix.send_msgto
            ~socket:fd
            ~io_vectors:lwt_iovecs
            ~fds:[]
            ~dest:client_address
          >|= fun n -> `Ok n)
        (function
          | Unix.Unix_error (Unix.EBADF, "check_descriptor", _) ->
            Lwt.return `Closed
          | exn ->
            Lwt.fail exn)

    let shutdown socket command =
      if Lwt_unix.state socket <> Lwt_unix.Closed then
        try Lwt_unix.shutdown socket command with
        | Unix.Unix_error (Unix.ENOTCONN, _, _) ->
          ()

    let shutdown_receive socket = shutdown socket Unix.SHUTDOWN_RECEIVE
  end

  module Runtime = Quic.Server_connection

  let start t ~read_buffer_size socket =
    let read_buffer = Buffer.create read_buffer_size in
    let read_loop_exited, notify_read_loop_exited = Lwt.wait () in
    let rec read_loop () =
      let rec read_loop_step () =
        match Runtime.next_read_operation t with
        | `Read ->
          Buffer.put read_buffer ~f:(fun buf ~off ~len ->
              Io.read socket buf ~off ~len)
          >>= ( function
          | `Eof ->
            Buffer.get read_buffer ~f:(fun bigstring ~off ~len ->
                Runtime.read_eof t bigstring ~off ~len)
            |> ignore;
            read_loop_step ()
          | `Ok (_, client_address) ->
            Buffer.get read_buffer ~f:(fun bigstring ~off ~len ->
                Runtime.read t ~client_address bigstring ~off ~len)
            |> ignore;
            read_loop_step () )
        | `Yield ->
          Runtime.yield_reader t read_loop;
          Lwt.return_unit
        | `Close ->
          Lwt.wakeup_later notify_read_loop_exited ();
          Io.shutdown_receive socket;
          Lwt.return_unit
      in
      Lwt.async read_loop_step
      (* (fun () -> Lwt.catch read_loop_step (fun exn -> Format.eprintf "read
         EXN: %s@." (Printexc.to_string exn); Runtime.report_exn t exn;
         Lwt.return_unit)) *)
    in
    let write_loop_exited, notify_write_loop_exited = Lwt.wait () in
    let rec write_loop () =
      let rec write_loop_step () =
        match Runtime.next_write_operation t with
        | `Writev (io_vectors, client_address, cid) ->
          Io.writev socket ~client_address io_vectors >>= fun result ->
          Runtime.report_write_result t ~cid result;
          write_loop_step ()
        | `Yield ->
          Runtime.yield_writer t write_loop;
          Lwt.return_unit
        | `Close _ ->
          Lwt.wakeup_later notify_write_loop_exited ();
          Lwt.return_unit
      in
      Lwt.async write_loop_step
      (* (fun () -> *)
      (* Lwt.catch write_loop_step (fun exn -> *)
      (* Format.eprintf "write EXN: %s@." (Printexc.to_string exn); *)
      (* Runtime.report_exn t exn; *)
      (* Lwt.return_unit)) *)
    in
    read_loop ();
    write_loop ();
    Lwt.join [ read_loop_exited; write_loop_exited ] >>= fun () ->
    Io.close socket
end

module Server = struct
  let establish_server ~config listen_address handler =
    let server_fd =
      Lwt_unix.socket (Unix.domain_of_sockaddr listen_address) Unix.SOCK_DGRAM 0
    in
    Lwt_unix.bind server_fd listen_address >>= fun () ->
    let connection = Quic.Server_connection.create ~config handler in
    IO_loop.start connection ~read_buffer_size:0x1000 server_fd
end
