(*----------------------------------------------------------------------------
 *  Copyright (c) 2020 António Nuno Monteiro
 *
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 *
 *  3. Neither the name of the copyright holder nor the names of its
 *  contributors may be used to endorse or promote products derived from this
 *  software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *---------------------------------------------------------------------------*)

module Writer = Serialize.Writer

module Type = struct
  type t =
    | Client of Direction.t
    | Server of Direction.t

  let classify t =
    let direction = Direction.classify t in
    if Stream_id.is_server_initiated t
    then Server direction
    else (
      assert (Stream_id.is_client_initiated t);
      Client direction)

  (* From RFC<QUIC-RFC>§2.1:
   *   Bits Stream Type
   *   0x0  Client-Initiated, Bidirectional
   *   0x1  Server-Initiated, Bidirectional
   *   0x2  Client-Initiated, Unidirectional
   *   0x3  Server-Initiated, Unidirectional *)
  let serialize = function
    | Client Bidirectional -> 0x0L
    | Server Bidirectional -> 0x1L
    | Client Unidirectional -> 0x2L
    | Server Unidirectional -> 0x3L

  let gen_id ~typ id = Int64.logor (Int64.shift_left id 2) (serialize typ)
end

module Buffer = struct
  type t =
    { faraday : Faraday.t
    ; mutable read_scheduled : bool
    ; mutable on_eof : unit -> unit
    ; mutable on_read : Bigstringaf.t -> off:int -> len:int -> unit
    ; done_reading : int -> unit
    ; when_ready : unit -> unit
    }

  let default_on_eof = Sys.opaque_identity (fun () -> ())
  let default_on_read = Sys.opaque_identity (fun _ ~off:_ ~len:_ -> ())
  let default_done_reading = Sys.opaque_identity (fun _ -> ())

  let of_faraday ?(done_reading = default_done_reading) faraday when_ready =
    { faraday
    ; read_scheduled = false
    ; on_eof = default_on_eof
    ; on_read = default_on_read
    ; done_reading
    ; when_ready
    }

  let create ?done_reading buffer when_ready =
    of_faraday ?done_reading (Faraday.of_bigstring buffer) when_ready

  let create_empty () =
    let t = create Bigstringaf.empty ignore in
    Faraday.close t.faraday;
    t

  let empty = create_empty ()
  let write_uint8 t c = Faraday.write_uint8 t.faraday c
  let write_char t c = Faraday.write_char t.faraday c
  let write_string t ?off ?len s = Faraday.write_string ?off ?len t.faraday s

  let write_bigstring t ?off ?len b =
    Faraday.write_bigstring ?off ?len t.faraday b

  let schedule_bigstring t ?off ?len (b : Bigstringaf.t) =
    Faraday.schedule_bigstring ?off ?len t.faraday b

  let ready t = t.when_ready ()

  let flush t kontinue =
    Faraday.flush t.faraday kontinue;
    ready t

  let is_closed t = Faraday.is_closed t.faraday

  let close_writer t =
    Faraday.close t.faraday;
    ready t

  let unsafe_faraday t = t.faraday

  let rec do_execute_read t on_eof on_read =
    match Faraday.operation t.faraday with
    | `Yield -> ()
    | `Close ->
      t.read_scheduled <- false;
      t.on_eof <- default_on_eof;
      t.on_read <- default_on_read;
      on_eof ()
    | `Writev [] -> assert false
    | `Writev (iovec :: _) ->
      t.read_scheduled <- false;
      t.on_eof <- default_on_eof;
      t.on_read <- default_on_read;
      let { IOVec.buffer; off; len } = iovec in
      Faraday.shift t.faraday len;
      on_read buffer ~off ~len;
      t.done_reading len;
      execute_read t

  and execute_read t =
    if t.read_scheduled then do_execute_read t t.on_eof t.on_read

  let schedule_read t ~on_eof ~on_read =
    if t.read_scheduled
    then failwith "Body.schedule_read: reader already scheduled";
    if is_closed t
    then do_execute_read t on_eof on_read
    else (
      t.read_scheduled <- true;
      t.on_eof <- on_eof;
      t.on_read <- on_read;
      ready t)

  let is_read_scheduled t = t.read_scheduled
  let has_pending_output t = Faraday.has_pending_output t.faraday

  let close_reader t =
    Faraday.close t.faraday;
    execute_read t;
    ready t
end

(* From RFC<QUIC-RFC>§2.2:
 *   Endpoints MUST be able to deliver stream data to an application as an
 *   ordered byte-stream. Delivering an ordered byte-stream requires that an
 *   endpoint buffer any data that is received out of order, up to the
 *   advertised flow control limit. *)

module Q : Psq.S with type k = int and type p = Frame.fragment =
  Psq.Make
    (Int)
    (struct
      type t = Frame.fragment

      let compare { Frame.off = off1; _ } { Frame.off = off2; _ } =
        compare off1 off2
    end)

module Recv = struct
  type t =
    { mutable q : Q.t
    ; mutable offset : int (* TODO: int64? *)
    ; consumer : Buffer.t
    ; mutable fin_offset : int option
    }

  module State = struct
    type t =
      | Recv
      | Size_known
      | Data_recvd
      | Data_read
      | Reset_recvd
      | Reset_read
  end

  let create ?(done_reading = fun _ -> ()) () =
    { q = Q.empty
    ; offset = 0
    ; consumer = Buffer.create ~done_reading Bigstringaf.empty ignore
    ; fin_offset = None
    }

  let push ~is_fin ({ Frame.off; len; _ } as fragment) t =
    (match t.fin_offset with
    | Some fin_off -> assert (off <= fin_off)
    | None -> ());
    if is_fin then t.fin_offset <- Some (off + len);
    (* From RFC<QUIC-RFC>§2.2:
     *   An endpoint could receive data for a stream at the same stream offset
     *   multiple times. Data that has already been received can be discarded. *)
    if t.offset < off + len || (is_fin && len = 0)
    then
      let fragment =
        if off >= t.offset || len = 0
        then fragment
        else
          let drop_prefix = t.offset - off in
          let len = len - drop_prefix in
          { Frame.off = t.offset
          ; len
          ; payload = fragment.payload
          ; payload_off = fragment.payload_off + drop_prefix
          }
      in
      let q' = Q.add fragment.off fragment t.q in
      t.q <- q'

  let flush t =
    if Buffer.has_pending_output t.consumer
    then (
      try Buffer.execute_read t.consumer with
      | exn ->
        let bt = Printexc.get_raw_backtrace () in
        let bt_s = Printexc.raw_backtrace_to_string bt in
        Format.eprintf
          "REAL EXN: %s@.%s@."
          (Printexc.to_string exn)
          (if String.length bt_s = 0 then "(no backtrace captured)" else bt_s);
        failwith "NYI: Streamd.flush_recv / report_exn")

  let rec pop t =
    let close_if_finished () =
      if not (Buffer.is_closed t.consumer)
      then
        match t.fin_offset with
        | Some fin_offset when fin_offset = t.offset -> Buffer.close_reader t.consumer
        | _ -> ()
    in
    match Q.pop t.q with
    | Some ((off, fragment), q') ->
      if off > t.offset
      then None
      else (
        t.q <- q';
        let fragment =
          if off = t.offset || fragment.len = 0
          then fragment
          else
            let drop_prefix = t.offset - off in
            let len = fragment.len - drop_prefix in
            { Frame.off = t.offset
            ; len
            ; payload = fragment.payload
            ; payload_off = fragment.payload_off + drop_prefix
            }
        in
        if fragment.len = 0
        then (
          close_if_finished ();
          pop t)
        else (
          t.offset <- t.offset + fragment.len;
          if not (Buffer.is_closed t.consumer)
          then (
            Buffer.write_string
              t.consumer
              ~off:fragment.payload_off
              ~len:fragment.len
              fragment.payload;
            flush t;
            close_if_finished ());
          Some fragment))
    | None -> None

  let drain t ~f =
    let close_if_finished () =
      if not (Buffer.is_closed t.consumer)
      then
        match t.fin_offset with
        | Some fin_offset when fin_offset = t.offset -> Buffer.close_reader t.consumer
        | _ -> ()
    in
    let rec loop () =
      match Q.pop t.q with
      | Some ((off, fragment), q') ->
        if off > t.offset
        then ()
        else (
          t.q <- q';
          let fragment =
            if off = t.offset || fragment.len = 0
            then fragment
            else
              let drop_prefix = t.offset - off in
              let len = fragment.len - drop_prefix in
              { Frame.off = t.offset
              ; len
              ; payload = fragment.payload
              ; payload_off = fragment.payload_off + drop_prefix
              }
          in
          if fragment.len = 0
          then (
            close_if_finished ();
            loop ())
          else (
            t.offset <- t.offset + fragment.len;
            if not (Buffer.is_closed t.consumer)
            then (
              Buffer.write_string
                t.consumer
                ~off:fragment.payload_off
                ~len:fragment.len
                fragment.payload;
              flush t;
              close_if_finished ());
            f fragment;
            loop ()))
      | None -> ()
    in
    loop ()

  let remove off t =
    let q' = Q.remove off t.q in
    t.q <- q'
end

module Send = struct
  let max_buffered_bytes = 4 * 1024 * 1024

  type t =
    { mutable deferred_head : Frame.fragment option
    ; mutable deferred : Q.t
    ; fresh : Frame.fragment Queue.t
    ; mutable offset : int (* TODO: int64? *)
    ; mutable buffered_bytes : int
    ; producer : Buffer.t
    ; mutable fin_offset : int option
    }

  module State = struct
    type t =
      | Ready
      | Send
      | Data_sent
      | Data_recvd
      | Reset_sent
      | Reset_recvd
  end

  let push payload t =
    let len = String.length payload in
    let fragment = { Frame.off = t.offset; len; payload; payload_off = 0 } in
    Queue.add fragment t.fresh;
    t.offset <- t.offset + len;
    t.buffered_bytes <- t.buffered_bytes + len;
    fragment

  let pop t =
    let next_fragment () =
      match t.deferred_head with
      | Some fragment ->
        t.deferred_head <- None;
        t.buffered_bytes <- t.buffered_bytes - fragment.len;
        Some fragment
      | None ->
        (match Q.pop t.deferred with
         | Some ((_off, fragment), q') ->
           t.deferred <- q';
           t.buffered_bytes <- t.buffered_bytes - fragment.len;
           Some fragment
         | None ->
           if Queue.is_empty t.fresh
           then None
           else (
             let fragment = Queue.take t.fresh in
             t.buffered_bytes <- t.buffered_bytes - fragment.len;
             Some fragment))
    in
    match next_fragment () with
    | Some fragment ->
      let is_fin =
        match t.fin_offset with
        | None -> false
        | Some fin_offset ->
          assert (fin_offset = t.offset);
          Option.is_none t.deferred_head
          && Q.is_empty t.deferred
          && Queue.is_empty t.fresh
      in
      Some (fragment, is_fin)
    | None -> None

  let pop_exn t =
    match pop t with
    | Some ret -> ret
    | None -> failwith "Quic.Stream.Send.pop_exn"

  let remove off t =
    match t.deferred_head with
    | Some fragment when fragment.Frame.off = off ->
      t.deferred_head <- None;
      t.buffered_bytes <- t.buffered_bytes - fragment.len
    | Some _ | None ->
      (match Q.find off t.deferred with
      | Some fragment ->
        t.buffered_bytes <- t.buffered_bytes - fragment.len;
        t.deferred <- Q.remove off t.deferred
      | None -> ())

  let requeue fragment t =
    (match t.deferred_head with
    | None -> t.deferred_head <- Some fragment
    | Some current when fragment.Frame.off < current.Frame.off ->
      t.deferred <- Q.add current.Frame.off current t.deferred;
      t.deferred_head <- Some fragment
    | Some _ ->
      t.deferred <- Q.add fragment.Frame.off fragment t.deferred);
    t.buffered_bytes <- t.buffered_bytes + fragment.len

  let create when_ready =
    { deferred_head = None
    ; deferred = Q.empty
    ; fresh = Queue.create ()
    ; offset = 0
    ; buffered_bytes = 0
    ; producer =
        (* TODO: configurable size? *)
        Buffer.create (Bigstringaf.create 0x1000) when_ready
    ; fin_offset = None
    }

  let has_pending_output t =
    (* Force another write poll to make sure that a frame with the fin bit set
       is sent. *)
    Option.is_some t.deferred_head
    || not (Q.is_empty t.deferred)
    || not (Queue.is_empty t.fresh)
    || Buffer.has_pending_output t.producer

  (* TODO: this is probably not needed? *)
  (* || Option.is_none t.fin_offset *)

  let flush ?(max_bytes = Int.max_int) t =
    let faraday = t.producer.faraday in
    match Faraday.operation faraday with
    | `Yield -> 0
    | `Close ->
      (match t.fin_offset with
      | None ->
        t.fin_offset <- Some t.offset;
        ignore (push "" t : Frame.fragment)
      | Some _ -> ());
      0
    | `Writev iovecs ->
      let lengthv = IOVec.lengthv iovecs in
      let room = max 0 (max_buffered_bytes - t.buffered_bytes) in
      let writev_len = min room (min max_bytes lengthv) in
      if writev_len = 0
      then 0
      else (
        let remaining = ref writev_len in
        List.iter
          (fun { IOVec.buffer; off; len } ->
             if !remaining > 0
             then
               let take = min len !remaining in
               if take > 0
               then (
                 (* Copy before shifting Faraday's internal buffer; otherwise
                    queued fragments can alias mutable storage and get corrupted. *)
                 let fragment = Bigstringaf.substring buffer ~off ~len:take in
                 ignore (push fragment t : Frame.fragment);
                 remaining := !remaining - take))
          iovecs;
        Faraday.shift faraday writev_len;
        writev_len)

  let final_size t =
    (* From RFC9000§4.5:
     *   More generally, this is one higher than the offset of the byte with
     *   the largest offset sent on the stream, or zero if no bytes were sent.
     *)
    t.offset
end

type t =
  { send : Send.t
  ; recv : Recv.t
  ; typ : Type.t
  ; id : int64
  ; peer_address : string option
  ; mutable error_handler : int -> unit
  ; report_application_error : int -> unit
  }

let default_error_handler _ = ()

let create
      ~typ
      ~id
      ?peer_address
      ~report_application_error
      ?(on_bytes_read = ignore)
      when_ready
  =
  { send = Send.create when_ready
  ; recv = Recv.create ~done_reading:on_bytes_read ()
  ; typ
  ; id
  ; peer_address
  ; error_handler = default_error_handler
  ; report_application_error
  }

(* These are not consumed by the application, so the `recv` consumer starts out
 * closed. *)
let create_crypto () =
  let recv = { (Recv.create ()) with consumer = Buffer.empty } in
  { send = Send.create ignore
  ; recv
  ; typ = Server Bidirectional
  ; id = -1L
  ; peer_address = None
  ; error_handler = default_error_handler
  ; report_application_error = default_error_handler
  }

let id { id; _ } = id

let direction { typ; _ } =
  match typ with Client direction | Server direction -> direction

let peer_address { peer_address; _ } = peer_address

(* Public (application layer) API *)
let write_uint8 t c = Buffer.write_uint8 t.send.producer c
let write_char t c = Buffer.write_char t.send.producer c
let write_string t ?off ?len s = Buffer.write_string t.send.producer ?off ?len s

let write_bigstring t ?off ?len b =
  Buffer.write_bigstring t.send.producer ?off ?len b

let schedule_bigstring t ?off ?len (b : Bigstringaf.t) =
  Buffer.schedule_bigstring t.send.producer ?off ?len b

let unsafe_faraday t = Buffer.unsafe_faraday t.send.producer
let flush t k = Buffer.flush t.send.producer k
let close_writer t = Buffer.close_writer t.send.producer

let schedule_read t ~on_eof ~on_read =
  Buffer.schedule_read t.recv.consumer ~on_eof ~on_read

let close_reader t = Buffer.close_reader t.recv.consumer

let is_closed t =
  Buffer.is_closed t.recv.consumer && Buffer.is_closed t.send.producer

let report_application_error t code = t.report_application_error code
