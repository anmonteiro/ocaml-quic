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

module Buffer = struct
  type t =
    { faraday : Faraday.t
    ; mutable read_scheduled : bool
    ; mutable on_eof : unit -> unit
    ; mutable on_read : Bigstringaf.t -> off:int -> len:int -> unit
    ; when_ready : unit -> unit
    }

  let default_on_eof = Sys.opaque_identity (fun () -> ())

  let default_on_read = Sys.opaque_identity (fun _ ~off:_ ~len:_ -> ())

  let of_faraday faraday when_ready =
    { faraday
    ; read_scheduled = false
    ; on_eof = default_on_eof
    ; on_read = default_on_read
    ; when_ready
    }

  let create buffer when_ready =
    of_faraday (Faraday.of_bigstring buffer) when_ready

  let create_empty () =
    let t = create Bigstringaf.empty ignore in
    Faraday.close t.faraday;
    t

  let empty = create_empty ()

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
    | `Yield ->
      ()
    | `Close ->
      t.read_scheduled <- false;
      t.on_eof <- default_on_eof;
      t.on_read <- default_on_read;
      on_eof ()
    | `Writev [] ->
      assert false
    | `Writev (iovec :: _) ->
      t.read_scheduled <- false;
      t.on_eof <- default_on_eof;
      t.on_read <- default_on_read;
      let { IOVec.buffer; off; len } = iovec in
      Faraday.shift t.faraday len;
      on_read buffer ~off ~len;
      execute_read t

  and execute_read t =
    if t.read_scheduled then do_execute_read t t.on_eof t.on_read

  let schedule_read t ~on_eof ~on_read =
    if t.read_scheduled then
      failwith "Body.schedule_read: reader already scheduled";
    if is_closed t then
      do_execute_read t on_eof on_read
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

      let compare { IOVec.off = off1; _ } { IOVec.off = off2; _ } =
        compare off1 off2
    end)

module Recv = struct
  type t =
    { mutable q : Q.t
    ; mutable offset : int (* TODO: int64? *)
    ; consumer : Buffer.t
    ; mutable fin_offset : int option
    }

  let create () =
    { q = Q.empty
    ; offset = 0
    ; consumer = Buffer.create Bigstringaf.empty ignore
    ; fin_offset = None
    }

  let push ~is_fin ({ IOVec.off; len; _ } as fragment) t =
    (match t.fin_offset with
    | Some fin_off ->
      assert (off <= fin_off)
    | None ->
      ());
    (* From RFC<QUIC-RFC>§2.2:
     *   An endpoint could receive data for a stream at the same stream offset
     *   multiple times. Data that has already been received can be discarded. *)
    if t.offset < off + len then (
      let q' = Q.add off fragment t.q in
      t.q <- q';
      if is_fin then t.fin_offset <- Some off)

  let flush t =
    if Buffer.has_pending_output t.consumer then
      try Buffer.execute_read t.consumer with
      | _exn ->
        (* report_exn t exn *)
        failwith "NYI: Streamd.flush_recv / report_exn"

  let pop t =
    match Q.pop t.q with
    | Some ((off, fragment), q') ->
      if off = t.offset then (
        t.offset <- t.offset + fragment.len;
        t.q <- q';
        if not (Buffer.is_closed t.consumer) then (
          Buffer.schedule_bigstring t.consumer fragment.buffer;
          flush t;
          match t.fin_offset with
          | Some fin_offset ->
            if fin_offset = off then
              Buffer.close_reader t.consumer
          | None ->
            ());
        Some fragment)
      else
        None
    | None ->
      None

  let remove off t =
    let q' = Q.remove off t.q in
    t.q <- q'
end

module Send = struct
  type t =
    { mutable q : Q.t
    ; mutable offset : int (* TODO: int64? *)
    ; producer : Buffer.t
    ; mutable fin_offset : int option
    }

  let push buffer t =
    let len = Bigstringaf.length buffer in
    let fragment = { IOVec.off = t.offset; len; buffer } in
    let q' = Q.add t.offset fragment t.q in
    t.q <- q';
    t.offset <- t.offset + len;
    fragment

  let pop t =
    match Q.pop t.q with
    | Some ((_, fragment), q') ->
      t.q <- q';
      let is_fin =
        match t.fin_offset with
        | None ->
          false
        | Some fin_offset ->
          assert (fin_offset = t.offset);
          fin_offset = t.offset
      in
      Some (fragment, is_fin)
    | None ->
      None

  let pop_exn t =
    match pop t with
    | Some ret ->
      ret
    | None ->
      failwith "Quic.Stream.Send.pop_exn"

  let remove off t =
    let q' = Q.remove off t.q in
    t.q <- q'

  let create when_ready =
    { q = Q.empty
    ; offset = 0
    ; producer = Buffer.create Bigstringaf.empty when_ready
    ; fin_offset = None
    }

  let has_pending_output t =
    (* Force another write poll to make sure that a frame with the fin bit set
       is sent. *)
    (not (Q.is_empty t.q)) || Option.is_none t.fin_offset

  let flush ?(max_bytes = Int.max_int) t =
    let faraday = t.producer.faraday in
    match Faraday.operation faraday with
    | `Yield ->
      0
    | `Close ->
      (match t.fin_offset with
      | None ->
        t.fin_offset <- Some t.offset;
        ignore (push Bigstringaf.empty t : Frame.fragment)
      | Some _ ->
        ());
      0
    | `Writev iovecs ->
      let lengthv = IOVec.lengthv iovecs in
      let writev_len = if max_bytes < lengthv then max_bytes else lengthv in
      List.iter
        (fun { IOVec.buffer; off; len } ->
          (* XXX(anmonteiro): we might have to copy here since we're shifting
             below. *)
          let fragment = Bigstringaf.sub buffer ~off ~len in
          ignore (push fragment t : Frame.fragment))
        iovecs;
      Faraday.shift faraday writev_len;
      writev_len
end

type t =
  { send : Send.t
  ; recv : Recv.t
  ; direction : Frame.Direction.t
  ; id : int64
  }

let create ~direction ~id when_ready =
  { send = Send.create when_ready; recv = Recv.create (); direction; id }

(* These are not consumed by the application, so the `recv` consumer starts out
 * closed. *)
let create_crypto () =
  let recv = { (Recv.create ()) with consumer = Buffer.empty } in
  { send = Send.create ignore; recv; direction = Bidirectional; id = -1L }

(* Public (application layer) API *)
let write_char t c = Buffer.write_char t.send.producer c

let write_string t ?off ?len s = Buffer.write_string t.send.producer ?off ?len s

let write_bigstring t ?off ?len b =
  Buffer.write_bigstring t.send.producer ?off ?len b

let schedule_bigstring t ?off ?len (b : Bigstringaf.t) =
  Buffer.schedule_bigstring t.send.producer ?off ?len b

let flush t k = Buffer.flush t.send.producer k

let close_writer t = Buffer.close_writer t.send.producer

let schedule_read t ~on_eof ~on_read =
  Buffer.schedule_read t.recv.consumer ~on_eof ~on_read

let close_reader t = Buffer.close_reader t.recv.consumer

let is_closed t =
  Buffer.is_closed t.recv.consumer && Buffer.is_closed t.send.producer
