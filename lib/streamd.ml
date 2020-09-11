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

type 'a rd = < rd : unit ; .. > as 'a

type 'a wr = < wr : unit ; .. > as 'a

type _ t =
  { faraday : Faraday.t
  ; mutable read_scheduled : bool
  ; mutable on_eof : unit -> unit
  ; mutable on_read : Bigstringaf.t -> off:int -> len:int -> unit
  ; mutable when_ready : Optional_thunk.t
  ; buffered_bytes : int ref
  }

type rdwr = < rd : unit ; wr : unit >

type ro = < rd : unit >

type wo = < wr : unit >

external ro : 'a rd t -> ro t = "%identity"

external wo : 'a wr t -> wo t = "%identity"

let default_on_eof = Sys.opaque_identity (fun () -> ())

let default_on_read = Sys.opaque_identity (fun _ ~off:_ ~len:_ -> ())

let of_faraday faraday when_ready =
  { faraday
  ; read_scheduled = false
  ; on_eof = default_on_eof
  ; on_read = default_on_read
  ; when_ready
  ; buffered_bytes = ref 0
  }

let create buffer when_ready =
  of_faraday (Faraday.of_bigstring buffer) when_ready

let create_empty () =
  let t = create Bigstringaf.empty Optional_thunk.none in
  Faraday.close t.faraday;
  t

let empty = create_empty ()

let write_char t c = Faraday.write_char t.faraday c

let write_string t ?off ?len s = Faraday.write_string ?off ?len t.faraday s

let write_bigstring t ?off ?len b =
  Faraday.write_bigstring ?off ?len t.faraday b

let schedule_bigstring t ?off ?len (b : Bigstringaf.t) =
  Faraday.schedule_bigstring ?off ?len t.faraday b

let ready t = Optional_thunk.call_if_some t.when_ready

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
