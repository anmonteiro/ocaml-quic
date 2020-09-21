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

module Writer = Serialize.Writer

type _ t =
  { writer : Quic.Stream.t
  ; mutable read_scheduled : bool
  ; mutable write_final_data_frame : bool
  ; mutable on_eof : unit -> unit
  ; mutable on_read : Bigstringaf.t -> off:int -> len:int -> unit
  ; buffered_bytes : int ref
  }

let default_on_eof = Sys.opaque_identity (fun () -> ())

let default_on_read = Sys.opaque_identity (fun _ ~off:_ ~len:_ -> ())

let create writer =
  { writer
  ; read_scheduled = false
  ; write_final_data_frame = true
  ; on_eof = default_on_eof
  ; on_read = default_on_read
  ; buffered_bytes = ref 0
  }

let write_char t c = Quic.Stream.write_char t.writer c

let write_string t ?off ?len s = Quic.Stream.write_string t.writer ?off ?len s

let write_bigstring t ?off ?len b =
  Quic.Stream.write_bigstring ?off ?len t.writer b

let schedule_bigstring t ?off ?len (b : Bigstringaf.t) =
  Quic.Stream.schedule_bigstring ?off ?len t.writer b

let flush t kontinue = Quic.Stream.flush t.writer kontinue

let is_closed t = Quic.Stream.is_closed t.writer

let close_writer t = Quic.Stream.close_writer t.writer

let unsafe_faraday t = Quic.Stream.unsafe_faraday t.writer

let schedule_read t ~on_eof ~on_read =
  Quic.Stream.schedule_read t.writer ~on_eof ~on_read

let close_reader t = Quic.Stream.close_reader t.writer
