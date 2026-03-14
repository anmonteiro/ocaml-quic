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

type transport_parameters =
  { initial_max_data : int
  ; max_idle_timeout : int
  ; initial_max_stream_data_bidi_local : int
  ; initial_max_stream_data_bidi_remote : int
  ; initial_max_stream_data_uni : int
  ; initial_max_streams_bidi : int
  ; initial_max_streams_uni : int
  }

let default_transport_parameters =
  { initial_max_data = 1 lsl 27
  ; max_idle_timeout = 30_000
  ; initial_max_stream_data_bidi_local = 1 lsl 27
  ; initial_max_stream_data_bidi_remote = 1 lsl 27
  ; initial_max_stream_data_uni = 1 lsl 27
  ; initial_max_streams_bidi = 1 lsl 8
  ; initial_max_streams_uni = 1 lsl 8
  }

let default_max_datagram_size = 1200

type t =
  { certificates : Tls.Config.own_cert
  ; alpn_protocols : string list (* ; authenticator : X509.Authenticator.t *)
  ; transport_parameters : transport_parameters
  ; max_datagram_size : int
  }

let null_auth ?ip:_ ~host:_ _certs = Ok None
