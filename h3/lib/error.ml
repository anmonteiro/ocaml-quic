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

module Code = struct
  type t =
    | (* From RFC<HTTP3-RFC>§8.1:
       *   H3_NO_ERROR (0x100): No error. This is used when the connection or
       *   stream needs to be closed, but there is no error to signal. *)
        No_error
    | (* From RFC<HTTP3-RFC>§8.1:
       *   H3_GENERAL_PROTOCOL_ERROR (0x101): Peer violated protocol requirements in
       *   a way that does not match a more specific error code, or endpoint
       *   declines to use the more specific error code. *)
        General_protocol_error
    | (* From RFC<HTTP3-RFC>§8.1:
       *   H3_INTERNAL_ERROR (0x102): An internal error has occurred in the HTTP
       *   stack. *)
        Internal_error
    | (* From RFC<HTTP3-RFC>§8.1:
       *   H3_STREAM_CREATION_ERROR (0x103): The endpoint detected that its peer
       *   created a stream that it will not accept. *)
        Stream_creation_error
    | (* From RFC<HTTP3-RFC>§8.1:
       *   H3_CLOSED_CRITICAL_STREAM (0x104): A stream required by the connection
       *   was closed or reset. *)
        Closed_critical_stream
    | (* From RFC<HTTP3-RFC>§8.1:
       *   H3_FRAME_UNEXPECTED (0x105): A frame was received that was not
       *   permitted in the current state or on the current stream. *)
        Frame_unexpected
    | (* From RFC<HTTP3-RFC>§8.1:
       *   H3_FRAME_ERROR (0x106): A frame that fails to satisfy layout
       *   requirements or with an invalid size was received. *)
        Frame_error
    | (* From RFC<HTTP3-RFC>§8.1:
       *   H3_EXCESSIVE_LOAD (0x107): The endpoint detected that its peer is
       *   exhibiting a behavior that might be generating excessive load. *)
        Excessive_load
    | (* From RFC<HTTP3-RFC>§8.1:
       *   H3_ID_ERROR (0x108): A Stream ID or Push ID was used incorrectly, such
       *   as exceeding a limit, reducing a limit, or being reused. *)
        Id_error
    | (* From RFC<HTTP3-RFC>§8.1:
       *   H3_SETTINGS_ERROR (0x109): An endpoint detected an error in the
       *   payload of a SETTINGS frame. *)
        Settings_error
    | (* From RFC<HTTP3-RFC>§8.1:
       *   H3_MISSING_SETTINGS (0x10a): No SETTINGS frame was received at the
       *   beginning of the control stream. *)
        Missing_settings
    | (* From RFC<HTTP3-RFC>§8.1:
       *   H3_REQUEST_REJECTED (0x10b): A server rejected a request without
       *   performing any application processing. *)
        Request_rejected
    | (* From RFC<HTTP3-RFC>§8.1:
       * H3_REQUEST_CANCELLED (0x10c): The request or its response (including
       * pushed response) is cancelled. *)
        Request_cancelled
    | (* From RFC<HTTP3-RFC>§8.1:
       *   H3_REQUEST_INCOMPLETE (0x10d): The client's stream terminated without
       *   containing a fully-formed request. *)
        Request_incomplete
    | (* From RFC<HTTP3-RFC>§8.1:
       *   H3_CONNECT_ERROR (0x10f): The connection established in response to a
       *   CONNECT request was reset or abnormally closed. *)
        Connect_error
    | (* From RFC<HTTP3-RFC>§8.1:
       * H3_VERSION_FALLBACK (0x110): The requested operation cannot be served
       * over HTTP/3. The peer should retry over HTTP/1.1. *)
        Version_fallback
    | Unknown_error of int

  let parse = function
    | 0x100 ->
      No_error
    | 0x101 ->
      General_protocol_error
    | 0x102 ->
      Internal_error
    | 0x103 ->
      Stream_creation_error
    | 0x104 ->
      Closed_critical_stream
    | 0x105 ->
      Frame_unexpected
    | 0x106 ->
      Frame_error
    | 0x107 ->
      Excessive_load
    | 0x108 ->
      Id_error
    | 0x109 ->
      Settings_error
    | 0x10a ->
      Missing_settings
    | 0x10b ->
      Request_rejected
    | 0x10c ->
      Request_cancelled
    | 0x10d ->
      Request_incomplete
    | 0x10f ->
      Connect_error
    | 0x110 ->
      Version_fallback
    | x ->
      Unknown_error x

  let serialize = function
    | No_error ->
      0x100
    | General_protocol_error ->
      0x101
    | Internal_error ->
      0x102
    | Stream_creation_error ->
      0x103
    | Closed_critical_stream ->
      0x104
    | Frame_unexpected ->
      0x105
    | Frame_error ->
      0x106
    | Excessive_load ->
      0x107
    | Id_error ->
      0x108
    | Settings_error ->
      0x109
    | Missing_settings ->
      0x10a
    | Request_rejected ->
      0x10b
    | Request_cancelled ->
      0x10c
    | Request_incomplete ->
      0x10d
    | Connect_error ->
      0x10f
    | Version_fallback ->
      0x110
    | Unknown_error x ->
      x
end

type t =
  | ConnectionError of Code.t * string
  | StreamError of Code.t

let message = function ConnectionError (_, msg) -> msg | StreamError _ -> ""
