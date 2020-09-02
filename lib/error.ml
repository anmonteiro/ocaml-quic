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

type t =
  | No_error
  | Internal_error
  | Connection_refused
  | Flow_control_error
  | Stream_limit_error
  | Stream_state_error
  | Final_size_error
  | Frame_encoding_error
  | Transport_parameter_error
  | Connection_id_limit_error
  | Protocol_violation
  | Invalid_token
  | Application_error
  | Crypto_buffer_exceeded
  | Crypto_error of int
  | Other of int

let parse = function
  | 0x0 ->
    No_error
  | 0x1 ->
    Internal_error
  | 0x2 ->
    Connection_refused
  | 0x3 ->
    Flow_control_error
  | 0x4 ->
    Stream_limit_error
  | 0x5 ->
    Stream_state_error
  | 0x6 ->
    Final_size_error
  | 0x7 ->
    Frame_encoding_error
  | 0x8 ->
    Transport_parameter_error
  | 0x9 ->
    Connection_id_limit_error
  | 0xa ->
    Protocol_violation
  | 0xb ->
    Invalid_token
  | 0xc ->
    Application_error
  | 0xd ->
    Crypto_buffer_exceeded
  | x when x >= 0x100 && x <= 0x1ff ->
    Crypto_error (x - 0x100)
  | other ->
    Other other

let serialize = function
  | No_error ->
    0x0
  | Internal_error ->
    0x1
  | Connection_refused ->
    0x2
  | Flow_control_error ->
    0x3
  | Stream_limit_error ->
    0x4
  | Stream_state_error ->
    0x5
  | Final_size_error ->
    0x6
  | Frame_encoding_error ->
    0x7
  | Transport_parameter_error ->
    0x8
  | Connection_id_limit_error ->
    0x9
  | Protocol_violation ->
    0xa
  | Invalid_token ->
    0xb
  | Application_error ->
    0xc
  | Crypto_buffer_exceeded ->
    0xd
  | Crypto_error x ->
    x + 0x100
  | Other other ->
    other
