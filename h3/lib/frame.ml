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

module Type = struct
  type t =
    | Data
    | Headers
    | Cancel_push
    | Settings
    | Push_promise
    | GoAway
    | Max_push_id
    | Ignored of int
    | Unknown of int

  let parse = function
    | 0x0 -> Data
    | 0x1 -> Headers
    | 0x3 -> Cancel_push
    | 0x4 -> Settings
    | 0x5 -> Push_promise
    | 0x7 -> GoAway
    | 0xd -> Max_push_id
    | x when (x - 0x21) / 0x1f > 0 -> Ignored x
    | x -> Unknown x

  let serialize = function
    | Data -> 0x0
    | Headers -> 0x1
    | Cancel_push -> 0x3
    | Settings -> 0x4
    | Push_promise -> 0x5
    | GoAway -> 0x7
    | Max_push_id -> 0xd
    | Ignored x | Unknown x -> x
end

type t =
  | Data of Bigstringaf.t
  | Headers of Bigstringaf.t
  | Cancel_push of int64
  | Settings of Settings.t
  | Push_promise of
      { push_id : int
      ; headers : Bigstringaf.t
      }
  | GoAway of int
  | Max_push_id of int
  | Ignored of int
  | Unknown of int

let to_frame_type = function
  | Data _ -> Type.Data
  | Headers _ -> Headers
  | Cancel_push _ -> Cancel_push
  | Settings _ -> Settings
  | Push_promise _ -> Push_promise
  | GoAway _ -> GoAway
  | Max_push_id _ -> Max_push_id
  | Ignored x -> Ignored x
  | Unknown x -> Unknown x
