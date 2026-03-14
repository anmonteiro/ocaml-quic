module Result = Stdlib.Result

exception Parse_error of string

let failf fmt = Format.kasprintf (fun s -> raise (Parse_error s)) fmt

module Cursor = struct
  type t =
    { buffer : Bigstringaf.t
    ; base : int
    ; limit : int
    ; mutable off : int
    }

  let create buffer ~off ~len = { buffer; base = off; limit = off + len; off }
  let remaining t = t.limit - t.off
  let consumed t = t.off - t.base

  let ensure t needed =
    if remaining t < needed
    then failf "truncated input: need %d bytes, have %d" needed (remaining t)

  let advance t n =
    ensure t n;
    t.off <- t.off + n

  let uint8 t =
    ensure t 1;
    let x = Char.code (Bigstringaf.unsafe_get t.buffer t.off) in
    t.off <- t.off + 1;
    x

  let uint16_be t =
    ensure t 2;
    let x =
      (Char.code (Bigstringaf.unsafe_get t.buffer t.off) lsl 8)
      lor Char.code (Bigstringaf.unsafe_get t.buffer (t.off + 1))
    in
    t.off <- t.off + 2;
    x

  let int32_be t =
    ensure t 4;
    let x = Bigstringaf.unsafe_get_int32_be t.buffer t.off in
    t.off <- t.off + 4;
    x

  let take_bigstring t len =
    ensure t len;
    let off = t.off in
    t.off <- t.off + len;
    Bigstringaf.sub t.buffer ~off ~len

  let take_string t len =
    ensure t len;
    let off = t.off in
    t.off <- t.off + len;
    Bigstringaf.substring t.buffer ~off ~len
end

module String_cursor = struct
  type t =
    { buffer : string
    ; base : int
    ; limit : int
    ; mutable off : int
    }

  let create buffer ~off ~len = { buffer; base = off; limit = off + len; off }
  let remaining t = t.limit - t.off
  let consumed t = t.off - t.base

  let ensure t needed =
    if remaining t < needed
    then failf "truncated input: need %d bytes, have %d" needed (remaining t)

  let uint8 t =
    ensure t 1;
    let x = Char.code (String.unsafe_get t.buffer t.off) in
    t.off <- t.off + 1;
    x

  let take_bigstring t len =
    ensure t len;
    let off = t.off in
    t.off <- t.off + len;
    Bigstringaf.of_string ~off ~len t.buffer

  let take_string t len =
    ensure t len;
    let off = t.off in
    t.off <- t.off + len;
    String.sub t.buffer off len
end

let parse_varint (t : Cursor.t) =
  let first_byte = Cursor.uint8 t in
  let encoding = first_byte lsr 6 in
  let b1 = first_byte land 0b00111111 in
  let rec gather acc remaining =
    if remaining = 0
    then acc
    else gather ((acc lsl 8) lor Cursor.uint8 t) (remaining - 1)
  in
  match encoding with
  | 0 -> b1
  | 1 -> gather b1 1
  | 2 -> gather b1 3
  | _ -> gather b1 7

let parse_varint_string (t : String_cursor.t) =
  let first_byte = String_cursor.uint8 t in
  let encoding = first_byte lsr 6 in
  let b1 = first_byte land 0b00111111 in
  let rec gather acc remaining =
    if remaining = 0
    then acc
    else gather ((acc lsl 8) lor String_cursor.uint8 t) (remaining - 1)
  in
  match encoding with
  | 0 -> b1
  | 1 -> gather b1 1
  | 2 -> gather b1 3
  | _ -> gather b1 7

let parse_varint_len (buffer : Bigstringaf.t) ~off ~limit =
  if off >= limit
  then failf "truncated varint at offset %d" off
  else
    let first_byte = Char.code (Bigstringaf.unsafe_get buffer off) in
    let len =
      match first_byte lsr 6 with
      | 0 -> 1
      | 1 -> 2
      | 2 -> 4
      | _ -> 8
    in
    if off + len > limit
    then failf "truncated varint at offset %d" off
    else len

let parse_varint_at (buffer : Bigstringaf.t) ~off ~limit =
  let len = parse_varint_len buffer ~off ~limit in
  let first_byte = Char.code (Bigstringaf.unsafe_get buffer off) in
  let rec gather acc index remaining =
    if remaining = 0
    then acc
    else
      gather
        ((acc lsl 8) lor Char.code (Bigstringaf.unsafe_get buffer (off + index)))
        (index + 1)
        (remaining - 1)
  in
  let value =
    match first_byte lsr 6 with
    | 0 -> first_byte land 0b00111111
    | 1 -> gather (first_byte land 0b00111111) 1 1
    | 2 -> gather (first_byte land 0b00111111) 1 3
    | _ -> gather (first_byte land 0b00111111) 1 7
  in
  len, value

let parse_cid cursor =
  let len = Cursor.uint8 cursor in
  Cursor.take_string cursor len |> CID.of_string

module Frame = struct
  let parse_ack_frame cursor ecn_counts =
    let largest_ack = parse_varint cursor in
    let ack_delay = parse_varint cursor in
    let ack_range_count = parse_varint cursor in
    let first_ack_range = parse_varint cursor in
    let rec parse_ranges acc remaining =
      if remaining = 0
      then List.rev acc
      else
        let gap = Int64.of_int (parse_varint cursor) in
        let len = Int64.of_int (parse_varint cursor) in
        parse_ranges ((gap, len) :: acc) (remaining - 1)
    in
    let ranges_desc = parse_ranges [] ack_range_count in
    let ecn_counts =
      if not ecn_counts
      then None
      else
        let ect0 = parse_varint cursor in
        let ect1 = parse_varint cursor in
        let cn = parse_varint cursor in
        Some (ect0, ect1, cn)
    in
    let smallest_ack = largest_ack - first_ack_range in
    let first_range =
      { Frame.Range.first = Int64.of_int smallest_ack
      ; last = Int64.of_int largest_ack
      }
    in
    let ranges =
      List.fold_left
        (fun acc (gap, len) ->
           let smallest_ack = (List.hd acc).Frame.Range.first in
           let largest_ack = Int64.(sub (sub smallest_ack gap) 2L) in
           let smallest_ack = Int64.sub largest_ack len in
           { Frame.Range.first = smallest_ack; last = largest_ack } :: acc)
        [ first_range ]
        ranges_desc
    in
    Frame.Ack { delay = ack_delay; ranges; ecn_counts }

  let parse_stream_frame cursor ~off ~len ~fin =
    let stream_id = Int64.of_int (parse_varint cursor) in
    let off = if off then parse_varint cursor else 0 in
    let len = if len then parse_varint cursor else Cursor.remaining cursor in
    let payload = Cursor.take_string cursor len in
    Frame.Stream
      { id = stream_id
      ; fragment = { Frame.off; len; payload; payload_off = 0 }
      ; is_fin = fin
      }

  let parse_frame cursor =
    let frame_type = Frame.Type.parse (parse_varint cursor) in
    match frame_type with
    | Padding ->
      let count = ref 0 in
      (try
         while Cursor.remaining cursor > 0 do
           if Char.code (Bigstringaf.unsafe_get cursor.buffer cursor.off) = 0x00
           then (
             incr count;
             cursor.off <- cursor.off + 1)
           else raise Exit
         done
       with
       | Exit -> ());
      Frame.Padding !count
    | Ping -> Frame.Ping
    | Ack { ecn_counts } -> parse_ack_frame cursor ecn_counts
    | Reset_stream ->
      let stream_id = Int64.of_int (parse_varint cursor) in
      let application_protocol_error = parse_varint cursor in
      let final_size = parse_varint cursor in
      Frame.Reset_stream
        { stream_id; application_protocol_error; final_size }
    | Stop_sending ->
      let stream_id = Int64.of_int (parse_varint cursor) in
      let application_protocol_error = parse_varint cursor in
      Frame.Stop_sending { stream_id; application_protocol_error }
    | Crypto ->
      let off = parse_varint cursor in
      let len = parse_varint cursor in
      let payload = Cursor.take_string cursor len in
      Frame.Crypto { Frame.off; len; payload; payload_off = 0 }
    | New_token ->
      let length = parse_varint cursor in
      let data = Cursor.take_bigstring cursor length in
      Frame.New_token { length; data }
    | Stream { off; len; fin } -> parse_stream_frame cursor ~off ~len ~fin
    | Max_data -> Frame.Max_data (parse_varint cursor)
    | Max_stream_data ->
      let stream_id = Int64.of_int (parse_varint cursor) in
      let max_data = parse_varint cursor in
      Frame.Max_stream_data { stream_id; max_data }
    | Max_streams direction ->
      Frame.Max_streams (direction, parse_varint cursor)
    | Data_blocked -> Frame.Data_blocked (parse_varint cursor)
    | Stream_data_blocked ->
      let id = Int64.of_int (parse_varint cursor) in
      let max_data = parse_varint cursor in
      Frame.Stream_data_blocked { id; max_data }
    | Streams_blocked direction ->
      Frame.Streams_blocked (direction, parse_varint cursor)
    | New_connection_id ->
      let sequence_no = parse_varint cursor in
      let retire_prior_to = parse_varint cursor in
      let cid = parse_cid cursor in
      let stateless_reset_token = Cursor.take_string cursor 16 in
      Frame.New_connection_id
        { cid; stateless_reset_token; retire_prior_to; sequence_no }
    | Retire_connection_id ->
      Frame.Retire_connection_id (parse_varint cursor)
    | Path_challenge ->
      Frame.Path_challenge (Cursor.take_bigstring cursor 8)
    | Path_response ->
      Frame.Path_response (Cursor.take_bigstring cursor 8)
    | Connection_close_quic ->
      let error_code = Error.parse (parse_varint cursor) in
      let frame_type = Frame.Type.parse (parse_varint cursor) in
      let reason_phrase_length = parse_varint cursor in
      let reason_phrase = Cursor.take_string cursor reason_phrase_length in
      Frame.Connection_close_quic { frame_type; reason_phrase; error_code }
    | Connection_close_app ->
      let error_code = parse_varint cursor in
      let reason_phrase_length = parse_varint cursor in
      let reason_phrase = Cursor.take_string cursor reason_phrase_length in
      Frame.Connection_close_app { error_code; reason_phrase }
    | Handshake_done -> Frame.Handshake_done
    | Unknown x -> Frame.Unknown x

  let parse_bigstring buffer ~handler =
    let cursor = Cursor.create buffer ~off:0 ~len:(Bigstringaf.length buffer) in
    try
      while Cursor.remaining cursor > 0 do
        handler (parse_frame cursor)
      done;
      Ok ()
    with
    | Parse_error e -> Error e

  let parse_ack_frame_string cursor ecn_counts =
    let largest_ack = parse_varint_string cursor in
    let ack_delay = parse_varint_string cursor in
    let ack_range_count = parse_varint_string cursor in
    let first_ack_range = parse_varint_string cursor in
    let rec parse_ranges acc remaining =
      if remaining = 0
      then List.rev acc
      else
        let gap = Int64.of_int (parse_varint_string cursor) in
        let len = Int64.of_int (parse_varint_string cursor) in
        parse_ranges ((gap, len) :: acc) (remaining - 1)
    in
    let ranges_desc = parse_ranges [] ack_range_count in
    let ecn_counts =
      if not ecn_counts
      then None
      else
        let ect0 = parse_varint_string cursor in
        let ect1 = parse_varint_string cursor in
        let cn = parse_varint_string cursor in
        Some (ect0, ect1, cn)
    in
    let smallest_ack = largest_ack - first_ack_range in
    let first_range =
      { Frame.Range.first = Int64.of_int smallest_ack
      ; last = Int64.of_int largest_ack
      }
    in
    let ranges =
      List.fold_left
        (fun acc (gap, len) ->
           let smallest_ack = (List.hd acc).Frame.Range.first in
           let largest_ack = Int64.(sub (sub smallest_ack gap) 2L) in
           let smallest_ack = Int64.sub largest_ack len in
           { Frame.Range.first = smallest_ack; last = largest_ack } :: acc)
        [ first_range ]
        ranges_desc
    in
    Frame.Ack { delay = ack_delay; ranges; ecn_counts }

  let parse_stream_frame_string cursor ~off ~len ~fin =
    let stream_id = Int64.of_int (parse_varint_string cursor) in
    let off = if off then parse_varint_string cursor else 0 in
    let len = if len then parse_varint_string cursor else String_cursor.remaining cursor in
    let payload_off = cursor.off in
    cursor.off <- cursor.off + len;
    Frame.Stream
      { id = stream_id
      ; fragment = { Frame.off; len; payload = cursor.buffer; payload_off }
      ; is_fin = fin
      }

  let parse_frame_string cursor =
    let frame_type = Frame.Type.parse (parse_varint_string cursor) in
    match frame_type with
    | Padding ->
      let count = ref 0 in
      (try
         while String_cursor.remaining cursor > 0 do
           if Char.code (String.unsafe_get cursor.buffer cursor.off) = 0x00
           then (
             incr count;
             cursor.off <- cursor.off + 1)
           else raise Exit
         done
       with
       | Exit -> ());
      Frame.Padding !count
    | Ping -> Frame.Ping
    | Ack { ecn_counts } -> parse_ack_frame_string cursor ecn_counts
    | Reset_stream ->
      let stream_id = Int64.of_int (parse_varint_string cursor) in
      let application_protocol_error = parse_varint_string cursor in
      let final_size = parse_varint_string cursor in
      Frame.Reset_stream { stream_id; application_protocol_error; final_size }
    | Stop_sending ->
      let stream_id = Int64.of_int (parse_varint_string cursor) in
      let application_protocol_error = parse_varint_string cursor in
      Frame.Stop_sending { stream_id; application_protocol_error }
    | Crypto ->
      let off = parse_varint_string cursor in
      let len = parse_varint_string cursor in
      let payload_off = cursor.off in
      cursor.off <- cursor.off + len;
      Frame.Crypto { Frame.off; len; payload = cursor.buffer; payload_off }
    | New_token ->
      let length = parse_varint_string cursor in
      let data = String_cursor.take_bigstring cursor length in
      Frame.New_token { length; data }
    | Stream { off; len; fin } -> parse_stream_frame_string cursor ~off ~len ~fin
    | Max_data -> Frame.Max_data (parse_varint_string cursor)
    | Max_stream_data ->
      let stream_id = Int64.of_int (parse_varint_string cursor) in
      let max_data = parse_varint_string cursor in
      Frame.Max_stream_data { stream_id; max_data }
    | Max_streams direction ->
      Frame.Max_streams (direction, parse_varint_string cursor)
    | Data_blocked -> Frame.Data_blocked (parse_varint_string cursor)
    | Stream_data_blocked ->
      let id = Int64.of_int (parse_varint_string cursor) in
      let max_data = parse_varint_string cursor in
      Frame.Stream_data_blocked { id; max_data }
    | Streams_blocked direction ->
      Frame.Streams_blocked (direction, parse_varint_string cursor)
    | New_connection_id ->
      let sequence_no = parse_varint_string cursor in
      let retire_prior_to = parse_varint_string cursor in
      let cid =
        let len = String_cursor.uint8 cursor in
        String_cursor.take_string cursor len |> CID.of_string
      in
      let stateless_reset_token = String_cursor.take_string cursor 16 in
      Frame.New_connection_id
        { cid; stateless_reset_token; retire_prior_to; sequence_no }
    | Retire_connection_id ->
      Frame.Retire_connection_id (parse_varint_string cursor)
    | Path_challenge ->
      Frame.Path_challenge (String_cursor.take_bigstring cursor 8)
    | Path_response ->
      Frame.Path_response (String_cursor.take_bigstring cursor 8)
    | Connection_close_quic ->
      let error_code = Error.parse (parse_varint_string cursor) in
      let frame_type = Frame.Type.parse (parse_varint_string cursor) in
      let reason_phrase_length = parse_varint_string cursor in
      let reason_phrase = String_cursor.take_string cursor reason_phrase_length in
      Frame.Connection_close_quic { frame_type; reason_phrase; error_code }
    | Connection_close_app ->
      let error_code = parse_varint_string cursor in
      let reason_phrase_length = parse_varint_string cursor in
      let reason_phrase = String_cursor.take_string cursor reason_phrase_length in
      Frame.Connection_close_app { error_code; reason_phrase }
    | Handshake_done -> Frame.Handshake_done
    | Unknown x -> Frame.Unknown x

  let parse_string buffer ~handler =
    let cursor = String_cursor.create buffer ~off:0 ~len:(String.length buffer) in
    try
      while String_cursor.remaining cursor > 0 do
        handler (parse_frame_string cursor)
      done;
      Ok ()
    with
    | Parse_error e -> Error e
end

module Packet_parser = struct
  type parse_result =
    | Skip of int
    | Packet of Packet.t * int
    | Error of Packet.t * Error.t * int

  type protected_header =
    { header : Packet.Header.t
    ; payload_length : int
    ; header_prefix_len : int
    }

  let is_protected buffer ~off ~len =
    if len <= 0
    then false
    else
      let first_byte = Char.code (Bigstringaf.unsafe_get buffer off) in
      match Packet.Header.Type.parse first_byte with
      | Short -> true
      | Long ->
        if len < 5
        then false
        else
          let version = Bigstringaf.unsafe_get_int32_be buffer (off + 1) in
          match Packet.Version.parse version with
          | Negotiation -> false
          | Number _ ->
            match Packet.parse_type first_byte with
            | Retry -> false
            | _ -> true

  let parse_long_header_common cursor =
    let version = Packet.Version.parse (Cursor.int32_be cursor) in
    let dest_cid = parse_cid cursor in
    let source_cid = parse_cid cursor in
    (match version with
    | Negotiation -> ()
    | Number _ ->
      if CID.length dest_cid > CID.max_length || CID.length source_cid > CID.max_length
      then failf "invalid connection id length");
    version, source_cid, dest_cid

  let parse_unprotected buffer ~off ~len =
    let cursor = Cursor.create buffer ~off ~len in
    let first_byte = Cursor.uint8 cursor in
    match Packet.parse_type first_byte with
    | Retry ->
      let version, source_cid, dest_cid = parse_long_header_common cursor in
      let header_size = Cursor.consumed cursor in
      if Cursor.remaining cursor < 16
      then failf "retry packet shorter than integrity tag";
      let pseudo_len = len - 16 in
      let token_len = pseudo_len - header_size in
      let token = Cursor.take_string cursor token_len in
      let tag = Cursor.take_bigstring cursor 16 in
      let pseudo = Bigstringaf.sub buffer ~off ~len:pseudo_len in
      let version =
        match version with
        | Packet.Version.Negotiation -> Int32.zero
        | Number version -> version
      in
      Packet.Retry
        { header =
            Packet.Header.Long
              { version; source_cid; dest_cid; packet_type = Retry }
        ; token
        ; pseudo
        ; tag
        }
    | _ ->
      let version, source_cid, dest_cid = parse_long_header_common cursor in
      match version with
      | Number _ -> failf "unexpected protected long packet"
      | Negotiation ->
        let remaining = Cursor.remaining cursor in
        if remaining mod 4 <> 0
        then failf "invalid version negotiation payload length";
        let rec gather acc =
          if Cursor.remaining cursor = 0
          then List.rev acc
          else gather (Cursor.int32_be cursor :: acc)
        in
        Packet.VersionNegotiation
          { source_cid; dest_cid; versions = gather [] }

  let parse_protected_header buffer ~off ~len =
    let cursor = Cursor.create buffer ~off ~len in
    let first_byte = Cursor.uint8 cursor in
    match Packet.Header.Type.parse first_byte with
    | Short ->
      let dest_cid = Cursor.take_string cursor CID.src_length |> CID.of_string in
      { header = Packet.Header.Short { dest_cid }
      ; payload_length = Cursor.remaining cursor
      ; header_prefix_len = Cursor.consumed cursor
      }
    | Long ->
      let packet_type = Packet.parse_type first_byte in
      let version, source_cid, dest_cid = parse_long_header_common cursor in
      let version =
        match version with
        | Packet.Version.Negotiation -> failf "unexpected negotiation packet"
        | Number version -> version
      in
      let header =
        match packet_type with
        | Packet.Type.Initial ->
          let token_length = parse_varint cursor in
          let token = Cursor.take_string cursor token_length in
          Packet.Header.Initial { version; source_cid; dest_cid; token }
        | Zero_RTT | Handshake ->
          Packet.Header.Long { version; source_cid; dest_cid; packet_type }
        | Retry -> failf "unexpected retry packet"
      in
      let payload_length = parse_varint cursor in
      { header; payload_length; header_prefix_len = Cursor.consumed cursor }

  let parse
        ~decrypt
        (buffer : Bigstringaf.t)
        ~off
        ~len
    =
    if len <= 0
    then Skip 0
    else if is_protected buffer ~off ~len
    then (
      let first_byte = Char.code (Bigstringaf.unsafe_get buffer off) in
      if not (Bits.test first_byte 6)
      then Skip len
      else
        try
          let { header; payload_length; header_prefix_len } =
            parse_protected_header buffer ~off ~len
          in
          match decrypt ~payload_length ~header ~header_prefix_len buffer ~off ~len with
          | None -> Skip len
          | Some { Crypto.AEAD.first_byte_unprotected
                 ; plaintext
                 ; packet_number
                 ; pn_length
                 } ->
            let packet =
              Packet.Frames
                { header
                ; payload = Packet.Payload.String plaintext
                ; payload_length = payload_length - pn_length
                ; packet_number
                }
            in
            let consumed = header_prefix_len + payload_length in
            if first_byte_unprotected land 0b00001100 <> 0
            then Error (packet, Protocol_violation, consumed)
            else Packet (packet, consumed)
        with
        | Parse_error _ -> Skip len)
    else
      try Packet (parse_unprotected buffer ~off ~len, len) with
      | Parse_error _ -> Skip len
end

module Reader = struct
  type t =
    { decrypt :
        payload_length:int
        -> header:Packet.Header.t
        -> header_prefix_len:int
        -> Cstruct.buffer
        -> off:int
        -> len:int
        -> Crypto.AEAD.parse_ret option
    ; handler : ?error:Error.t -> Packet.t -> unit
    ; mutable closed : bool
    }

  let packets ~decrypt handler = { decrypt; handler; closed = false }

  let read_with_more _t bs ~off ~len ~eof =
    let cursor = Cursor.create bs ~off ~len in
    while Cursor.remaining cursor > 0 do
      match
        Packet_parser.parse
          ~decrypt:_t.decrypt
          bs
          ~off:cursor.off
          ~len:(Cursor.remaining cursor)
      with
      | Skip consumed ->
        if consumed <= 0
        then failf "fast parser made no progress"
        else Cursor.advance cursor consumed
      | Packet (packet, consumed) ->
        _t.handler packet;
        Cursor.advance cursor consumed;
        if not (Packet.can_be_followed_by_other_packets packet)
        then cursor.off <- cursor.limit
      | Error (packet, error, consumed) ->
        _t.handler ~error packet;
        Cursor.advance cursor consumed;
        if not (Packet.can_be_followed_by_other_packets packet)
        then cursor.off <- cursor.limit
    done;
    if eof then _t.closed <- true;
    len

  let force_close t = t.closed <- true
  let recover _t = ()
  let next t = if t.closed then `Close else `Read
end
