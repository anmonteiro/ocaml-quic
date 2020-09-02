type t = unit

let create () = ()

let shutdown _t = ()

let is_closed _t = false

let report_exn _t _exn = ()

let yield_writer _t _k = ()

let report_write_result _t _ = ()

let next_write_operation _t = `Yield

let yield_reader _t _k = ()

let read_eof _t _bs ~off:_ ~len:_ = 0

let read _t bs ~off ~len =
  let hex = Hex.of_string (Bigstringaf.substring bs ~off ~len) in
  Format.eprintf "wtf: %a@." Hex.pp hex;
  0

let next_read_operation _t = `Read
