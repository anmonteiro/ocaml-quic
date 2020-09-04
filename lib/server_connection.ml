module Reader = Parse.Reader

type t =
  { reader : Reader.server
  ; encrypter : Crypto.AEAD.t option
  ; decrypter : Crypto.AEAD.t option
  ; mutable largest_pn : int64
  }

let create () =
  let rec handler t _packet =
    let _t = Lazy.force t in
    ()
  and decrypt t bs ~off ~len =
    let t = Lazy.force t in
    let cs = Cstruct.of_bigarray ~off ~len bs in
    Crypto.AEAD.decrypt_packet
      (Option.get t.decrypter)
      ~largest_pn:t.largest_pn
      cs
  and t =
    lazy
      { reader = Reader.packets ~decrypt:(decrypt t) (handler t)
      ; encrypter = None
      ; decrypter = None
      ; largest_pn = 0L
      }
  in
  Lazy.force t

let shutdown _t = ()

let is_closed _t = false

let report_exn _t _exn = ()

let yield_writer _t _k = ()

let report_write_result _t _ = ()

let next_write_operation _t = `Yield

let yield_reader _t _k = ()

let read_with_more t bs ~off ~len more =
  let consumed = Reader.read_with_more t.reader bs ~off ~len more in
  consumed

let read t bs ~off ~len =
  let hex = Hex.of_string (Bigstringaf.substring bs ~off ~len) in
  Format.eprintf "wtf: %a@." Hex.pp hex;
  read_with_more t bs ~off ~len Incomplete

let read_eof t bs ~off ~len = read_with_more t bs ~off ~len Complete

let next_read_operation _t = `Read
