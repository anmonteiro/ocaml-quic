open Qpack__
open Types

let ( // ) = Filename.concat

let header_equal { name; value; _ } { name = name'; value = value'; _ } =
  name = name' && value = value'

let theader =
  (module struct
    type t = header

    let pp formatter { name; value; _ } = Fmt.pf formatter "%s: %s" name value

    let equal h1 h2 = header_equal h1 h2
  end : Alcotest.TESTABLE
    with type t = header)

let headers_list_pp =
  let (module Headers) = theader in
  Format.pp_print_list
    ~pp_sep:(fun fmt () -> Format.pp_print_string fmt ";@\n")
    Headers.pp

let qstring = Alcotest.testable (Fmt.quote Fmt.string) ( = )
