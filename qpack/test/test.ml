let () =
  Alcotest.run
    "qpack"
    [ "encoder", Test_encoder.suite
    ; "decoder", Test_decoder.suite
    ; "qif interop", Test_qifs.suite
    ]
