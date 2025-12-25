{
  lib,
  stdenv,
  ocamlPackages,
}:

with ocamlPackages;
let
  buildQuic =
    args:
    buildDunePackage (
      {
        version = "n/a";
        doCheck = true;
      }
      // args
    );

in

rec {
  qpack = buildQuic {
    doCheck = false;
    pname = "qpack";
    src =
      let
        fs = lib.fileset;
      in
      fs.toSource {
        root = ./..;
        fileset = fs.unions [
          ../dune-project
          ../qpack
          ../qpack.opam
        ];
      };

    buildInputs = [
      alcotest
      hex
      yojson
    ];
    propagatedBuildInputs = [
      angstrom
      faraday
      psq
    ];
  };

  quic = buildQuic {
    pname = "quic";
    src =
      let
        fs = lib.fileset;
      in
      fs.toSource {
        root = ./..;
        fileset = fs.unions [
          ../dune-project
          ../lib
          ../lib_test
          ../vendor
          ../quic.opam
        ];
      };

    buildInputs = [
      alcotest
      hex
      yojson
    ];
    propagatedBuildInputs = [
      angstrom
      faraday
      base64
      psq
      hpack
      httpaf
      mirage-crypto
      ppx_sexp_conv
      ppx_cstruct
      cstruct
      cstruct-sexp
      sexplib
      mirage-crypto-pk
      mirage-crypto-rng
      x509
      domain-name
      fmt
      ptime
      # hacl_x25519
      # fiat-p256
      logs
      hkdf
      ke
      ipaddr-sexp
      eio
      eio_main
      gluten-lwt
      gluten-eio

      # TLS tests
      ounit
      cstruct-unix
      # TLS Mirage
      mirage-clock
      mirage-flow
      mirage-kv
    ];
  };
}
