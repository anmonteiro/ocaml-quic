{ pkgs ? import ./sources.nix { inherit ocamlVersion; }
, ocamlVersion ? "4_10"
, doCheck ? true }:

let
  inherit (pkgs) lib stdenv ocamlPackages;
  inherit (lib) filterGitSource;
in

  with ocamlPackages;

  let
    genSrc = { dirs, files }: filterGitSource {
      src = ./..;
      inherit dirs;
      files = files ++ [ "dune-project" ];
    };
    buildH2 = args: buildDunePackage ({
      version = "0.6.0-dev";
      useDune2 = true;
      doCheck = doCheck;
    } // args);

    h2Packages = rec {
      hpack = buildH2 {
        pname = "hpack";
        src = genSrc {
          dirs = [ "hpack" ];
          files = [ "hpack.opam" ];
        };

        buildInputs = [ alcotest hex yojson ];
        propagatedBuildInputs = [ angstrom faraday ];
        checkPhase = ''
          dune build @slowtests -p hpack --no-buffer --force
        '';
      };

      h2 = buildH2 {
        pname = "h2";
        src = genSrc {
          dirs = [ "lib" "lib_test" ];
          files = [ "h2.opam" ];
        };

        buildInputs = [ alcotest hex yojson ];
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
          hacl_x25519
          fiat-p256
          logs
          hkdf

          # TLS tests
          ounit
          cstruct-unix
          # TLS Mirage
          mirage-clock
          mirage-flow
          mirage-kv
        ];
      };

      # These two don't have tests
      h2-lwt = buildH2 {
        pname = "h2-lwt";
        src = genSrc {
          dirs = [ "lwt" ];
          files = [ "h2-lwt.opam" ];
        };
        doCheck = false;
        propagatedBuildInputs = [ h2 lwt gluten-lwt ];
      };

      h2-lwt-unix = buildH2 {
        pname = "h2-lwt-unix";
        src = genSrc {
          dirs = [ "lwt-unix" ];
          files = [ "h2-lwt-unix.opam" ];
        };
        doCheck = false;
        propagatedBuildInputs = [
          h2-lwt
          gluten-lwt-unix
          faraday-lwt-unix
          lwt_ssl
        ];
      };
    };
  in
  h2Packages
