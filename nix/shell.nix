{
  packages,
  ocamlPackages,
  release-mode ? false,
  stdenv,
  lib,
  mkShell,
  pkgs,
}:

let
  hsPkgs = import ./h3spec.nix { inherit pkgs; };
in
mkShell {
  inputsFrom = [ packages.default ];
  buildInputs =
    (
      if release-mode then
        with pkgs;
        [
          cacert
          curl
          ocamlPackages.dune-release
          git
          opam
        ]
      else
        [ ]
    )
    ++ (with ocamlPackages; [
      merlin
      ocamlformat
      ocaml-lsp
      utop
    ])
    ++ (with hsPkgs; [
      h3spec
    ]);
}
