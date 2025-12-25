{
  packages,
  ocamlPackages,
  release-mode ? false,
  stdenv,
  lib,
  mkShell,
  pkgs,
}:

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
    ]);
}
