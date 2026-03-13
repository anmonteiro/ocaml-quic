{
  packages,
  ocamlPackages,
  release-mode ? false,
  benchmark-mode ? false,
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
    (with pkgs;
     if benchmark-mode then
       [
         cacert
         curl
         git
       ]
     else if release-mode then
       [
         cacert
         curl
         ocamlPackages.dune-release
         git
         opam
       ]
     else
       [ ])
    ++
      (if benchmark-mode then
         [ ]
       else
         with ocamlPackages;
         [
           merlin
           ocamlformat
           ocaml-lsp
           utop
         ])
    ++
      (if benchmark-mode then
         [ ]
       else
         with hsPkgs;
         [
           h3spec
         ]);
}
