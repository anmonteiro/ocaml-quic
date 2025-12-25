{
  description = "Nix Flake for ocaml-quic";

  inputs.nixpkgs.url = "github:nix-ocaml/nix-overlays";

  outputs =
    { self, nixpkgs }:
    let
      forAllSystems =
        f:
        nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed (
          system:
          let
            pkgs = nixpkgs.legacyPackages.${system}.extend (
              self: super: {
                ocamlPackages = super.ocaml-ng.ocamlPackages_5_4;
              }
            );
          in
          f pkgs
        );
    in
    {
      packages = forAllSystems (
        pkgs:
        let
          packages = pkgs.callPackage ./nix { };
        in
        {
          inherit (packages) qpack quic;
          default = packages.quic;
        }
      );

      devShells = forAllSystems (pkgs: {
        default = pkgs.callPackage ./nix/shell.nix {
          packages = self.packages.${pkgs.stdenv.hostPlatform.system};
        };
        release = pkgs.callPackage ./nix/shell.nix {
          packages = self.packages.${pkgs.stdenv.hostPlatform.system};
          release-mode = true;
        };
      });
    };
}
