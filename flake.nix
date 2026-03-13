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
                ocamlPackages = super.ocaml-ng.ocamlPackages_5_4.overrideScope (
                  oself: osuper: {
                    ssl = osuper.ssl.overrideAttrs (_: {
                      src = super.fetchFromGitHub {
                        owner = "savonet";
                        repo = "ocaml-ssl";
                        rev = "a3ec4b6d6883a6a73e59f6756eceb1b7cbf45183";
                        hash = "sha256-zXk5cV6lz5q6XX/CVk8ymt/o+J8DCgAqWMULJLPzenk=";
                      };
                    });
                  }
                );
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
        benchmark = pkgs.callPackage ./nix/shell.nix {
          packages = self.packages.${pkgs.stdenv.hostPlatform.system};
          benchmark-mode = true;
        };
        release = pkgs.callPackage ./nix/shell.nix {
          packages = self.packages.${pkgs.stdenv.hostPlatform.system};
          release-mode = true;
        };
      });
    };
}
