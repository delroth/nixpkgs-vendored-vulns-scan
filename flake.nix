{
  description = "Automatic scanner and dashboard for vulnerabilities in vendored dependencies for nixpkgs packages.";

  inputs.flake-utils.url = "github:numtide/flake-utils";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.poetry2nix.url = "github:nix-community/poetry2nix";
  inputs.poetry2nix.inputs.nixpkgs.follows = "nixpkgs";

  outputs = { self, nixpkgs, flake-utils, poetry2nix }: {
    overlay = nixpkgs.lib.composeManyExtensions [
      poetry2nix.overlays.default
      (final: prev: {
        vendored-vulns-frontend = prev.poetry2nix.mkPoetryApplication {
          src = prev.poetry2nix.cleanPythonSources { src = ./.; };
          projectDir = vendoredvulns/frontend;

          sourceRoot = "source/vendoredvulns/frontend";
        };

        vendored-vulns-scanner = prev.poetry2nix.mkPoetryApplication {
          src = prev.poetry2nix.cleanPythonSources { src = ./.; };
          projectDir = vendoredvulns/scanner;

          sourceRoot = "source/vendoredvulns/scanner";
        };
      })
    ];
  } // (flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ self.overlay ];
      };
    in
    rec {
      packages = {
        frontend = pkgs.vendored-vulns-frontend;
        scanner = pkgs.vendored-vulns-scanner;
      };
      defaultPackage = packages.scanner;

      devShells.default = with pkgs; mkShell {
        buildInputs = [ cargo-audit nixpkgs-fmt nodejs poetry sqlite ];
      };
    }
  ));
}
