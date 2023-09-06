{
  description = "a blazing-fast pentesting (recon/exploitation) suite";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";

    gomod2nix = {
      url = "github:tweag/gomod2nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.utils.follows = "utils";
    };
  };

  outputs = { self, nixpkgs, utils, gomod2nix }:
    utils.lib.eachDefaultSystem (system:
      let pkgs = import nixpkgs { 
        inherit system; 
        overlays = [ gomod2nix.overlays.default ];
      };
      in
      {
        packages.default = pkgs.buildGoApplication {
          pname = "sif";
          version = "0.1.0";
          src = ./.;
          modules = ./gomod2nix.toml;
        };
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [ 
            go 
            gomod2nix.packages.${system}.default
          ];
        };
      });
}
