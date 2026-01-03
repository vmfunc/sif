{
  description = "A blazing-fast pentesting (recon/exploitation) suite";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.buildGoModule {
            pname = "sif";
            version = "unstable-${self.shortRev or self.dirtyShortRev or "dev"}";
            src = ./.;

            vendorHash = "sha256-ztKXnOjZS/jMxsRjtF0rIZ3lKv4YjMdZd6oQFRuAtR4=";

            # Tests require network access (httptest)
            doCheck = false;

            ldflags = [ "-s" "-w" ];

            meta = with pkgs.lib; {
              description = "Modular pentesting toolkit written in Go";
              homepage = "https://github.com/vmfunc/sif";
              license = licenses.bsd3;
              mainProgram = "sif";
              maintainers = [ ];
            };
          };

          sif = self.packages.${system}.default;
        });

      overlays.default = final: prev: {
        sif = self.packages.${final.system}.default;
      };

      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            buildInputs = with pkgs; [ go gopls ];
          };
        });
    };
}
