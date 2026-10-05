{
  description = "OpenWrt selective-routing manager with pluggable proxy cores";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  # Unstable no longer supports Intel macOS; keep its dev shell supported.
  inputs.nixpkgs-darwin-intel.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-darwin-intel,
    }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor =
        system:
        import (if system == "x86_64-darwin" then nixpkgs-darwin-intel else nixpkgs) {
          inherit system;
        };
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.go_1_27
              pkgs.nodejs_24
              pkgs.golangci-lint
              pkgs.gopls
              pkgs.gotools
              pkgs.qemu
              pkgs.expect
              pkgs.netcat
              pkgs.python3
              pkgs.shellcheck
            ]
            ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
              pkgs.nftables
            ];
          };
        }
      );

      formatter = forAllSystems (system: (pkgsFor system).nixfmt-tree);
    };
}
