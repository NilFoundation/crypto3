{
  description = "Nix flake for zkllvm-blueprint";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    nil_crypto3 = {
      url = "https://github.com/NilFoundation/crypto3";
      type = "git";
      submodules = true;
    };
  };

  outputs = { self, nixpkgs, nil_crypto3 }:
    let
      # Systems supported
      allSystems = [
        "x86_64-linux" # 64-bit Intel/AMD Linux
        "aarch64-linux" # 64-bit ARM Linux
        "x86_64-darwin" # 64-bit Intel macOS
        "aarch64-darwin" # 64-bit ARM macOS
      ];

      forAllSystems = f: nixpkgs.lib.genAttrs allSystems (system: f {
        pkgs = import nixpkgs { inherit system; };
      });

      # This library is header-only, so we don't need to provide debug and
      # release versions of package.
      makePackage = { pkgs }:
        let
          stdenv = pkgs.llvmPackages_16.stdenv;
          crypto3 = nil_crypto3.packages.${pkgs.system}.default;
        in
        stdenv.mkDerivation {
          name = "zkllvm-blueprint";

          src = self;

          env.CXXFLAGS = toString ([
            "-fPIC"
          ]);

          env.NIX_CFLAGS_COMPILE = toString ([
            "-Wno-unused-but-set-variable"
          ]);

          buildInputs = with pkgs; [
            cmake
            pkg-config
            clang_16
            boost
          ];

          # Because crypto3 is header-only, we must propagate it so users
          # of this flake must not specify crypto3 in their derivations manually
          propagatedBuildInputs = [
            crypto3
          ];

          cmakeFlags = [
            "-DCMAKE_BUILD_TYPE=Release"
            "-DCMAKE_CXX_STANDARD=17"
          ];

          doCheck = false;
        };

      makeChecks = { pkgs }:
        let
          stdenv = pkgs.llvmPackages_16.stdenv;
          crypto3 = nil_crypto3.packages.${pkgs.system}.default;
        in
        stdenv.mkDerivation {
          # TODO: rewrite this using overrideAttrs on makePackage
          name = "zkllvm-blueprint-tests";

          src = self;

          env.CXXFLAGS = toString ([
            "-fPIC"
          ]);

          env.NIX_CFLAGS_COMPILE = toString ([
            "-Wno-unused-but-set-variable"
          ]);

          buildInputs = with pkgs; [
            cmake
            pkg-config
            clang_16
            boost
            crypto3
          ];

          cmakeFlags = [
            "-DCMAKE_BUILD_TYPE=Release"
            "-DCMAKE_CXX_STANDARD=17"
            "-DBUILD_TESTS=TRUE"
          ];

          doCheck = true;
        };

      makeDevShell = { pkgs }:
        let
          crypto3 = nil_crypto3.packages.${pkgs.system}.default;
        in
        pkgs.mkShell {
          buildInputs = with pkgs; [
            cmake
            pkg-config
            boost
            clang_16
            clang-tools_16
            crypto3
          ];

          shellHook = ''
            echo "zkllvm-blueprint dev environment activated"
          '';
        };
    in
    {
      packages = forAllSystems ({ pkgs }: { default = makePackage { inherit pkgs; }; });
      # TODO: because of issues in CMakeLists, these checks cannot be run right now.
      # After fixing the way we bring Crypto3 dependency in CMake, these checks
      # may be used in testing and CI workflow.
      checks = forAllSystems ({ pkgs }: { default = makeChecks { inherit pkgs; }; });
      devShells = forAllSystems ({ pkgs }: { default = makeDevShell { inherit pkgs; }; });
    };
}
