{
  description = "Blueprint circuits library.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
  };

  outputs = { self, nixpkgs }:
    let
      revCount = self.revCount or 1;
      package_version = "0.1.0-${toString revCount}";

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


      make_package = pkgs: with pkgs;
        let
          stdenv =  pkgs.llvmPackages_16.stdenv;
        in
          stdenv.mkDerivation {
            name = "blueprint_circuits";
            src = self;
            dontFixCmake = true;
            env.CXXFLAGS = toString([
              "-fPIC"
            ]);
            env.NIX_CFLAGS_COMPILE = toString([
              "-Wno-unused-but-set-variable"
            ]);
            nativeBuildInputs = [
              cmake
              boost
              pkg-config
              clang-tools_16
              clang_16
            ];
            cmakeFlags = [
              "-DCMAKE_CXX_STANDARD=17"
              "-DBUILD_SHARED_LIBS=TRUE"
              "-DBUILD_TESTS=TRUE"
              "-DBUILD_EXAMPLES=TRUE"
              "-DCMAKE_BUILD_TYPE=Debug"
              "-DCMAKE_CXX_COMPILER=clang++"
              "-DCMAKE_C_COMPILER=clang"
            ];
          };
    in
      {
        packages = forAllSystems({ pkgs }: {
          blueprint_circuits = make_package pkgs;
          default = make_package pkgs;

          devShell.x86_64-linux = pkgs.mkShell {
            buildInputs = [
              make_package pkgs
            ];
          };

          devShell.aarch64-linux = pkgs.mkShell {
            buildInputs = [
              make_package pkgs
            ];
          };

          devShell.x86_64-darwin = pkgs.mkShell {
            buildInputs = [
              make_package pkgs
            ];
          };

          devShell.aarch64-darwin = pkgs.mkShell {
            buildInputs = [
              make_package pkgs
            ];
          };
        });
      };
}