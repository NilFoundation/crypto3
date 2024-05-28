{
  description = "Nix flake for zkllvm-blueprint";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";
    nil_crypto3 = {
      url =
        "git+https://github.com/NilFoundation/crypto3?submodules=1&rev=a458a8b321576f3ac9c97bf0278f4f7b6401c9be";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, nil_crypto3, flake-utils }:
    (flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        stdenv = pkgs.llvmPackages_16.stdenv;
      in rec {
        packages = rec {
          crypto3 = nil_crypto3.packages.${pkgs.system}.default;
          zkllvm-blueprint = stdenv.mkDerivation {
            name = "zkllvm-blueprint";

            src = self;

            env.CXXFLAGS = toString ([ "-fPIC" ]);

            env.NIX_CFLAGS_COMPILE =
              toString ([ "-Wno-unused-but-set-variable" ]);

            buildInputs = with pkgs; [ cmake pkg-config clang_16 boost ];

            # Because crypto3 is header-only, we must propagate it so users
            # of this flake must not specify crypto3 in their derivations manually
            propagatedBuildInputs = [ crypto3 ];

            cmakeFlags =
              [ "-DCMAKE_BUILD_TYPE=Release" "-DCMAKE_CXX_STANDARD=17" ];

            doCheck = false;
          };
        };

        checks = {
          default = stdenv.mkDerivation {
            # TODO: rewrite this using overrideAttrs on makePackage
            name = "zkllvm-blueprint-tests";

            src = self;

            env.CXXFLAGS = toString ([ "-fPIC" ]);

            env.NIX_CFLAGS_COMPILE =
              toString ([ "-Wno-unused-but-set-variable" ]);

            buildInputs = with pkgs; [
              cmake
              pkg-config
              clang_16
              boost
              packages.crypto3
            ];

            cmakeFlags = [
              "-DCMAKE_BUILD_TYPE=Release"
              "-DCMAKE_CXX_STANDARD=17"
              "-DBUILD_TESTS=TRUE"
            ];

            doCheck = true;
          };
        };

        devShells = {
          default = pkgs.mkShell {
            buildInputs = with pkgs; [
              cmake
              pkg-config
              boost
              clang_16
              clang-tools_16
              packages.crypto3
            ];

            shellHook = ''
              echo "zkllvm-blueprint dev environment activated"
            '';
          };
        };
      }));
}

# nix develop --redirect .#crypto3 /home/username/nil/crypto3/result # to override crypto3 folder
