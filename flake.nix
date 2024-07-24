{
  description = "Nix flake for zkllvm-blueprint";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    nix-3rdparty = {
      url = "github:NilFoundation/nix-3rdparty";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
    nil-crypto3 = {
      url = "https://github.com/NilFoundation/crypto3";
      type = "git";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
  };

  outputs = { self, nixpkgs, nil-crypto3, flake-utils, nix-3rdparty }:
    (flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        stdenv = pkgs.llvmPackages_16.stdenv;
        crypto3 = nil-crypto3.packages.${system}.crypto3;
        cmake_modules = nix-3rdparty.packages.${system}.cmake_modules;
      in {
        packages = rec {
          zkllvm-blueprint = (pkgs.callPackage ./zkllvm-blueprint.nix {
            src_repo = self;
            crypto3 = crypto3;
            cmake_modules = cmake_modules;
          });
          zkllvm-blueprint-debug = (pkgs.callPackage ./zkllvm-blueprint.nix {
            src_repo = self;
            crypto3 = crypto3;
            cmake_modules = cmake_modules;
            enableDebug = true;
          });
          zkllvm-blueprint-debug-tests = (pkgs.callPackage ./zkllvm-blueprint.nix {
            src_repo = self;
            crypto3 = crypto3;
            cmake_modules = cmake_modules;
            enableDebug = true;
            runTests = true;
          });
          default = zkllvm-blueprint-debug-tests;
        };
        checks = rec {
          gcc = (pkgs.callPackage ./zkllvm-blueprint.nix {
            src_repo = self;
            crypto3 = crypto3;
            cmake_modules = cmake_modules;
            runTests = true;
          });
          clang = (pkgs.callPackage ./zkllvm-blueprint.nix {
            stdenv = pkgs.llvmPackages_18.stdenv;
            src_repo = self;
            crypto3 = crypto3;
            cmake_modules = cmake_modules;
            runTests = true;
          });
          all = pkgs.symlinkJoin {
            name = "all";
            paths = [ gcc clang ];
          };
          default = all;
        };
      }));
}

# `nix flake -L check` to run all tests (-L to output build logs)
# `nix flake show` to show derivations tree
# If build fails due to OOM, run `export NIX_CONFIG="cores = 2"` to set desired parallel level
