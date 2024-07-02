{
  description = "Nix flake for Crypto3 header-only C++ library by =nil; Foundation";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    nix-3rdparty = {
      url = "github:NilFoundation/nix-3rdparty";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
  };

  outputs = { self
  , nixpkgs
  , nix-3rdparty
  , ... }:
    let
      supportedSystems = [
        "x86_64-linux"
        "x86_64-darwin"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      makeCrypto3Derivation = { system }:
        let
          pkgs = import nixpkgs {
            overlays = [ nix-3rdparty.overlays.${system}.default ];
            inherit system;
        };
        in
        pkgs.stdenv.mkDerivation {
          name = "Crypto3";

          src = self;

          nativeBuildInputs = with pkgs; [
            cmake
            cmake_modules
            ninja
            pkg-config
          ];

          propagatedBuildInputs = with pkgs; [
            boost183
          ];

          cmakeFlags = [
            "-B build"
            "-G Ninja"
            "-DCMAKE_INSTALL_PREFIX=${placeholder "out"}"
          ];

          dontBuild = true; # nothing to build, header-only lib

          doCheck = false; # tests are inside crypto3-tests derivation

          installPhase = ''
            cmake --build build --target install
          '';
        };

      makeCrypto3Shell = { system }:
        let
          pkgs = import nixpkgs {
            overlays = [ nix-3rdparty.overlays.${system}.default ];
            inherit system;
        };
        in
        pkgs.mkShell {
          buildInputs = with pkgs; [
            cmake
            cmake_modules
            ninja
            clang
            gcc
            boost183
          ];

          shellHook = ''
            PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
            echo "Welcome to Crypto3 development environment!"
          '';
        };

      makeCrypto3Tests = { system }:
        let
          pkgs = import nixpkgs {
            overlays = [ nix-3rdparty.overlays.${system}.default ];
            inherit system;
        };
          isDarwin = builtins.match ".*-darwin" system != null; # Used only to exclude gcc from macOS.
          testCompilers = [
            "clang"
            # TODO: fix gcc linkage on macOS, remove optional condition
          ] ++ nixpkgs.lib.optional (!isDarwin) "gcc";
          # Modules with no failing tests are kept here. Built as `tests-crypto3-<module_name>` targets
          moduleToTestsRegex = {
            algebra = "algebra_.*_test";
            containers = "crypto3_containers_.*_test";
            hash = "hash_.*_test";
            math = "math_.*_test";
            block = "block_.*_test";
            multiprecision = "multiprecision_.*_test";
            zk = "crypto3_zk_*_test";
            pubkey = "pubkey_*_test";
            marshalling-core = "marshalling_core_*_test";
            marshalling-zk = "marshalling_zk_*_test";
            marshalling-algebra = "marshalling_algebra_*_test";
          };
          makeTestDerivation = { name, compiler, targets ? [ ], buildTargets ? targets, testTargets ? targets }:
            (makeCrypto3Derivation { inherit system; }).overrideAttrs (oldAttrs: {
              name = "Crypto3-${name}-tests";

              nativeBuildInputs = oldAttrs.nativeBuildInputs ++ oldAttrs.propagatedBuildInputs ++ [
                (if compiler == "gcc" then pkgs.gcc else pkgs.clang)
              ];

              propagatedBuildInputs = [];

              cmakeFlags = [
                "-G Ninja"
                "-DCMAKE_CXX_COMPILER=${if compiler == "gcc" then "g++" else "clang++"}"
                "-DCMAKE_BUILD_TYPE=Release" # TODO: change to Debug after build fix
                "-DCMAKE_ENABLE_TESTS=TRUE"
              ];

              dontBuild = false;
              # working dir is already set to build dir
              buildPhase = ''
                cmake --build . --parallel $NIX_BUILD_CORES --target ${nixpkgs.lib.concatStringsSep " " buildTargets}
              '';

              doCheck = true;
              checkPhase = ''
                # JUNIT file without explicit file name is generated after the name of the master test suite inside `CMAKE_CURRENT_SOURCE_DIR` (/build/source)
                export BOOST_TEST_LOGGER=JUNIT:HRF
                ctest --verbose -j $NIX_BUILD_CORES --output-on-failure -R "${nixpkgs.lib.concatStringsSep "|" (map (target: "^" + target + "$") testTargets)}"

                mkdir -p ${placeholder "out"}/test-logs
                find .. -type f -name '*_test.xml' -exec cp {} ${placeholder "out"}/test-logs \;
              '';

              dontInstall = true;
            });
          compilerModuleTestsRegexPairs = pkgs.lib.cartesianProductOfSets {
            compiler = testCompilers;
            module = pkgs.lib.attrNames moduleToTestsRegex;
          };
        in
        pkgs.lib.listToAttrs (
          builtins.map
            (pair: {
              name = "${pair.module}-${pair.compiler}";
              value = makeTestDerivation {
                name = pair.module;
                compiler = pair.compiler;
                buildTargets = [ "tests-crypto3-${pair.module}" ];
                testTargets = [ moduleToTestsRegex.${pair.module} ];
              };
            })
            compilerModuleTestsRegexPairs
        );
    in
    {
      packages = forAllSystems (system: {
        default = makeCrypto3Derivation { inherit system; };
      });
      checks = forAllSystems (system:
        makeCrypto3Tests { inherit system; }
      );
      devShells = forAllSystems (system: {
        default = makeCrypto3Shell { inherit system; };
      });
    };
}


# `nix flake -L check .?submodules=1#` to run all tests (-L to output build logs)
# `nix build -L .?submodules=1#checks.x86_64-linux.hash-clang` for partial testing
# `nix flake show` to show derivations tree
# If build fails due to OOM, run `export NIX_CONFIG="cores = 2"` to set desired parallel level
