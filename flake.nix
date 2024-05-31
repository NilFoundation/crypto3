{
  description = "Nix flake for Crypto3 header-only C++ library by Nil; Foundation";

  inputs = {
    nixpkgs.url = github:NixOS/nixpkgs/nixos-23.11;
  };

  outputs = { self, nixpkgs, ... }:
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
          pkgs = nixpkgs.legacyPackages.${system};
        in
        pkgs.stdenv.mkDerivation {
          name = "Crypto3";

          src = self;

          nativeBuildInputs = with pkgs; [
            cmake
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
          pkgs = nixpkgs.legacyPackages.${system};
        in
        pkgs.mkShell {
          buildInputs = with pkgs; [
            cmake
            ninja
            clang
            gcc
            (boost183.override {
              enableShared = true;
              enableStatic = true;
              enableRelease = true;
              enableDebug = true;
            })
          ];

          shellHook = ''
            PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
            echo "Welcome to Crypto3 development environment!"
          '';
        };

      makeCrypto3Tests = { system }:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          isDarwin = builtins.match ".*-darwin" system != null; # Used only to exclude gcc from macOS.
          testCompilers = [
            "clang"
            # TODO: fix gcc linkage on macOS, remove optional condition
          ] ++ nixpkgs.lib.optional (!isDarwin) "gcc";
          # We have lots of failing tests. Modules with such tests are kept here. Built as separate targets.
          brokenModuleToTestsNames = {
            pubkey = [
              "pubkey_ecdsa_test"
              "pubkey_bls_test"
            ];
            zk = [
              "crypto3_zk_commitment_fold_polynomial_test"
              "crypto3_zk_commitment_fri_test"
              "crypto3_zk_commitment_lpc_test"
              "crypto3_zk_systems_plonk_placeholder_placeholder_circuits_test"
              "crypto3_zk_systems_plonk_placeholder_placeholder_curves_test"
              "crypto3_zk_systems_plonk_placeholder_placeholder_gate_argument_test"
              "crypto3_zk_systems_plonk_placeholder_placeholder_goldilocks_test"
              "crypto3_zk_systems_plonk_placeholder_placeholder_hashes_test"
              "crypto3_zk_systems_plonk_placeholder_placeholder_kzg_test"
              "crypto3_zk_systems_plonk_placeholder_placeholder_lookup_argument_test"
              "crypto3_zk_systems_plonk_placeholder_placeholder_permutation_argument_test"
              "crypto3_zk_systems_plonk_placeholder_placeholder_quotient_polynomial_chunks_test"
              # "crypto3_zk_commitment_powers_of_tau_test"
              "crypto3_zk_commitment_proof_of_knowledge_test"
              "crypto3_zk_commitment_r1cs_gg_ppzksnark_mpc_test"
              "crypto3_zk_math_expression_test"
              "crypto3_zk_systems_plonk_plonk_constraint_test"
            ];
            # Everything is built successfully, just can't use regex to distinguish from other marshalling tests
            # TODO: change prefix to marshalling_core inside module, move to moduleToTestsRegex
            marshalling-core = [
              "marshalling_processing_test"
              "marshalling_interfaces_test"
              "marshalling_types_test"
            ];
            # Ditto
            marshalling-zk = [
              "marshalling_fri_commitment_test"
              "marshalling_lpc_commitment_test"
              "marshalling_placeholder_common_data_test"
              "marshalling_placeholder_proof_test"
              "marshalling_sparse_vector_test"
              "marshalling_accumulation_vector_test"
              "marshalling_plonk_constraint_system_test"
              "marshalling_plonk_assignment_table_test"
              "marshalling_plonk_gates_test"
              "marshalling_r1cs_gg_ppzksnark_primary_input_test"
              "marshalling_r1cs_gg_ppzksnark_proof_test"
              "marshalling_r1cs_gg_ppzksnark_verification_key_test"
              "marshalling_merkle_proof_test"
            ];
            # Ditto
            marshalling-algebra = [
              "marshalling_field_element_test"
              "marshalling_field_element_non_fixed_size_container_test"
              "marshalling_curve_element_fixed_size_container_test"
              "marshalling_curve_element_non_fixed_size_container_test"
              "marshalling_curve_element_test"
            ];
          };
          # Modules with no failing tests are kept here. Built as `tests-crypto3-<module_name>` targets
          moduleToTestsRegex = {
            algebra = "algebra_.*_test";
            containers = "crypto3_containers_.*_test";
            hash = "hash_.*_test";
            math = "math_.*_test";
            block = "block_.*_test";
            multiprecision = "multiprecision_.*_test";
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
          compilerBrokenModuleTestsNamesPairs = pkgs.lib.cartesianProductOfSets {
            compiler = testCompilers;
            module = pkgs.lib.attrNames brokenModuleToTestsNames;
          };
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
                targets = brokenModuleToTestsNames.${pair.module};
              };
            })
            compilerBrokenModuleTestsNamesPairs
          ++
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
