{
  description = "Nix flake for zkllvm-blueprint";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";
    nil_crypto3 = {
      url =
        "git+https://github.com/NilFoundation/crypto3?submodules=1&rev=66096ae733cabc99a763e00e803d710493318563";
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

            buildInputs = with pkgs; [ cmake pkg-config clang_16
              (boost183.override {
                enableShared = true;
                enableStatic = true;
                enableRelease = true;
                enableDebug = true;
              })
            ];

            # Because crypto3 is header-only, we must propagate it so users
            # of this flake must not specify crypto3 in their derivations manually
            propagatedBuildInputs = [ crypto3 ];

            cmakeFlags =
              [ "-DCMAKE_BUILD_TYPE=Release"
                "-DCMAKE_CXX_STANDARD=17" ];

            doCheck = false;
          };
          default = zkllvm-blueprint;
        };

        testList = [
            "blueprint_algebra_fields_plonk_field_operations_test"
            "blueprint_algebra_fields_plonk_exponentiation_test"
            "blueprint_algebra_curves_plonk_unified_addition_test"
            "blueprint_algebra_curves_plonk_variable_base_scalar_mul_test"
            "blueprint_verifiers_kimchi_sponge_oracles_test"
            "blueprint_hashes_plonk_poseidon_test"
            "blueprint_algebra_curves_plonk_endo_scalar_test"
            "blueprint_algebra_fields_plonk_range_check_test"
            "blueprint_algebra_fields_plonk_logic_and_flag_test"
            "blueprint_algebra_fields_plonk_logic_or_flag_test"
            "blueprint_algebra_fields_plonk_interpolation_test"
            "blueprint_algebra_fields_plonk_non_native_addition_test"
            "blueprint_algebra_fields_plonk_non_native_subtraction_test"
            "blueprint_algebra_fields_plonk_non_native_range_test"
            "blueprint_algebra_fields_plonk_non_native_reduction_test"
            "blueprint_algebra_fields_plonk_non_native_bit_decomposition_test"
            "blueprint_algebra_fields_plonk_non_native_bit_composition_test"
            "blueprint_algebra_fields_plonk_non_native_bit_shift_constant_test"
            "blueprint_algebra_fields_plonk_non_native_logic_ops_test"
            "blueprint_algebra_fields_plonk_non_native_lookup_logic_ops_test"
            "blueprint_algebra_fields_plonk_non_native_comparison_checked_test"
            "blueprint_algebra_fields_plonk_non_native_comparison_unchecked_test"
            "blueprint_algebra_fields_plonk_non_native_comparison_flag_test"
            "blueprint_algebra_fields_plonk_non_native_equality_flag_test"
            "blueprint_algebra_fields_plonk_non_native_division_remainder_test"
            "blueprint_non_native_plonk_bool_scalar_multiplication_test"
            "blueprint_hashes_plonk_decomposition_test"
            "blueprint_verifiers_placeholder_fri_cosets_test"
            "blueprint_hashes_plonk_sha256_process_test"
            "blueprint_hashes_plonk_sha512_process_test"
            "blueprint_hashes_plonk_sha256_test"
            "blueprint_hashes_plonk_sha512_test"
            "blueprint_algebra_fields_plonk_sqrt_test"
            "blueprint_verifiers_placeholder_fri_lin_inter_test"
            "blueprint_verifiers_placeholder_fri_array_swap_test"
            "blueprint_manifest_test"
            "blueprint_detail_huang_lu_test"
            "blueprint_private_input_test"
            "blueprint_verifiers_placeholder_permutation_argument_verifier_test"
            "blueprint_verifiers_placeholder_gate_argument_verifier_test"
            "blueprint_verifiers_placeholder_lookup_argument_verifier_test"
            "blueprint_verifiers_placeholder_f1_loop_test"
            "blueprint_verifiers_placeholder_f3_loop_test"
            "blueprint_verifiers_placeholder_gate_component_test"
            "blueprint_verifiers_flexible_pow_factor_test"
            "blueprint_proxy_test"
            "blueprint_component_batch_test"
            "blueprint_verifiers_placeholder_expression_evaluation_component_test"
            "blueprint_verifiers_placeholder_final_polynomial_check_test"
            "blueprint_verifiers_flexible_swap_test"
            "blueprint_verifiers_flexible_additions_test"
            "blueprint_verifiers_flexible_multiplications_test"
            "blueprint_verifiers_flexible_poseidon_test"
            "blueprint_verifiers_flexible_constant_pow_test"
        ];

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
              ninja
              pkg-config
              clang_16
              boost183
              packages.crypto3
            ];

            cmakeBuildType = "Debug";

            cmakeFlags = [
              "-DCMAKE_CXX_STANDARD=17"
              "-DBUILD_SHARED_LIBS=TRUE"
              "-DCMAKE_ENABLE_TESTS=TRUE"
              "-DCMAKE_C_COMPILER=clang"
              "-DCMAKE_CXX_COMPILER=clang++"
            ];

            ninjaFlags = pkgs.lib.strings.concatStringsSep " " testList;

            doCheck = true;

            checkPhase = ''
              # JUNIT file without explicit file name is generated after the name of the master test suite inside `CMAKE_CURRENT_SOURCE_DIR` (/build/source)
              export BOOST_TEST_LOGGER=JUNIT:HRF
              ctest --verbose -j $NIX_BUILD_CORES --output-on-failure -R "${nixpkgs.lib.concatStringsSep "|" testList}"

              mkdir -p ${placeholder "out"}/test-logs
              find .. -type f -name '*_test.xml' -exec cp {} ${placeholder "out"}/test-logs \;
            '';

            dontInstall = true;
          };
        };

        devShells = {
          default = pkgs.mkShell {
            buildInputs = with pkgs; [
              cmake
              pkg-config
              boost183
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

# 1 build crypto 3 locally with the command 'nix build -L .?submodules=1#'
# 2 redirect to the local build of crypto3: 'nix develop --redirect .#crypto3 /your/path/to/crypto3/result/'
# 3a to build all in blueprint: 'nix flake -L check .?submodules=1#'
# 3b to build individual targets:
# nix develop . -c cmake -B build -DCMAKE_CXX_STANDARD=17 -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=FALSE -DCMAKE_ENABLE_TESTS=TRUE -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
# cd build
# nix develop ../ -c cmake --build . -t blueprint_verifiers_flexible_constant_pow_test
