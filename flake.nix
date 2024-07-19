{
  description = "Nix flake for zkllvm-blueprint";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
    nix-3rdparty = {
      url = "github:NilFoundation/nix-3rdparty";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
    nil-crypto3 = {
      type = "github";
      owner = "NilFoundation";
      repo = "crypto3";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
        nix-3rdparty.follows = "nix-3rdparty";
      };
    };
  };

  outputs = { self, nixpkgs, nil-crypto3, flake-utils, nix-3rdparty }:
    (flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        stdenv = pkgs.llvmPackages_16.stdenv;
        crypto3 = nil-crypto3.packages.${system}.crypto3;
      in rec {
        packages = rec {
          zkllvm-blueprint = stdenv.mkDerivation {
            name = "zkllvm-blueprint";

            src = self;

            buildInputs = with pkgs; [
              cmake
              pkg-config
              clang_16
            ];

            propagatedBuildInputs = [ crypto3 pkgs.boost183 ];

            cmakeBuildType = "Release";

            cmakeFlags = [
              "-DCMAKE_CXX_STANDARD=17"
            ];

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
            "blueprint_algebra_fields_plonk_non_native_multiplication_test"
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
            #blueprint_non_native_plonk_scalar_non_native_range_test, TODO: enable once fixed.
            "blueprint_non_native_plonk_bool_scalar_multiplication_test"
            "blueprint_non_native_plonk_add_mul_zkllvm_compatible_test"
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
            #blueprint_mock_mocked_components_test, TODO: Enable after code and test re-written.
            "blueprint_component_batch_test"
            "blueprint_verifiers_placeholder_expression_evaluation_component_test"
            "blueprint_verifiers_placeholder_final_polynomial_check_test"
            "blueprint_verifiers_flexible_swap_test"
            "blueprint_verifiers_flexible_additions_test"
            "blueprint_verifiers_flexible_multiplications_test"
            "blueprint_verifiers_flexible_poseidon_test"
            "blueprint_verifiers_flexible_constant_pow_test"
            "blueprint_verifiers_placeholder_verifier_test"
            "blueprint_zkevm_zkevm_word_test"
            "blueprint_zkevm_bytecode_test"
            "blueprint_zkevm_state_selector_test"
            "blueprint_zkevm_state_transition_test"
            "blueprint_zkevm_opcodes_iszero_test"
            "blueprint_zkevm_opcodes_add_sub_test"
            "blueprint_zkevm_opcodes_mul_test"
            "blueprint_zkevm_opcodes_div_test"
        ];

        checks = {
          default = stdenv.mkDerivation {
            name = "zkllvm-blueprint-tests";

            src = self;

            buildInputs = with pkgs; [
              cmake
              ninja
              pkg-config
              clang_16
              boost183
              crypto3
            ];

            cmakeBuildType = "Debug";

            cmakeFlags = [
              "-DCMAKE_CXX_STANDARD=17"
              "-DCMAKE_ENABLE_TESTS=TRUE"
              "-DCMAKE_C_COMPILER=clang"
              "-DCMAKE_CXX_COMPILER=clang++"
            ];

            ninjaFlags = pkgs.lib.strings.concatStringsSep " " (["-k 0"] ++ testList);

            doCheck = true;

            checkPhase = ''
              # JUNIT file without explicit file name is generated after the name of the master test suite inside `CMAKE_CURRENT_SOURCE_DIR` (/build/source)
              export BOOST_TEST_LOGGER=JUNIT:HRF
              ctest --verbose -j $NIX_BUILD_CORES --output-on-failure -R "${nixpkgs.lib.concatStringsSep "|" testList}" || true

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
              crypto3
            ];

            shellHook = ''
              export NO_AT_BRIDGE="1"
              function nil_test_runner() {
                clear
                filename=$(cat Makefile | grep "$2" | awk 'NR==1{print $NF}')
                make -j$(nproc) "$filename" && ./test/$filename
              }
              function ctcmp() {
                nil_test_runner blueprint $1
              }
              echo "zkllvm-blueprint dev environment activated"
            '';
          };
        };
      }));
}

# 1 build crypto 3 locally with the command 'nix build -L .?submodules=1#'
# 2 use the local source of crypto3: 'nix develop --override-input nil-crypto3 /your/path/to/crypto3 .?submodules=1#'
# 3a to build all in blueprint: 'nix flake -L check .?submodules=1#' or build all and run tests: nix build -L .?submodules=1#checks.x86_64-linux.default
# 3b to build individual targets:
# nix develop . -c cmake -B build -DCMAKE_CXX_STANDARD=17 -DCMAKE_BUILD_TYPE=Debug -DCMAKE_ENABLE_TESTS=TRUE -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
# cd build
# nix develop ../ -c cmake --build . -t blueprint_verifiers_flexible_constant_pow_test
