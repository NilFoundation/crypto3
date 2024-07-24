{ lib,
  stdenv,
  src_repo,
  ninja,
  pkg-config,
  cmake,
  boost183,
  # We'll use boost183 by default, but you can override it
  boost_lib ? boost183,
  gdb,
  cmake_modules,
  crypto3,
  enableDebugging,
  enableDebug ? false,
  runTests ? false,
  }:
let
  inherit (lib) optional;
in stdenv.mkDerivation rec {
  name = "blueprint";

  src = src_repo;

  nativeBuildInputs = [ cmake ninja pkg-config ] ++ (lib.optional (!stdenv.isDarwin) gdb);

  # enableDebugging will keep debug symbols in boost
  propagatedBuildInputs = [ (if enableDebug then (enableDebugging boost_lib) else boost_lib) ];

  buildInputs = [cmake_modules crypto3];

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

  cmakeFlags =
  [
      (if runTests then "-DBUILD_TESTS=TRUE" else "")
      (if runTests then "-DCMAKE_ENABLE_TESTS=TRUE" else "")
      (if enableDebug then "-DCMAKE_BUILD_TYPE=Debug" else "-DCMAKE_BUILD_TYPE=Release")
      (if enableDebug then "-DCMAKE_CXX_FLAGS=-ggdb" else "")
  ];
  
  ninjaFlags = lib.strings.concatStringsSep " " (["-k 0"] ++ testList);

  doCheck = runTests;
  dontInstall = true;

  checkPhase = ''
    # JUNIT file without explicit file name is generated after the name of the master test suite inside `CMAKE_CURRENT_SOURCE_DIR` (/build/source)
    export BOOST_TEST_LOGGER=JUNIT:HRF
    ctest --verbose -j $NIX_BUILD_CORES --output-on-failure -R "${lib.concatStringsSep "|" testList}" || true

    mkdir -p ${placeholder "out"}/test-logs
    find .. -type f -name '*_test.xml' -exec cp {} ${placeholder "out"}/test-logs \;
  '';

  shellHook = ''
    PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
    echo "Welcome to Blueprint development environment!"
  '';
}
