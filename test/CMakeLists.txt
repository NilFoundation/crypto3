#---------------------------------------------------------------------------#
# Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@gmail.com>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

find_package(Boost REQUIRED COMPONENTS random unit_test_framework)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                       crypto3::all
                       ${Boost_LIBRARIES})

macro(define_blueprint_test test)
    string(REPLACE "/" "_" full_test_name blueprint_${test}_test)

    set(TEST_RESULTS_DIR "${CMAKE_CURRENT_BINARY_DIR}/junit_results")
    set(TEST_LOGS_DIR "${TEST_RESULTS_DIR}/logs")
    set(additional_args "--log_format=JUNIT"
                        "--log_sink=${TEST_LOGS_DIR}/${full_test_name}.xml")

    cm_test(NAME ${full_test_name} SOURCES ${test}.cpp ARGS ${additional_args})

    target_include_directories(${full_test_name} PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(${full_test_name} PROPERTIES CXX_STANDARD 17)

    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${full_test_name} PRIVATE "${ARGV2}" "-fconstexpr-steps=2147483647" "-ftemplate-backtrace-limit=0")
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${full_test_name} PRIVATE "${ARGV2}" "-fconstexpr-ops-limit=4294967295" "-ftemplate-backtrace-limit=0")
    endif()

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(${full_test_name} PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()
endmacro()

set(COMMON_TEST_FILES
    "manifest"
    "detail/huang_lu"
    "gate_id"
    "utils/connectedness_check"
    "private_input"
    "proxy"
    #"mock/mocked_components"
    "component_batch"
    )

set(NON_NATIVE_TESTS_FILES
    "algebra/fields/plonk/non_native/multiplication"
    "algebra/fields/plonk/non_native/addition"
    "algebra/fields/plonk/non_native/subtraction"
    "algebra/fields/plonk/non_native/range"
    "algebra/fields/plonk/non_native/reduction"
    "algebra/fields/plonk/non_native/bit_decomposition"
    "algebra/fields/plonk/non_native/bit_composition"
    "algebra/fields/plonk/non_native/bit_shift_constant"
    "algebra/fields/plonk/non_native/comparison_checked"
    "algebra/fields/plonk/non_native/comparison_unchecked"
    "algebra/fields/plonk/non_native/comparison_flag"
    "algebra/fields/plonk/non_native/equality_flag"
    "algebra/fields/plonk/non_native/division_remainder"
    "non_native/plonk/bool_scalar_multiplication"
    #"non_native/plonk/add_mul_zkllvm_compatible"
    "non_native/plonk/scalar_non_native_range"
    )

set(NON_NATIVE_TESTS_FILES_WITH_PROOF_GEN
    "algebra/fields/plonk/non_native/logic_ops"
    "algebra/fields/plonk/non_native/lookup_logic_ops"
)

set(PLONK_TESTS_FILES
    "algebra/curves/plonk/variable_base_scalar_mul"
    "algebra/curves/plonk/unified_addition"
    "algebra/curves/plonk/variable_base_endo_scalar_mul"
    "algebra/curves/plonk/endo_scalar"
    "hashes/plonk/poseidon"
    "hashes/plonk/sha256"
    "hashes/plonk/sha512"
    "hashes/plonk/sha256_process"
    "hashes/plonk/sha512_process"
    "hashes/plonk/decomposition"
    "hashes/plonk/detail/sha_table_generators_base4"
    "hashes/plonk/detail/sha_table_generators_base7"
    "verifiers/kimchi/base_field"
    "verifiers/kimchi/prepare_batch_scalar"
    "verifiers/kimchi/verify_scalar"
    "verifiers/kimchi/basic_verifier"
    "verifiers/kimchi/table_commitment"
    "verifiers/kimchi/demo_verifier"
    "verifiers/kimchi/oracles_scalar"
    "verifiers/kimchi/batch_verify_base_field"
    "verifiers/kimchi/batch_verify_scalar_field"
    "verifiers/kimchi/detail/lagrange_denominators"
    "verifiers/kimchi/detail/b_poly"
    "verifiers/kimchi/detail/b_poly_coefficients"
    "verifiers/kimchi/detail/to_group"
    "verifiers/kimchi/detail/public_evaluations"
    "verifiers/kimchi/detail/prev_chal_evals"
    "verifiers/kimchi/detail/ft_eval"
    "verifiers/kimchi/detail/combine_proof_evals"
    "verifiers/kimchi/detail//constraints/index_terms_scalars"
    "verifiers/kimchi/detail/constraints/rpn_expression"
    "verifiers/kimchi/detail/constraints/vanishes_on_last_4_rows"
    "verifiers/kimchi/detail/constraints/unnormalized_lagrange_basis"
    "verifiers/kimchi/detail/constraints/perm_scalars"
    "verifiers/kimchi/detail/constraints/generic_scalars"
    "verifiers/kimchi/detail/oracles_cip"
    "verifiers/kimchi/detail/zk_w3"
    "verifiers/kimchi/detail/prepare_scalars"
    "verifiers/kimchi/detail/zkpm_evaluate"
    "verifiers/kimchi/sponge/sponge"
    "verifiers/kimchi/sponge/oracles"
    "verifiers/kimchi/sponge/transcript_fr"
    "verifiers/kimchi/sponge/transcript_fq"
    "verifiers/kimchi/sponge/compare"
    "algebra/fields/plonk/field_operations"
    "algebra/fields/plonk/combined_inner_product"
    "algebra/fields/plonk/element_powers"
    "algebra/fields/plonk/exponentiation"
    "algebra/fields/plonk/sqrt"
    "algebra/fields/plonk/range_check"
    "algebra/fields/plonk/logic_and_flag"
    "algebra/fields/plonk/logic_or_flag"
    "algebra/fields/plonk/interpolation"
    "verifiers/pickles/verify_heterogenous_scalar"
    "verifiers/pickles/verify_heterogenous_base"
    "verifiers/pickles/scalar_details/evals_of_split_evals"
    "verifiers/placeholder/permutation_argument_verifier"
    "verifiers/placeholder/gate_argument_verifier"
    "verifiers/placeholder/lookup_argument_verifier"
    "verifiers/placeholder/gate_component"
    "verifiers/placeholder/f1_loop"
    "verifiers/placeholder/f3_loop"
    "verifiers/placeholder/fri_cosets"
    "verifiers/placeholder/fri_lin_inter"
    "verifiers/placeholder/fri_array_swap"
    "verifiers/placeholder/expression_evaluation_component"
    "verifiers/placeholder/final_polynomial_check"
    "verifiers/flexible/swap"
    "verifiers/flexible/additions"
    "verifiers/flexible/multiplications"
    "verifiers/flexible/poseidon"
    "verifiers/flexible/constant_pow"
    "verifiers/flexible/pow_factor"
    "verifiers/placeholder/verifier"
    "zkevm/bytecode"
    )

set(FIELDS_TESTS_FILES
    "algebra/fields/r1cs/fp2"
    "algebra/fields/r1cs/fp2_verification"
    "algebra/fields/r1cs/fp3"
    "algebra/fields/r1cs/fp3_verification"
    "algebra/fields/r1cs/fp4"
    "algebra/fields/r1cs/fp4_verification"
    "algebra/fields/r1cs/fp6_2over3"
    "algebra/fields/r1cs/fp6_2over3_verification"
    #"algebra/fields/r1cs/exponentiation"
    )

set(ZKEVM_TESTS_FILES
    "zkevm/state_selector"
    "zkevm/zkevm_word"
    "zkevm/state_transition"
    "zkevm/opcodes/iszero"
    "zkevm/opcodes/add_sub"
    "zkevm/opcodes/mul"
    "zkevm/opcodes/div"
    )

set(CURVES_TESTS_FILES
    "algebra/curves/r1cs/montgomery"
    "algebra/curves/r1cs/twisted_edwards"
    "algebra/curves/r1cs/fixed_base_mul_zcash"
    )

set(HASHES_TESTS_FILES
    "hashes/r1cs/knapsack"
    "hashes/r1cs/knapsack_verification"
    "hashes/r1cs/sha256"
    "hashes/r1cs/sha256_verification"
    "hashes/r1cs/pedersen")

set(PAIRING_TESTS_FILES
    "algebra/pairing/weierstrass/r1cs/miller_loop"
    "algebra/pairing/weierstrass/r1cs/precomputation")

set(ROUTING_TESTS_FILES
    "routing_algorithms/routing_algorithms"
    "routing/r1cs/as_waksman"
    "routing/r1cs/benes")

set(SCHEMES_TESTS_FILES
    "verifiers/r1cs_ppzksnark"
    "set_commitment_component")

set(MERKLE_TREE_TESTS_FILES
    "merkle_tree_components")

set(VOTING_TESTS_FILES
    "voting/r1cs/encrypted_input_voting")

set(BASIC_COMPONENTS_TESTS_FILES
    "basic_components"
    "basic_components_r1cs_gg_ppzksnark")

SET(ALGEBRA_TESTS_FILES
    ${FIELDS_TESTS_FILES}
    ${CURVES_TESTS_FILES}
    ${PAIRING_TESTS_FILES})

SET(ALL_TESTS_FILES
    ${COMMON_TEST_FILES}
    ${NON_NATIVE_TESTS_FILES}
    ${PLONK_TESTS_FILES}
    ${ALGEBRA_TESTS_FILES}
    ${ZKEVM_TESTS_FILES}
    ${HASHES_TESTS_FILES}
    ${ROUTING_TESTS_FILES}
    ${SCHEMES_TESTS_FILES}
    ${MERKLE_TREE_TESTS_FILES}
    ${VOTING_TESTS_FILES}
    ${BASIC_COMPONENTS_TESTS_FILES})

foreach(TEST_FILE ${ALL_TESTS_FILES})
    define_blueprint_test(${TEST_FILE})
endforeach()

foreach(TEST_FILE ${NON_NATIVE_TESTS_FILES_WITH_PROOF_GEN})
    define_blueprint_test(${TEST_FILE} ARGS "-DBLUEPRINT_PLACEHOLDER_PROOF_GEN=True")
endforeach()
