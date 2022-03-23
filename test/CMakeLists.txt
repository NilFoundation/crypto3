#---------------------------------------------------------------------------#
# Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

cm_find_package(Boost REQUIRED COMPONENTS random unit_test_framework)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}

                       ${CMAKE_WORKSPACE_NAME}::algebra
                       ${CMAKE_WORKSPACE_NAME}::hash
                       ${CMAKE_WORKSPACE_NAME}::math
                       ${CMAKE_WORKSPACE_NAME}::multiprecision
                       ${CMAKE_WORKSPACE_NAME}::random
                       ${CMAKE_WORKSPACE_NAME}::zk

                       ${Boost_LIBRARIES})

macro(define_blueprint_test test)
    get_filename_component(name ${test} NAME)
    get_filename_component(path ${test} DIRECTORY)

    get_filename_component(dir ${test} NAME)

    set (full_test_name blueprint_${name}_test)

    if (NOT ${path}  STREQUAL "")
        get_filename_component(dir ${path} NAME)
        
        set (full_test_name blueprint_${dir}_${name}_test)
    endif()

    cm_test(NAME ${full_test_name} SOURCES ${test}.cpp)

    target_include_directories(${full_test_name} PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(${full_test_name} PROPERTIES CXX_STANDARD 17)

    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${full_test_name} PRIVATE "-fconstexpr-steps=2147483647")
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${full_test_name} PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif()

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(${full_test_name} PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()
endmacro()

set(NON_NATIVE_TESTS_FILES
    "non_native/plonk/field_mul"
    )

set(BLUEPRINT_TESTS_FILES
    "blueprint/plonk"
    )

set(PLONK_TESTS_FILES
    "algebra/curves/plonk/fixed_base_scalar_mul"
    "algebra/curves/plonk/variable_base_scalar_mul"
    "algebra/curves/plonk/unified_addition"
    "algebra/curves/plonk/variable_base_endo_scalar_mul"
    "algebra/curves/plonk/endo_scalar"
    "hashes/plonk/poseidon"
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
    "algebra/pairing/weierstrass/miller_loop"
    "algebra/pairing/weierstrass/precomputation")

set(ROUTING_TESTS_FILES
    "routing_algorithms/routing_algorithms"
    "routing/as_waksman"
    "routing/benes")

set(SCHEMES_TESTS_FILES
    "verifiers/r1cs_ppzksnark"
    "set_commitment_component")

set(MERKLE_TREE_TESTS_FILES
    "merkle_tree_components")

set(VOTING_TESTS_FILES
    "voting/encrypted_input_voting")

set(BASIC_COMPONENTS_TESTS_FILES
    "basic_components"
    "basic_components_r1cs_gg_ppzksnark")

SET(ALGEBRA_TESTS_FILES 
    ${FIELDS_TESTS_FILES}
    ${CURVES_TESTS_FILES}
    ${PAIRING_TESTS_FILES})

SET(ALL_TESTS_FILES
    ${NON_NATIVE_TESTS_FILES}
    ${BLUEPRINT_TESTS_FILES}
    ${PLONK_TESTS_FILES}
    ${ALGEBRA_TESTS_FILES}
    ${HASHES_TESTS_FILES}
    ${ROUTING_TESTS_FILES}
    ${SCHEMES_TESTS_FILES}
    ${MERKLE_TREE_TESTS_FILES}
    ${VOTING_TESTS_FILES}
    ${BASIC_COMPONENTS_TESTS_FILES})

foreach(TEST_FILE ${ALL_TESTS_FILES})
    define_blueprint_test(${TEST_FILE})
endforeach()
