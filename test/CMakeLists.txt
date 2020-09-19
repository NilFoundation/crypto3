#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

if(NOT Boost_UNIT_TEST_FRAMEWORK_FOUND)
    cm_find_package(Boost REQUIRED COMPONENTS unit_test_framework)
endif()

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}

                       ${CMAKE_WORKSPACE_NAME}::algebra
                       ${CMAKE_WORKSPACE_NAME}::fft

                       $<TARGET_NAME_IF_EXISTS:boost_multiprecision>
                       $<TARGET_NAME_IF_EXISTS:boost_math>

                       ${Boost_LIBRARIES})

macro(define_zk_test test)
    get_filename_component(name ${test} NAME)
    cm_test(NAME zk_${name}_test SOURCES ${test}.cpp)

    target_include_directories(zk_${name}_test PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(zk_${name}_test PROPERTIES CXX_STANDARD 14)

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(zk_${name}_test PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()
endmacro()

set(TESTS_NAMES
    "routing_algorithms/test_routing_algorithms"

    "gadgets/hashes/knapsack/test_knapsack_component"
    "gadgets/hashes/sha256/test_sha256_component"

    "components/r1cs_ppzksnark_verifier_component"
    "components/merkle_tree_components"
    "components/set_commitment_component"

    "relations/numeric/qap/qap"
    "relations/numeric/sap/sap"
    "relations/numeric/ssp/ssp"

    "proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/r1cs_mp_ppzkpcd"
    "proof_systems/pcd/r1cs_pcd/r1cs_sp_ppzkpcd/r1cs_sp_ppzkpcd"

    "proof_systems/ppzksnark/bacs_ppzksnark/bacs_ppzksnark"
    "proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark"
    "proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark"
    "proof_systems/ppzksnark/r1cs_se_ppzksnark/r1cs_se_ppzksnark"
    "proof_systems/ppzksnark/ram_ppzksnark/ram_ppzksnark"
    "proof_systems/ppzksnark/tbcs_ppzksnark/tbcs_ppzksnark"
    "proof_systems/ppzksnark/uscs_ppzksnark/uscs_ppzksnark"

    "proof_systems/zksnark/ram_zksnark/ram_zksnark")

foreach(TEST_NAME ${TESTS_NAMES})
    define_zk_test(${TEST_NAME})
endforeach()