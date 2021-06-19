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
                       ${CMAKE_WORKSPACE_NAME}::fft
                       ${CMAKE_WORKSPACE_NAME}::hash
                       ${CMAKE_WORKSPACE_NAME}::multiprecision
                       ${CMAKE_WORKSPACE_NAME}::random
                       ${CMAKE_WORKSPACE_NAME}::zk

                       ${Boost_LIBRARIES})

macro(define_blueprint_test test)
    get_filename_component(name ${test} NAME)
    cm_test(NAME blueprint_${name}_test SOURCES ${test}.cpp)

    target_include_directories(blueprint_${name}_test PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(blueprint_${name}_test PROPERTIES CXX_STANDARD 14)

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(blueprint_${name}_test PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()
endmacro()

set(TESTS_NAMES
    "routing_algorithms/test_routing_algorithms"

    "hashes/knapsack/knapsack_component"
    "hashes/knapsack/knapsack_component_r1cs_scheme"
    "hashes/sha256/sha256_component"
    "hashes/sha256/sha256_r1cs_gg_ppzksnark"

    "routing/as_waksman"
    "routing/benes"

    "pairing/weierstrass_miller_loop"
#    "pairing/weierstrass_precomputation"

    "verifiers/r1cs_ppzksnark"
    "basic_components"
    "basic_components_r1cs_gg_ppzksnark"
    "exponentiation_component"
    "merkle_tree_components"
    "set_commitment_component")

foreach(TEST_NAME ${TESTS_NAMES})
    define_blueprint_test(${TEST_NAME})
endforeach()
