#---------------------------------------------------------------------------#
# Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

if(NOT Boost_UNIT_TEST_FRAMEWORK_FOUND)
    cm_find_package(Boost REQUIRED COMPONENTS unit_test_framework filesystem log log_setup program_options thread system)
endif()

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                       ${Boost_LIBRARIES}

                       crypto3::multiprecision
                       crypto3::algebra
                       crypto3::zk
                       crypto3::blueprint
                       crypto3::pubkey
                       crypto3::pkpad
                       crypto3::hash
                       crypto3::random
                       crypto3::math
                       ${CMAKE_WORKSPACE_NAME}::crypto3_multiprecision
                       ${CMAKE_WORKSPACE_NAME}::crypto3_algebra
                       ${CMAKE_WORKSPACE_NAME}::core)

macro(define_marshalling_test test)

    get_filename_component(name ${test} NAME)

    cm_test(NAME marshalling_${name}_test SOURCES ${test}.cpp)

    target_include_directories(marshalling_${name}_test PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(marshalling_${name}_test PROPERTIES
                          CXX_STANDARD 17
                          CXX_STANDARD_REQUIRED TRUE)

    if(TARGET Boost::unit_test_framework)
        get_target_property(target_type Boost::unit_test_framework TYPE)
        if(target_type STREQUAL "SHARED_LIB")
            target_compile_definitions(marshalling_${name}_test PRIVATE BOOST_TEST_DYN_LINK)
        elseif(target_type STREQUAL "STATIC_LIB")

        endif()
    endif()
endmacro()

set(TESTS_NAMES
    "merkle_proof"
    "accumulation_vector"
    "sparse_vector"
    "r1cs_gg_ppzksnark_primary_input"
    "r1cs_gg_ppzksnark_proof"
    "r1cs_gg_ppzksnark_verification_key"
    "r1cs_gg_ppzksnark"
    "fri_commitment"
    "lpc_commitment"
    "placeholder_proof"
    "placeholder_common_data"
    "plonk_gates"
    "plonk_constraint_system"
    "eddsa")

foreach(TEST_NAME ${TESTS_NAMES})
    define_marshalling_test(${TEST_NAME})
endforeach()
