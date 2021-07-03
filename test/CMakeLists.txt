#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

cm_find_package(Boost REQUIRED COMPONENTS unit_test_framework)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}

                       ${CMAKE_WORKSPACE_NAME}::algebra
                       ${CMAKE_WORKSPACE_NAME}::blueprint
                       ${CMAKE_WORKSPACE_NAME}::fft
                       ${CMAKE_WORKSPACE_NAME}::multiprecision
                       nil::marshalling

                       ${Boost_LIBRARIES})

macro(define_zk_test test)
    get_filename_component(name ${test} NAME)
    cm_test(NAME zk_${name}_test SOURCES ${test}.cpp)

    target_include_directories(zk_${name}_test PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(zk_${name}_test PROPERTIES CXX_STANDARD 17)

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(zk_${name}_test PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()

    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(zk_${name}_test PRIVATE "-fconstexpr-steps=2147483647")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(zk_${name}_test PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif()

endmacro()

set(TESTS_NAMES
    "routing_algorithms/test_routing_algorithms"

    "relations/numeric/qap"
    "relations/numeric/sap"
    "relations/numeric/ssp"

    "schemes/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/r1cs_mp_ppzkpcd"
    "schemes/pcd/r1cs_pcd/r1cs_sp_ppzkpcd/r1cs_sp_ppzkpcd"

    "schemes/ppzksnark/bacs_ppzksnark/bacs_ppzksnark"
    "schemes/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark"
    "schemes/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark_marshalling"
    "schemes/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark_tvm_marshalling"
    "schemes/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark"
    "schemes/ppzksnark/r1cs_se_ppzksnark/r1cs_se_ppzksnark"
    "schemes/ppzksnark/ram_ppzksnark/ram_ppzksnark"
    "schemes/ppzksnark/tbcs_ppzksnark/tbcs_ppzksnark"
    "schemes/ppzksnark/uscs_ppzksnark/uscs_ppzksnark"
    "schemes/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark_aggregation_conformity")

foreach(TEST_NAME ${TESTS_NAMES})
    define_zk_test(${TEST_NAME})
endforeach()
