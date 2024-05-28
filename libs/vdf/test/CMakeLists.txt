#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}

                       ${CMAKE_WORKSPACE_NAME}::multiprecision

                       $<$<BOOL:${GMP_FOUND}>:${GMP_LIBRARIES}>
                       $<$<BOOL:${TOMMATH_FOUND}>:${TomMath_LIBRARIES}>

                       Boost::unit_test_framework)

macro(define_vdf_test name)
    cm_test(NAME vdf_${name}_test SOURCES ${name}.cpp)

    target_include_directories(vdf_${name}_test PRIVATE
                               $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                               $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>

                               $<$<BOOL:${GMP_FOUND}>:${GMP_INCLUDE_DIRS}>
                               $<$<BOOL:${TOMMATH_FOUND}>:${TomMath_INCLUDE_DIRS}>

                               ${Boost_INCLUDE_DIRS})

    target_compile_definitions(vdf_${name}_test PRIVATE
                               $<$<BOOL:${TOMMATH_FOUND}>:CRYPTO3_VDF_BOOST_TOMMATH>
                               $<$<BOOL:${GMP_FOUND}>:CRYPTO3_VDF_BOOST_GMP>)

    set_target_properties(vdf_${name}_test PROPERTIES CXX_STANDARD 14)
endmacro()

set(TESTS_NAMES "chia" "pietrzak" "wesolowski")

foreach(TEST_NAME ${TESTS_NAMES})
    define_vdf_test(${TEST_NAME})
endforeach()
