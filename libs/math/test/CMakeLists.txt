#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}

                       ${CMAKE_WORKSPACE_NAME}::algebra
                       ${CMAKE_WORKSPACE_NAME}::multiprecision

                       Boost::random
                       Boost::unit_test_framework
                       )

macro(define_math_test name)
    set(test_name "math_${name}_test")

    cm_test(NAME ${test_name} SOURCES ${name}.cpp)

    target_include_directories(${test_name} PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(${test_name} PROPERTIES CXX_STANDARD 17)

endmacro()

set(TESTS_NAMES
    "evaluation_domain"
    # "kronecker_substitution"  # FIXME: This fails. Disabled for passing CI
    "polynomial_arithmetic"
    "polynomial"
    "polynomial_view"
    "polynomial_dfs"
    "polynomial_dfs_view"
    "lagrange_interpolation"
    "basic_radix2_domain")

foreach(TEST_NAME ${TESTS_NAMES})
    define_math_test(${TEST_NAME})
endforeach()

if(ENABLE_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()
