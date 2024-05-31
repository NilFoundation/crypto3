#---------------------------------------------------------------------------#
# Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

cm_test_link_libraries(
    ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
    Boost::unit_test_framework
    Boost::random
)

add_custom_target(algebra_runtime_tests)

macro(define_runtime_algebra_test name)
    set(test_name "algebra_${name}_test")
    add_dependencies(algebra_runtime_tests ${test_name})

    cm_test(NAME ${test_name} SOURCES ${name}.cpp)

    target_include_directories(${test_name} PRIVATE
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
        "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

        ${Boost_INCLUDE_DIRS}
    )

    set_target_properties(${test_name} PROPERTIES CXX_STANDARD 17
        CXX_STANDARD_REQUIRED TRUE)

    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${test_name} PRIVATE "-fconstexpr-steps=2147483647" "-ftemplate-backtrace-limit=0")
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${test_name} PRIVATE "-fconstexpr-ops-limit=4294967295" "-ftemplate-backtrace-limit=0")
    endif()

    target_compile_definitions(${test_name} PRIVATE TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data/")
endmacro()

macro(define_compile_time_algebra_test name)
    cm_test(NAME algebra_${name}_compile_test SOURCES ${name}.cpp COMPILE_ONLY)

    target_include_directories(algebra_${name}_compile_test PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(algebra_${name}_compile_test PROPERTIES CXX_STANDARD 17)
endmacro()

set(RUNTIME_TESTS_NAMES
    "curves"
    "short_weierstrass_coordinates"
    "curves_static"
    "fields"
    "fields_static"
    "pairing"
    "multiexp"
    )

set(COMPILE_TIME_TESTS_NAMES
    "matrix"
    "vector")

foreach(TEST_NAME ${RUNTIME_TESTS_NAMES})
    define_runtime_algebra_test(${TEST_NAME})
endforeach()

foreach(TEST_NAME ${COMPILE_TIME_TESTS_NAMES})
    define_compile_time_algebra_test(${TEST_NAME})
endforeach()

if(BUILD_BENCH_TESTS)
    cm_add_test_subdirectory(bench_test)
endif()
