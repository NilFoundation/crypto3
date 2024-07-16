#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2018-2021 Aleksei Moskvin <alalmoskvin@gmail.com>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

add_custom_target(${CURRENT_PROJECT_NAME}_test_suite_modular_cpp_int_tests)

cm_test_link_libraries(
    ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
    Boost::unit_test_framework
)

macro(define_runtime_multiprecision_test name)
    set(test_name "${CURRENT_PROJECT_NAME}_${name}_test")

    cm_test(NAME ${test_name} SOURCES ${name}.cpp ARGS)

    target_include_directories(${test_name} PRIVATE
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
        "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

        ${Boost_INCLUDE_DIRS}
    )

    set_target_properties(${test_name} PROPERTIES CXX_STANDARD 17
        CXX_STANDARD_REQUIRED TRUE)

    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${test_name} PRIVATE "-fconstexpr-steps=2147483647")
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${test_name} PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif()

    target_compile_definitions(${test_name} PRIVATE TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data/")
endmacro(define_runtime_multiprecision_test)

macro(define_modular_cpp_int_test name)
    define_runtime_multiprecision_test(${name})

    set(test_name "${CURRENT_PROJECT_NAME}_${name}_test")
    target_compile_definitions(${test_name} PUBLIC -DTEST_CPP_INT)
    # target_link_libraries(${test_name} no_eh_support)
    add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_modular_cpp_int_tests ${test_name})

endmacro(define_modular_cpp_int_test)

set(RUNTIME_TESTS_NAMES
    "inverse"
    "jacobi"
    "ressol"
    "arithmetic_non_matching_bitlength_numbers"
    )

set(MODULAR_TESTS_NAMES
    "modular_adaptor_fixed"
)

foreach(TEST_NAME ${RUNTIME_TESTS_NAMES})
    define_runtime_multiprecision_test(${TEST_NAME})
endforeach()

foreach(TEST_NAME ${MODULAR_TESTS_NAMES})
    define_modular_cpp_int_test(${TEST_NAME})
endforeach()

if(BUILD_BENCH_TESTS)
    cm_add_test_subdirectory(bench_test)
endif()
