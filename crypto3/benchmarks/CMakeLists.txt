#---------------------------------------------------------------------------#
# Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

add_custom_target(crypto3_benchmarks)

macro(define_benchmark benchmark)

    get_filename_component(name ${benchmark} NAME)
    string(REPLACE "/" "_" full_name ${benchmark}_benchmark)

    add_dependencies(crypto3_benchmarks ${full_name})

    cm_test(NAME ${full_name} SOURCES ${benchmark}.cpp)

    target_include_directories(
        ${full_name} PRIVATE
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
            "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"
            ${Boost_INCLUDE_DIRS})

    target_link_libraries(${full_name}
        ${CMAKE_WORKSPACE_NAME}::random
        ${CMAKE_WORKSPACE_NAME}::math
        ${CMAKE_WORKSPACE_NAME}::algebra
        ${CMAKE_WORKSPACE_NAME}::multiprecision
        ${CMAKE_WORKSPACE_NAME}::zk
        ${CMAKE_WORKSPACE_NAME}::benchmark_tools

        Boost::unit_test_framework
        Boost::timer
        Boost::random)

    set_target_properties(${full_name}
        PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED TRUE)

    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${full_name} PRIVATE "-fconstexpr-steps=2147483647")
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${full_name} PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif()

endmacro()

set(BENCHMARK_NAMES
    "algebra/curves"
    "algebra/fields"
    "algebra/multiexp"

    "math/polynomial_dfs"

    "multiprecision/modular_adaptor_fixed"

    "zk/lpc"
    "zk/pedersen"
)

foreach(BENCHMARK_NAME ${BENCHMARK_NAMES})
    define_benchmark(${BENCHMARK_NAME})
endforeach()


