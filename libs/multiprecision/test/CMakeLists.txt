#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2018-2021 Aleksei Moskvin <alalmoskvin@gmail.com>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

find_package(Eigen3)

#add_custom_target(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests)
#add_custom_target(${CURRENT_PROJECT_NAME}_test_suite_functions_and_limits)
#add_custom_target(${CURRENT_PROJECT_NAME}_test_suite_conversions)
#add_custom_target(${CURRENT_PROJECT_NAME}_test_suite_cpp_int_tests)
add_custom_target(${CURRENT_PROJECT_NAME}_test_suite_modular_cpp_int_tests)
#add_custom_target(${CURRENT_PROJECT_NAME}_test_suite_misc)
#add_custom_target(${CURRENT_PROJECT_NAME}_test_suite_specfun)
#add_custom_target(${CURRENT_PROJECT_NAME}_test_suite_concepts)
#add_custom_target(${CURRENT_PROJECT_NAME}_test_suite_examples)
#add_custom_target(${CURRENT_PROJECT_NAME}_test_suite_compile_fail)

cm_test_link_libraries(
    ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
    Boost::unit_test_framework
)

# HACK: Workaround broken includes
file(GLOB TEST_HEADERS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/*.hpp ${CMAKE_CURRENT_SOURCE_DIR}/*.ipp)
set(CMAKE_INCLUDE_CURRENT_DIR TRUE)
foreach(HEADER ${TEST_HEADERS})
    configure_file(${HEADER} ${CMAKE_CURRENT_BINARY_DIR}/libs/${CURRENT_PROJECT_NAME}/test/${HEADER}
                   @ONLY)
endforeach()

add_library(${CURRENT_PROJECT_NAME}_test_settings INTERFACE)
target_include_directories(${CURRENT_PROJECT_NAME}_test_settings INTERFACE ${CURRENT_TEST_SOURCES_DIR}/include)
cm_test_link_libraries(${CURRENT_PROJECT_NAME}_test_settings)

if(EIGEN_FOUND)
    try_compile(EIGEN_COMPILED ${CMAKE_BINARY_DIR} ${CURRENT_TEST_SOURCES_DIR}/../config/has_eigen.cpp
                CMAKE_FLAGS "-DCMAKE_CXX_LINK_EXECUTABLE='echo not linking now...'" "-DINCLUDE_DIRECTORIES=${EIGEN3_INCLUDE_DIRS}")
endif()

# TODO: figure out if it is needed
# add_library(no_eh_support SHARED ${CURRENT_TEST_SOURCES_DIR}/no_eh_test_support.cpp)

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
