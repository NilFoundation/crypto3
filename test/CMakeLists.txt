#---------------------------------------------------------------------------#
# Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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

                       ${CMAKE_WORKSPACE_NAME}::multiprecision

                       ${Boost_LIBRARIES})


macro(define_runtime_algebra_test name)
    set(test_name "algebra_${name}_test")

    set(additional_args "")
    if(ENABLE_JUNIT_TEST_OUTPUT)
        set(TEST_RESULTS_DIR "${CMAKE_CURRENT_BINARY_DIR}/junit_results")
        set(TEST_LOGS_DIR "${TEST_RESULTS_DIR}/logs")
        file(MAKE_DIRECTORY ${TEST_LOGS_DIR})

        set(additional_args "--log_format=JUNIT"
                            "--log_sink=${TEST_LOGS_DIR}/${test_name}.xml")
    endif()

    cm_test(NAME ${test_name} SOURCES ${name}.cpp ARGS ${additional_args})

    target_include_directories(${test_name} PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(${test_name} PROPERTIES CXX_STANDARD 17
        CXX_STANDARD_REQUIRED TRUE)

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(${test_name} PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()

    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${test_name} PRIVATE "-fconstexpr-steps=2147483647")
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${test_name} PRIVATE "-fconstexpr-ops-limit=4294967295")
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

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(algebra_${name}_compile_test PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()
endmacro()

set(RUNTIME_TESTS_NAMES
    "curves"
    "short_weierstrass_coordinates"
    "curves_static"
    "fields"
    "fields_static"
    "pairing"
    "hash_to_curve"
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
