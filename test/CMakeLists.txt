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
    cm_test(NAME algebra_${name}_test SOURCES ${name}.cpp)

    target_include_directories(algebra_${name}_test PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(algebra_${name}_test PROPERTIES CXX_STANDARD 17
        CXX_STANDARD_REQUIRED TRUE)

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(algebra_${name}_test PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()

    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(algebra_${name}_test PRIVATE "-fconstexpr-steps=2147483647")
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(algebra_${name}_test PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif()
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
    "curves_static"
    "fields"
    "fields_static"
    "pairing"
    "hash_to_curve"
    "wnaf"
    "multiexp"
    #    "groups"
    #    "bilinearity"
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
