#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

cm_find_package(${CMAKE_WORKSPACE_NAME}_block)

if(NOT Boost_UNIT_TEST_FRAMEWORK_FOUND)
    cm_find_package(Boost REQUIRED COMPONENTS unit_test_framework)
endif()

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                       ${${CURRENT_PROJECT_NAME}_INTERFACE_LIBRARIES}

                       ${CMAKE_WORKSPACE_NAME}::block

                       ${Boost_LIBRARIES})

macro(define_hash_test name)
    set(test_name "hash_${name}_test")

    set(additional_args "")
    if(ENABLE_JUNIT_TEST_OUTPUT)
        set(TEST_RESULTS_DIR "${CMAKE_CURRENT_BINARY_DIR}/junit_results")
        set(TEST_LOGS_DIR "${TEST_RESULTS_DIR}/logs")
        file(MAKE_DIRECTORY ${TEST_LOGS_DIR})

        set(additional_args "--log_format=JUNIT"
                            "--log_sink=${TEST_LOGS_DIR}/${test_name}.xml")
    endif()

    cm_test(NAME ${test_name} SOURCES ${name}.cpp)

    target_include_directories(${test_name} PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(${test_name} PROPERTIES
                          CXX_STANDARD 17
                          CXX_STANDARD_REQUIRED TRUE)

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(${test_name} PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()

    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${test_name} PRIVATE "-fconstexpr-steps=2147483647")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${test_name} PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif()

    target_compile_options(${test_name} PRIVATE "-ftemplate-backtrace-limit=0")

    string(CONCAT TEST_DATA ${CMAKE_CURRENT_SOURCE_DIR} "/data/" "${name}" ".json")
    target_compile_definitions(${test_name} PRIVATE TEST_DATA="${TEST_DATA}")

endmacro()

set(TESTS_NAMES
    "blake2b"
    "crc"
    "keccak"
    "md4"
    "md5"
    "pack"
    "ripemd"
    "sha"
    "sha1"
    "sha2"
    "sha3"
    "static_digest"
    "tiger"
    "poseidon"
    )
    # "reinforced_concrete")  # fails

if(CRYPTO3_HASH_PEDERSEN)
    list(APPEND TESTS_NAMES
         find_group_hash
         h2c
         h2f)

    if(CRYPTO3_HASH_PEDERSEN)
        list(APPEND TESTS_NAMES pedersen)
    endif()
endif()

foreach(TEST_NAME ${TESTS_NAMES})
    define_hash_test(${TEST_NAME})
endforeach()
