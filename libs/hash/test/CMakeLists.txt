#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

cm_find_package(${CMAKE_WORKSPACE_NAME}_block)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                       ${${CURRENT_PROJECT_NAME}_INTERFACE_LIBRARIES}

                       ${CMAKE_WORKSPACE_NAME}::block

                       Boost::unit_test_framework)

macro(define_hash_test name)
    set(test_name "hash_${name}_test")

    cm_test(NAME ${test_name} SOURCES ${name}.cpp)

    target_include_directories(${test_name} PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(${test_name} PROPERTIES
                          CXX_STANDARD 17
                          CXX_STANDARD_REQUIRED TRUE)

    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${test_name} PRIVATE "-fconstexpr-steps=2147483647")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${test_name} PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif()

    target_compile_options(${test_name} PRIVATE "-ftemplate-backtrace-limit=0")

    string(CONCAT TEST_DATA ${CMAKE_CURRENT_SOURCE_DIR} "/data/" "${name}" ".json")
    target_compile_definitions(${test_name} PRIVATE TEST_DATA="${TEST_DATA}")

    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${test_name} PRIVATE "-fconstexpr-steps=2147483647")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${test_name} PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif()

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
    "hash_to_curve"
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
