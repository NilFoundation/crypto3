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
                       ${CMAKE_WORKSPACE_NAME}::block

                       ${Boost_LIBRARIES})

macro(define_hash_test name)
    cm_test(NAME hash_${name}_test SOURCES ${name}.cpp)

    target_include_directories(hash_${name}_test PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(hash_${name}_test PROPERTIES
                          CXX_STANDARD 14
                          CXX_STANDARD_REQUIRED TRUE)

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(hash_${name}_test PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()
endmacro()

set(TESTS_NAMES
    "blake2b"
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
    "tiger")

foreach(TEST_NAME ${TESTS_NAMES})
    define_hash_test(${TEST_NAME})
endforeach()
