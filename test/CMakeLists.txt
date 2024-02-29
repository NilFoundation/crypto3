#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

if(NOT Boost_UNIT_TEST_FRAMEWORK_FOUND)
    cm_find_package(Boost REQUIRED COMPONENTS unit_test_framework)
endif()

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                       ${Boost_LIBRARIES})

macro(define_block_cipher_test name)
    set(test_name "block_${name}_test")

    cm_test(NAME ${test_name} SOURCES ${name}.cpp)

    target_include_directories(${test_name} PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    if(NOT CMAKE_CXX_STANDARD)
        set_target_properties(${test_name} PROPERTIES CXX_STANDARD 14)
    endif()

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(${test_name} PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()

    string(CONCAT TEST_DATA ${CMAKE_CURRENT_SOURCE_DIR} "/data/" "${name}" ".json")
    target_compile_definitions(${test_name} PRIVATE TEST_DATA="${TEST_DATA}")
endmacro()

set(TESTS_NAMES
    "injector"
    "kasumi"
    "md4"
    "md5"
    "pack"
    "rijndael"
    "shacal"
    "shacal2")

foreach(TEST_NAME ${TESTS_NAMES})
    define_block_cipher_test(${TEST_NAME})
endforeach()
