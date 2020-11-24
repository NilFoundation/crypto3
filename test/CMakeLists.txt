#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

if(NOT Boost_UNIT_TEST_FRAMEWORK_FOUND)
    cm_find_package(Boost REQUIRED COMPONENTS unit_test_framework)
endif()

cm_test_link_libraries(${CURRENT_PROJECT_NAME} ${Boost_LIBRARIES})

macro(define_marshalling_test name)
    cm_test(NAME marshalling_${name}_test SOURCES ${name}.cpp)

    target_include_directories(marshalling_${name}_test PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(marshalling_${name}_test PROPERTIES
                          CXX_STANDARD 11
                          CXX_STANDARD_REQUIRED TRUE)
    
    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(marshalling_${name}_test PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()
endmacro()

set(TESTS_NAMES
    "utilities"
    "checksum_prefix_layer"
    "fields"
    "msg_size_layer"
    "message"
    "msg_id_layer"
    "sync_prefix_layer"
    "msg_data_layer"
    "checksum_layer"
    "transport_value_layer")

foreach(TEST_NAME ${TESTS_NAMES})
    define_marshalling_test(${TEST_NAME})
endforeach()
