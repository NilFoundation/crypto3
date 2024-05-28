#---------------------------------------------------------------------------#
# Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                       Boost::unit_test_framework
                       Boost::random
                   )

macro(define_marshalling_test name)
    get_filename_component(name ${name} NAME)

    set(test_name "marshalling_${name}_test")

    cm_test(NAME ${test_name} SOURCES ${name}.cpp)

    target_include_directories(marshalling_${name}_test PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(marshalling_${name}_test PROPERTIES
                          CXX_STANDARD 11
                          CXX_STANDARD_REQUIRED TRUE)
endmacro()

set(TESTS_NAMES
    "pack"
    "processing"
    "types"
    "interfaces")

foreach(TEST_NAME ${TESTS_NAMES})
    define_marshalling_test(${TEST_NAME})
endforeach()
