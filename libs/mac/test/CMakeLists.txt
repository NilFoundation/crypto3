#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

cm_find_package(${CMAKE_WORKSPACE_NAME}_block)
cm_find_package(${CMAKE_WORKSPACE_NAME}_hash)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                       Boost::unit_test_framework)

macro(define_mac_test name)
    cm_test(NAME ${name}_test SOURCES ${name}.cpp)

    target_include_directories(${name}_test PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(${name}_test PROPERTIES CXX_STANDARD 14)

endmacro()

set(TESTS_NAMES "hmac"
#"cmac" "gmac" "siphash" "x919_mac" "cbc_mac" "poly1305"
)

foreach(TEST_NAME ${TESTS_NAMES})
    define_mac_test(${TEST_NAME})
endforeach()
