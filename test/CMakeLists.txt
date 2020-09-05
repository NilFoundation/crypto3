#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

                       $<TARGET_NAME_IF_EXISTS:boost_multiprecision>

                       ${Boost_LIBRARIES})


macro(define_algebra_test name)
    cm_test(NAME algebra_${name}_test SOURCES ${name}.cpp)

    target_include_directories(algebra_${name}_test PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(algebra_${name}_test PROPERTIES CXX_STANDARD 14)

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(algebra_${name}_test PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()

    cm_test(NAME algebra_${name}_examples_test SOURCES ../example/${name}.cpp)
    target_link_libraries(algebra_${name}_examples_test no_eh_support)

endmacro()

set(TESTS_NAMES 
"curves"
"fields"
"pairing"
)

foreach(TEST_NAME ${TESTS_NAMES})
    define_algebra_test(${TEST_NAME})
endforeach()
