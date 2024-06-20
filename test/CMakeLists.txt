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

                      crypto3::all
                      ${Boost_LIBRARIES})

add_custom_target(compile_and_run_transpiler_tests)

macro(define_transpiler_test name)
    cm_test(NAME transpiler_${name}_test SOURCES ${name}.cpp)

    target_include_directories(transpiler_${name}_test PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(transpiler_${name}_test PROPERTIES CXX_STANDARD 17)

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(transpiler_${name}_test PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()
    add_custom_target(transpiler_${name}_test_run
        COMMAND $<TARGET_FILE:transpiler_${name}_test>
        DEPENDS transpiler_${name}_test $<TARGET_FILE:transpiler_${name}_test>
    )
    add_dependencies(compile_and_run_transpiler_tests transpiler_${name}_test_run)

endmacro()

set(TESTS_NAMES
    "transpiler"
)

foreach(TEST_NAME ${TESTS_NAMES})
    define_transpiler_test(${TEST_NAME})
endforeach()
