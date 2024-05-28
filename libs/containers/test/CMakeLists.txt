#---------------------------------------------------------------------------//
#  MIT License
#
#  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
#  Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in all
#  copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#  SOFTWARE.
#---------------------------------------------------------------------------//

include(CMTest)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}

                       ${CMAKE_WORKSPACE_NAME}::algebra
                       ${CMAKE_WORKSPACE_NAME}::hash

                       Boost::unit_test_framework
                       Boost::random
                   )

macro(define_storage_test test)
    get_filename_component(test_name ${test} NAME)
    set(target_name ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_${test_name}_test)

    while(TARGET ${target_name})
        get_filename_component(TEST_DIRECTORY ${test} DIRECTORY)
        get_filename_component(PARENT_DIR ${TEST_DIRECTORY} DIRECTORY)
        set(target_name ${PARENT_DIR}_${target_name})
    endwhile()

    cm_test(NAME ${target_name} SOURCES ${test}.cpp)

    target_include_directories(${target_name} PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(${target_name} PROPERTIES CXX_STANDARD 17)

     if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${target_name} PRIVATE "-fconstexpr-steps=2147483647" "-ftemplate-backtrace-limit=0")
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${target_name} PRIVATE "-fconstexpr-ops-limit=4294967295" "-ftemplate-backtrace-limit=0")
    endif()

endmacro()

set(TESTS_NAMES
    "merkle/merkle"
)

foreach(TEST_NAME ${TESTS_NAMES})
    define_storage_test(${TEST_NAME})
endforeach()
