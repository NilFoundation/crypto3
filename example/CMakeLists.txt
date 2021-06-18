#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/../include"
        "${CMAKE_CURRENT_BINARY_DIR}/include"

        ${Boost_INCLUDE_DIRS})

macro(define_random_example name)
    add_executable(random_${name}_example ${name}.cpp)
    target_link_libraries(random_${name}_example PRIVATE
            ${CMAKE_WORKSPACE_NAME}::algebra
            ${CMAKE_WORKSPACE_NAME}::hash
            ${CMAKE_WORKSPACE_NAME}::mac
            ${CMAKE_WORKSPACE_NAME}::stream
            ${CMAKE_WORKSPACE_NAME}::multiprecision

            ${Boost_LIBRARIES})
    set_target_properties(random_${name}_example PROPERTIES CXX_STANDARD 17)
endmacro()

set(EXAMPLES_NAMES
        "hash")

foreach(EXAMPLE_NAME ${EXAMPLES_NAMES})
    define_random_example(${EXAMPLE_NAME})
endforeach()
