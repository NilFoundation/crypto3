#---------------------------------------------------------------------------#
# Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
# Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

macro(define_marshalling_example name)
    add_executable(marshalling_${name}_example ${name}.cpp)

    target_link_libraries(marshalling_${name}_example PRIVATE
            ${CMAKE_WORKSPACE_NAME}::core

            Boost::container)

    target_include_directories(marshalling_${name}_example PRIVATE
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
            "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

            ${Boost_INCLUDE_DIRS})

    set_target_properties(marshalling_${name}_example PROPERTIES
            CXX_STANDARD 11
            CXX_STANDARD_REQUIRED TRUE)
endmacro()

set(EXAMPLES_NAMES
        "interfaces"
        "pack"
        "endian")

foreach (EXAMPLES_NAME ${EXAMPLES_NAMES})
    define_marshalling_example(${EXAMPLES_NAME})
endforeach ()
