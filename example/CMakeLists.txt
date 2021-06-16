#---------------------------------------------------------------------------#
# Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

macro(define_blueprint_example name)
    add_executable(blueprint_${name}_example ${name}.cpp)
    target_link_libraries(blueprint_${name}_example PRIVATE
                          ${CMAKE_WORKSPACE_NAME}_blueprint

                          ${CMAKE_WORKSPACE_NAME}::algebra
                          ${CMAKE_WORKSPACE_NAME}::fft
                          ${CMAKE_WORKSPACE_NAME}::block
                          ${CMAKE_WORKSPACE_NAME}::hash
                          ${CMAKE_WORKSPACE_NAME}::multiprecision
                          ${CMAKE_WORKSPACE_NAME}::zk

                          ${Boost_LIBRARIES})
    set_target_properties(blueprint_${name}_example PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED TRUE)
endmacro()



set(EXAMPLES_NAMES
    "curves"
    "test_component")

foreach(EXAMPLE_NAME ${EXAMPLES_NAMES})
    define_blueprint_example(${EXAMPLE_NAME})
endforeach()
