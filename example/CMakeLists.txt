#---------------------------------------------------------------------------#
# Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

macro(define_algebra_example name)
    add_executable(algebra_${name}_example ${name}.cpp)
    target_link_libraries(algebra_${name}_example PRIVATE
                          ${CMAKE_WORKSPACE_NAME}_algebra

                          $<TARGET_NAME_IF_EXISTS:boost_multiprecision>

                          ${Boost_LIBRARIES})
    set_target_properties(algebra_${name}_example PROPERTIES CXX_STANDARD 14)
endmacro()

set(EXAMPLES_NAMES
    "multiexp"
    "curves"
    "fields"
    "pairing"
    "random_element"
    "hash_to_curve")

foreach(EXAMPLE_NAME ${EXAMPLES_NAMES})
    define_algebra_example(${EXAMPLE_NAME})
endforeach()
