#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#



macro(define_pubkey_example name)
    add_executable(pubkey_${name}_example ${name}.cpp)
    target_link_libraries(pubkey_${name}_example PRIVATE
                          ${CMAKE_WORKSPACE_NAME}_pubkey

                          ${CMAKE_WORKSPACE_NAME}::block
                          ${CMAKE_WORKSPACE_NAME}::hash
                          ${CMAKE_WORKSPACE_NAME}::algebra
                          ${CMAKE_WORKSPACE_NAME}::multiprecision

                          Boost::container)
    set_target_properties(pubkey_${name}_example PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED TRUE)
endmacro()



set(EXAMPLES_NAMES
    "bls")

foreach(EXAMPLE_NAME ${EXAMPLES_NAMES})
    define_pubkey_example(${EXAMPLE_NAME})
endforeach()
