#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

find_package(Boost REQUIRED COMPONENTS
    timer
    unit_test_framework
)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}

    ${CMAKE_WORKSPACE_NAME}::algebra
    ${CMAKE_WORKSPACE_NAME}::multiprecision
    ${CMAKE_WORKSPACE_NAME}::random

    ${Boost_LIBRARIES}
)

set(TESTS_NAMES
    "polynomial_dfs_benchmark"
)

foreach(TEST_NAME ${TESTS_NAMES})
    define_math_test(${TEST_NAME})
endforeach()


#get_target_property(my_include_dirs math_polynomial_dfs_benchmark_test INCLUDE_DIRECTORIES)
#message(include dirs: ${my_include_dirs})
