#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2018-2021 Aleksei Moskvin <alalmoskvin@gmail.com>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

cm_test(NAME ${CURRENT_PROJECT_NAME}_bench_test_modular_adaptor_fixed_cpp_int SOURCES bench_test_modular_adaptor_fixed.cpp)
target_compile_definitions(${CURRENT_PROJECT_NAME}_bench_test_modular_adaptor_fixed_cpp_int PUBLIC -DTEST_CPP_INT)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_modular_cpp_int_tests ${CURRENT_PROJECT_NAME}_bench_test_modular_adaptor_fixed_cpp_int)
set_target_properties(${CURRENT_PROJECT_NAME}_bench_test_modular_adaptor_fixed_cpp_int PROPERTIES CXX_STANDARD 17)
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(${CURRENT_PROJECT_NAME}_bench_test_modular_adaptor_fixed_cpp_int PRIVATE "-fconstexpr-steps=2147483647")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${CURRENT_PROJECT_NAME}_bench_test_modular_adaptor_fixed_cpp_int PRIVATE "-fconstexpr-ops-limit=4294967295")
endif()

include_directories(${CMAKE_WORKSPACE_SOURCES_DIR})
