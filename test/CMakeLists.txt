#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2018-2021 Aleksei Moskvin <alalmoskvin@gmail.com>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

find_package(Eigen3)

if(BOOST_CMAKE)
    find_package(${CMAKE_WORKSPACE_NAME}_algorithm)
    find_package(${CMAKE_WORKSPACE_NAME}_chrono)
    find_package(${CMAKE_WORKSPACE_NAME}_exception)
    find_package(${CMAKE_WORKSPACE_NAME}_timer)
    find_package(${CMAKE_WORKSPACE_NAME}_filesystem)
    find_package(${CMAKE_WORKSPACE_NAME}_test)
    find_package(${CMAKE_WORKSPACE_NAME}_serialization)
    find_package(${CMAKE_WORKSPACE_NAME}_numeric_interval)
    find_package(${CMAKE_WORKSPACE_NAME}_detail)
    find_package(${CMAKE_WORKSPACE_NAME}_throw_exception)
    find_package(${CMAKE_WORKSPACE_NAME}_math)
    find_package(${CMAKE_WORKSPACE_NAME}_regexp)

    cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                           ${CMAKE_WORKSPACE_NAME}::algorithm
                           ${CMAKE_WORKSPACE_NAME}::chrono
                           ${CMAKE_WORKSPACE_NAME}::exception
                           ${CMAKE_WORKSPACE_NAME}::timer
                           ${CMAKE_WORKSPACE_NAME}::numeric_ublas
                           ${CMAKE_WORKSPACE_NAME}::filesystem
                           ${CMAKE_WORKSPACE_NAME}::test
                           ${CMAKE_WORKSPACE_NAME}::serialization
                           ${CMAKE_WORKSPACE_NAME}::numeric_interval
                           ${CMAKE_WORKSPACE_NAME}::detail
                           ${CMAKE_WORKSPACE_NAME}::throw_exception
                           ${CMAKE_WORKSPACE_NAME}::math
                           ${CMAKE_WORKSPACE_NAME}::regexp)
else()
    find_package(Boost REQUIRED COMPONENTS chrono filesystem unit_test_framework serialization regex)
    list(APPEND ${CURRENT_PROJECT_NAME}_LIBRARIES ${Boost_LIBRARIES})
    find_package(Boost COMPONENTS timer exception)
    list(APPEND ${CURRENT_PROJECT_NAME}_LIBRARIES ${Boost_LIBRARIES})

    cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                           ${${CURRENT_PROJECT_NAME}_LIBRARIES})

    include_directories("${CMAKE_CURRENT_SOURCE_DIR}/../include"
                        "${CMAKE_CURRENT_BINARY_DIR}/include"

                        ${Boost_INCLUDE_DIRS})
endif()

add_custom_target(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests)
add_custom_target(${CURRENT_PROJECT_NAME}_test_suite_functions_and_limits)
add_custom_target(${CURRENT_PROJECT_NAME}_test_suite_conversions)
add_custom_target(${CURRENT_PROJECT_NAME}_test_suite_cpp_int_tests)
add_custom_target(${CURRENT_PROJECT_NAME}_test_suite_modular_cpp_int_tests)
add_custom_target(${CURRENT_PROJECT_NAME}_test_suite_misc)
add_custom_target(${CURRENT_PROJECT_NAME}_test_suite_specfun)
add_custom_target(${CURRENT_PROJECT_NAME}_test_suite_concepts)
add_custom_target(${CURRENT_PROJECT_NAME}_test_suite_examples)
add_custom_target(${CURRENT_PROJECT_NAME}_test_suite_compile_fail)

# copyright John Maddock 2011
# Distributed under the Boost Software License, Version 1.0.
# (See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt.

# HACK: Workaround broken includes
file(GLOB TEST_HEADERS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/*.hpp ${CMAKE_CURRENT_SOURCE_DIR}/*.ipp)
set(CMAKE_INCLUDE_CURRENT_DIR TRUE)
foreach(HEADER ${TEST_HEADERS})
    configure_file(${HEADER} ${CMAKE_CURRENT_BINARY_DIR}/libs/${CURRENT_PROJECT_NAME}/test/${HEADER}
                   @ONLY)
endforeach()

add_library(${CURRENT_PROJECT_NAME}_test_settings INTERFACE)
target_include_directories(${CURRENT_PROJECT_NAME}_test_settings INTERFACE ${CURRENT_TEST_SOURCES_DIR}/include)
cm_test_link_libraries(${CURRENT_PROJECT_NAME}_test_settings)

if(EIGEN_FOUND)
    try_compile(EIGEN_COMPILED ${CMAKE_BINARY_DIR} ${CURRENT_TEST_SOURCES_DIR}/../config/has_eigen.cpp
                CMAKE_FLAGS "-DCMAKE_CXX_LINK_EXECUTABLE='echo not linking now...'" "-DINCLUDE_DIRECTORIES=${EIGEN3_INCLUDE_DIRS}")
endif()

add_library(no_eh_support SHARED ${CURRENT_TEST_SOURCES_DIR}/no_eh_test_support.cpp)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_backend_concept SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_backend_concept.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_backend_concept no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_backend_concept)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_backend_concept PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_1 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_cpp_int_1.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_1 no_eh_support)
if(MSVC)
    target_compile_options(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_1 PRIVATE /bigobj)
endif()
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_1)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_1 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_2 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_cpp_int_2.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_2 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_2)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_2 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_3 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_cpp_int_3.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_3 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_3)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_3 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_4 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_cpp_int_4.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_4 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_4)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_4 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_5 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_cpp_int_5.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_5 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_5)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_5 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_6 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_cpp_int_6.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_6 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_6)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_6 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_7 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_cpp_int_7.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_7 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_7)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_7 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_8 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_cpp_int_8.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_8 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_8)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_8 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_9 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_cpp_int_9.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_9 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_9)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_9 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_10 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_cpp_int_10.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_10 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_10)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_10 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_11 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_cpp_int_11.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_11 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_11)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_11 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_12 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_cpp_int_12.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_12 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_12)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_12 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_13 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_cpp_int_13.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_13 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_13)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_13 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_14 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_cpp_int_14.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_14 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_14)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_14 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_15 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_cpp_int_15.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_15 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_15)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_15 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_16 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_cpp_int_16.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_16 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_16)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_16 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_17 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_cpp_int_17.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_17 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_17)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_17 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_18 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_cpp_int_18.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_18 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_18)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_18 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_19 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_cpp_int_19.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_19 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_19)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_19 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_br SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_cpp_int_br.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_br no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_br)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_cpp_int_br PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_ab_1 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_ab_1.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_ab_1 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_ab_1)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_ab_1 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_ab_2 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_ab_2.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_ab_2 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_ab_2)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_ab_2 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_ab_3 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_ab_3.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_ab_3 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_ab_3)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_ab_3 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_logged_1 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_logged_1.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_logged_1 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_logged_1)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_logged_1 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_logged_2 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_logged_2.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_logged_2 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_logged_2)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_logged_2 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_dbg_adptr1 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_dbg_adptr1.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_dbg_adptr1 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_dbg_adptr1)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_dbg_adptr1 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_dbg_adptr1m SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_dbg_adptr1m.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_dbg_adptr1m no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_dbg_adptr1m)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_dbg_adptr1m PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_arithmetic_dbg_adptr2 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_arithmetic_dbg_adptr2.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_arithmetic_dbg_adptr2 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_arithmetic_tests ${CURRENT_PROJECT_NAME}_test_test_arithmetic_dbg_adptr2)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_arithmetic_dbg_adptr2 PROPERTIES CXX_STANDARD 14)

set(LOCAL_SOURCES
    test_exp.cpp
    test_log.cpp
    test_pow.cpp
    test_sinh.cpp
    test_sqrt.cpp
    test_round.cpp
    test_fpclassify.cpp
    test_sf_import_c99.cpp)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_numeric_limits_backend_concept SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_numeric_limits.cpp)
target_compile_definitions(${CURRENT_PROJECT_NAME}_test_test_numeric_limits_backend_concept PUBLIC -DTEST_BACKEND)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_numeric_limits_backend_concept no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_functions_and_limits ${CURRENT_PROJECT_NAME}_test_test_numeric_limits_backend_concept)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_numeric_limits_backend_concept PROPERTIES CXX_STANDARD 14)


if(NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_numeric_limits_cpp_int SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_numeric_limits.cpp)
    target_compile_definitions(${CURRENT_PROJECT_NAME}_test_test_numeric_limits_cpp_int PUBLIC -DTEST_CPP_INT)
    target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_numeric_limits_cpp_int no_eh_support)
    add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_functions_and_limits ${CURRENT_PROJECT_NAME}_test_test_numeric_limits_cpp_int)
    set_target_properties(${CURRENT_PROJECT_NAME}_test_test_numeric_limits_cpp_int PROPERTIES CXX_STANDARD 14)
endif()

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_move_cpp_int SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_move.cpp)
target_compile_definitions(${CURRENT_PROJECT_NAME}_test_test_move_cpp_int PUBLIC -DTEST_CPP_INT)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_move_cpp_int no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_functions_and_limits ${CURRENT_PROJECT_NAME}_test_test_move_cpp_int)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_move_cpp_int PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_test SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_test.cpp)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_test PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_cpp_int_lit SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_cpp_int_lit.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_cpp_int_lit no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_conversions ${CURRENT_PROJECT_NAME}_test_test_cpp_int_lit)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_cpp_int_lit PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_int_io_cpp_int SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_int_io.cpp)
target_compile_definitions(${CURRENT_PROJECT_NAME}_test_test_int_io_cpp_int PUBLIC -DTEST_CPP_INT)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_int_io_cpp_int no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_cpp_int_tests ${CURRENT_PROJECT_NAME}_test_test_int_io_cpp_int)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_int_io_cpp_int PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_unchecked_cpp_int SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_unchecked_cpp_int.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_unchecked_cpp_int no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_cpp_int_tests ${CURRENT_PROJECT_NAME}_test_test_unchecked_cpp_int)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_unchecked_cpp_int PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_nothrow_cpp_int SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_nothrow_cpp_int.cpp COMPILE_ONLY)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_misc ${CURRENT_PROJECT_NAME}_test_test_nothrow_cpp_int)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_nothrow_cpp_int PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_nothrow_cpp_rational SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_nothrow_cpp_rational.cpp COMPILE_ONLY)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_misc ${CURRENT_PROJECT_NAME}_test_test_nothrow_cpp_rational)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_nothrow_cpp_rational PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_cpp_int_conv SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_cpp_int_conv.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_cpp_int_conv no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_misc ${CURRENT_PROJECT_NAME}_test_test_cpp_int_conv)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_cpp_int_conv PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_cpp_int_import_export SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_cpp_int_import_export.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_cpp_int_import_export no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_misc ${CURRENT_PROJECT_NAME}_test_test_cpp_int_import_export)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_cpp_int_import_export PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_include_test_cpp_int_include_test SOURCES ${CURRENT_TEST_SOURCES_DIR}/include_test/cpp_int_include_test.cpp COMPILE_ONLY)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_misc ${CURRENT_PROJECT_NAME}_test_include_test_cpp_int_include_test)
set_target_properties(${CURRENT_PROJECT_NAME}_test_include_test_cpp_int_include_test PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_checked_mixed_cpp_int SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_checked_mixed_cpp_int.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_test_checked_mixed_cpp_int no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_misc ${CURRENT_PROJECT_NAME}_test_test_checked_mixed_cpp_int)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_checked_mixed_cpp_int PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_bug11922 SOURCES ${CURRENT_TEST_SOURCES_DIR}/bug11922.cpp COMPILE_ONLY)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_misc ${CURRENT_PROJECT_NAME}_test_bug11922)
set_target_properties(${CURRENT_PROJECT_NAME}_test_bug11922 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_bug12039 SOURCES ${CURRENT_TEST_SOURCES_DIR}/bug12039.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_bug12039 no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_misc ${CURRENT_PROJECT_NAME}_test_bug12039)
set_target_properties(${CURRENT_PROJECT_NAME}_test_bug12039 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_git_issue_30 SOURCES ${CURRENT_TEST_SOURCES_DIR}/git_issue_30.cpp COMPILE_ONLY)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_misc ${CURRENT_PROJECT_NAME}_test_git_issue_30)
set_target_properties(${CURRENT_PROJECT_NAME}_test_git_issue_30 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_issue_13301 SOURCES ${CURRENT_TEST_SOURCES_DIR}/issue_13301.cpp)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_misc ${CURRENT_PROJECT_NAME}_test_issue_13301)
set_target_properties(${CURRENT_PROJECT_NAME}_test_issue_13301 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_issue_13148 SOURCES ${CURRENT_TEST_SOURCES_DIR}/issue_13148.cpp)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_misc ${CURRENT_PROJECT_NAME}_test_issue_13148)
set_target_properties(${CURRENT_PROJECT_NAME}_test_issue_13148 PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_optional_compat SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_optional_compat.cpp)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_misc ${CURRENT_PROJECT_NAME}_test_test_optional_compat)
set_target_properties(${CURRENT_PROJECT_NAME}_test_test_optional_compat PROPERTIES CXX_STANDARD 14)

if(BUILD_WITH_SOURCES_DIR)
    file(GLOB TEST_FILES ${CURRENT_TEST_SOURCES_DIR}/concepts/*.cpp)
    foreach(FILEB ${TEST_FILES})
        get_filename_component(NAME ${FILEB} NAME_WE)

        cm_test(NAME ${CURRENT_PROJECT_NAME}_test_concepts_${NAME}_backend_concept SOURCES ${FILEB} COMPILE_ONLY)
        target_compile_definitions(${CURRENT_PROJECT_NAME}_test_concepts_${NAME}_backend_concept PUBLIC -DTEST_BACKEND)
        target_include_directories(${CURRENT_PROJECT_NAME}_test_concepts_${NAME}_backend_concept PRIVATE ${BUILD_WITH_SOURCES_DIR})
        add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_concepts ${CURRENT_PROJECT_NAME}_test_concepts_${NAME}_backend_concept)

        cm_test(NAME ${CURRENT_PROJECT_NAME}_test_concepts_${NAME}_logged_adaptor SOURCES ${FILEB} COMPILE_ONLY)
        target_compile_definitions(${CURRENT_PROJECT_NAME}_test_concepts_${NAME}_logged_adaptor PUBLIC -DTEST_LOGGED_ADAPTER)
        target_include_directories(${CURRENT_PROJECT_NAME}_test_concepts_${NAME}_logged_adaptor PRIVATE ${BUILD_WITH_SOURCES_DIR})
        add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_concepts ${CURRENT_PROJECT_NAME}_test_concepts_${NAME}_logged_adaptor)
    endforeach()
endif()

#test-suite examples

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_cpp_int_snips SOURCES ${CURRENT_TEST_SOURCES_DIR}/../example/cpp_int_snips.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_cpp_int_snips no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_examples ${CURRENT_PROJECT_NAME}_test_cpp_int_snips)
set_target_properties(${CURRENT_PROJECT_NAME}_test_cpp_int_snips PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_cpp_int_import_export SOURCES ${CURRENT_TEST_SOURCES_DIR}/../example/cpp_int_import_export.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_cpp_int_import_export no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_examples ${CURRENT_PROJECT_NAME}_test_cpp_int_import_export)
set_target_properties(${CURRENT_PROJECT_NAME}_test_cpp_int_import_export PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_debug_adaptor_snips SOURCES ${CURRENT_TEST_SOURCES_DIR}/../example/debug_adaptor_snips.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_debug_adaptor_snips no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_examples ${CURRENT_PROJECT_NAME}_test_debug_adaptor_snips)
set_target_properties(${CURRENT_PROJECT_NAME}_test_debug_adaptor_snips PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_integer_examples SOURCES ${CURRENT_TEST_SOURCES_DIR}/../example/integer_examples.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_integer_examples no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_examples ${CURRENT_PROJECT_NAME}_test_integer_examples)
set_target_properties(${CURRENT_PROJECT_NAME}_test_integer_examples PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_mixed_integer_arithmetic SOURCES ${CURRENT_TEST_SOURCES_DIR}/../example/mixed_integer_arithmetic.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_mixed_integer_arithmetic no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_examples ${CURRENT_PROJECT_NAME}_test_mixed_integer_arithmetic)
set_target_properties(${CURRENT_PROJECT_NAME}_test_mixed_integer_arithmetic PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_safe_prime SOURCES ${CURRENT_TEST_SOURCES_DIR}/../example/safe_prime.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_safe_prime no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_examples ${CURRENT_PROJECT_NAME}_test_safe_prime)
set_target_properties(${CURRENT_PROJECT_NAME}_test_safe_prime PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_modular_examples SOURCES ${CURRENT_TEST_SOURCES_DIR}/../example/modular_examples.cpp)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_modular_examples no_eh_support)
set_target_properties(${CURRENT_PROJECT_NAME}_test_modular_examples PROPERTIES CXX_STANDARD 17)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_modular_adaptor_cpp_int SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_modular_adaptor.cpp)
target_compile_definitions(${CURRENT_PROJECT_NAME}_test_modular_adaptor_cpp_int PUBLIC -DTEST_CPP_INT)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_modular_adaptor_cpp_int no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_modular_cpp_int_tests ${CURRENT_PROJECT_NAME}_test_modular_adaptor_cpp_int)
set_target_properties(${CURRENT_PROJECT_NAME}_test_modular_adaptor_cpp_int PROPERTIES CXX_STANDARD 17)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_modular_adaptor_fixed_cpp_int SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_modular_adaptor_fixed.cpp)
target_compile_definitions(${CURRENT_PROJECT_NAME}_test_modular_adaptor_fixed_cpp_int PUBLIC -DTEST_CPP_INT)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_modular_adaptor_fixed_cpp_int no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_modular_cpp_int_tests ${CURRENT_PROJECT_NAME}_test_modular_adaptor_fixed_cpp_int)
set_target_properties(${CURRENT_PROJECT_NAME}_test_modular_adaptor_fixed_cpp_int PROPERTIES CXX_STANDARD 17)
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(${CURRENT_PROJECT_NAME}_test_modular_adaptor_fixed_cpp_int PRIVATE "-fconstexpr-steps=2147483647")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${CURRENT_PROJECT_NAME}_test_modular_adaptor_fixed_cpp_int PRIVATE "-fconstexpr-ops-limit=4294967295")
endif()

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_jacobi_cpp_int SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_jacobi.cpp)
target_compile_definitions(${CURRENT_PROJECT_NAME}_test_jacobi_cpp_int PUBLIC -DTEST_CPP_INT)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_jacobi_cpp_int no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_modular_cpp_int_tests ${CURRENT_PROJECT_NAME}_test_jacobi_cpp_int)
set_target_properties(${CURRENT_PROJECT_NAME}_test_jacobi_cpp_int PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_ressol_cpp_int SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_ressol.cpp)
target_compile_definitions(${CURRENT_PROJECT_NAME}_test_ressol_cpp_int PUBLIC -DTEST_CPP_INT)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_ressol_cpp_int no_eh_support)
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(${CURRENT_PROJECT_NAME}_test_ressol_cpp_int PRIVATE "-fconstexpr-steps=2147483647")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${CURRENT_PROJECT_NAME}_test_ressol_cpp_int PRIVATE "-fconstexpr-ops-limit=4294967295")
endif()
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_modular_cpp_int_tests ${CURRENT_PROJECT_NAME}_test_ressol_cpp_int)
set_target_properties(${CURRENT_PROJECT_NAME}_test_ressol_cpp_int PROPERTIES CXX_STANDARD 14)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_inverse_cpp_int SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_inverse.cpp)
target_compile_definitions(${CURRENT_PROJECT_NAME}_test_inverse_cpp_int PUBLIC -DTEST_CPP_INT)
target_link_libraries(${CURRENT_PROJECT_NAME}_test_inverse_cpp_int no_eh_support)
add_dependencies(${CURRENT_PROJECT_NAME}_test_suite_modular_cpp_int_tests ${CURRENT_PROJECT_NAME}_test_inverse_cpp_int)
set_target_properties(${CURRENT_PROJECT_NAME}_test_inverse_cpp_int PROPERTIES CXX_STANDARD 17)

include_directories(${CMAKE_WORKSPACE_SOURCES_DIR})
