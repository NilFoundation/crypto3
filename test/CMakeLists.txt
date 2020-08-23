#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2018-2020 Alexey Moskvin
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

if(BOOST_CMAKE)
    find_package(${CMAKE_WORKSPACE_NAME}_filesystem)
    find_package(${CMAKE_WORKSPACE_NAME}_test)
    find_package(${CMAKE_WORKSPACE_NAME}_math)
    find_package(${CMAKE_WORKSPACE_NAME}_multiprecision)

    cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                           ${CMAKE_WORKSPACE_NAME}::filesystem
                           ${CMAKE_WORKSPACE_NAME}::test
                           ${CMAKE_WORKSPACE_NAME}::math
                           ${CMAKE_WORKSPACE_NAME}::multiprecision

                           crypto3::hash
                           crypto3::mac
                           crypto3::stream)
else()
    find_package(Boost REQUIRED COMPONENTS filesystem unit_test_framework)

    cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}

                           crypto3::hash
                           crypto3::mac
                           crypto3::stream

                           $<TARGET_NAME_IF_EXISTS:boost_multiprecision>

                           ${Boost_LIBRARIES})

    include_directories("${CMAKE_CURRENT_SOURCE_DIR}/../include"
                        "${CMAKE_CURRENT_BINARY_DIR}/include"

                        ${Boost_INCLUDE_DIRS})
endif()

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_const_mod SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_const_mod.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_generate_canonical SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_generate_canonical.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_random_number_generator SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_random_number_generator.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_random_device SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_random_device.cpp)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_minstd_rand0 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_minstd_rand0.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_minstd_rand SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_minstd_rand.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_rand48 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_rand48.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_mt11213b SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_mt11213b.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_mt19937 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_mt19937.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_mt19937_64 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_mt19937_64.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_mixmax SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_mixmax.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_ecuyer1988 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_ecuyer1988.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_hellekalek1995 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_hellekalek1995.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_linear_feedback_shift SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_linear_feedback_shift.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_taus88 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_taus88.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_kreutzer1986 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_kreutzer1986.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_ranlux3 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_ranlux3.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_ranlux4 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_ranlux4.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_ranlux3_01 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_ranlux3_01.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_ranlux4_01 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_ranlux4_01.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_ranlux64_4 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_ranlux64_4.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_ranlux64_3 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_ranlux64_3.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_ranlux64_3_01 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_ranlux64_3_01.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_ranlux64_4_01 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_ranlux64_4_01.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_ranlux24_base SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_ranlux24_base.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_ranlux24 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_ranlux24.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_ranlux48_base SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_ranlux48_base.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_ranlux48 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_ranlux48.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_knuth_b SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_knuth_b.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_independent_bits31 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_independent_bits31.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_independent_bits32 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_independent_bits32.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_lagged_fibonacci SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_lagged_fibonacci.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_lagged_fibonacci607 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_lagged_fibonacci607.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_lagged_fibonacci1279 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_lagged_fibonacci1279.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_lagged_fibonacci2281 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_lagged_fibonacci2281.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_lagged_fibonacci3217 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_lagged_fibonacci3217.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_lagged_fibonacci4423 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_lagged_fibonacci4423.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_lagged_fibonacci9689 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_lagged_fibonacci9689.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_lagged_fibonacci19937 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_lagged_fibonacci19937.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_lagged_fibonacci23209 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_lagged_fibonacci23209.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_lagged_fibonacci44497 SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_lagged_fibonacci44497.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_zero_seed SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_zero_seed.cpp)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_niederreiter_base2_validate SOURCES ${CURRENT_TEST_SOURCES_DIR}/niederreiter_base2_validate.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_sobol_validate SOURCES ${CURRENT_TEST_SOURCES_DIR}/sobol_validate.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_faure_validate SOURCES ${CURRENT_TEST_SOURCES_DIR}/faure_validate.cpp)

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_seed_seq SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_seed_seq.cpp)


cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_binomial SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_binomial.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_binomial_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_binomial_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_poisson SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_poisson.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_poisson_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_poisson_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_discrete SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_discrete.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_discrete_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_discrete_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_gamma SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_gamma.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_gamma_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_gamma_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_weibull SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_weibull.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_weibull_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_weibull_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_extreme_value SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_extreme_value.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_extreme_value_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_extreme_value_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_negative_binomial SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_negative_binomial.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_negative_binomial_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_negative_binomial_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_chi_squared SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_chi_squared.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_chi_squared_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_chi_squared_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_fisher_f SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_fisher_f.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_fisher_f_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_fisher_f_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_student_t SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_student_t.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_student_t_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_student_t_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_normal SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_normal.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_normal_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_normal_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_piecewise_constant SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_piecewise_constant.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_piecewise_constant_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_piecewise_constant_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_piecewise_linear SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_piecewise_linear.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_piecewise_linear_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_piecewise_linear_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_exponential SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_exponential.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_exponential_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_exponential_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_bernoulli SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_bernoulli.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_bernoulli_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_bernoulli_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_cauchy SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_cauchy.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_cauchy_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_cauchy_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_geometric SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_geometric.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_geometric_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_geometric_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_lognormal SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_lognormal.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_lognormal_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_lognormal_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_triangle SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_triangle.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_triangle_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_triangle_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_uniform_int SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_uniform_int.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_uniform_int_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_uniform_int_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_uniform_real SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_uniform_real.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_uniform_real_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_uniform_real_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_uniform_on_sphere SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_uniform_on_sphere.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_uniform_on_sphere_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_uniform_on_sphere_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_uniform_smallint SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_uniform_smallint.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_uniform_smallint_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_uniform_smallint_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_old_uniform_real SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_old_uniform_real.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_old_uniform_real_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_old_uniform_real_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_old_uniform_int SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_old_uniform_int.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_old_uniform_int_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_old_uniform_int_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_beta SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_beta.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_beta_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_beta_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_laplace SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_laplace.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_laplace_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_laplace_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_non_central_chi_squared SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_non_central_chi_squared.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_non_central_chi_squared_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_non_central_chi_squared_distribution.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_hyperexponential SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_hyperexponential.cpp)
cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_hyperexponential_distribution SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_hyperexponential_distribution.cpp)

if(Boost_MULTIPRECISION_FOUND OR TARGET boost_multiprecision)
    cm_test(NAME ${CURRENT_PROJECT_NAME}_test_multiprecision_int_test SOURCES ${CURRENT_TEST_SOURCES_DIR}/multiprecision_int_test.cpp)
    cm_test(NAME ${CURRENT_PROJECT_NAME}_test_multiprecision_float_test SOURCES
            ${CURRENT_TEST_SOURCES_DIR}/multiprecision_float_test.cpp)
endif()

cm_test(NAME ${CURRENT_PROJECT_NAME}_test_test_chacha SOURCES ${CURRENT_TEST_SOURCES_DIR}/test_chacha.cpp)

include_directories(${CMAKE_WORKSPACE_SOURCES_DIR})