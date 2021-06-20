/** @file
 *****************************************************************************

 Implementation of interfaces for gadgets for Miller loops.

 See weierstrass_miller_loop.hpp .

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#define BOOST_TEST_MODULE weierstrass_miller_loop_components_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/mnt4.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/fields/mnt6/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt6.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/mnt6.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/mnt6.hpp>

#include "weierstrass_miller_loop.hpp"

using namespace nil::crypto3::zk;
using namespace nil::crypto3::algebra;

BOOST_AUTO_TEST_SUITE(weierstrass_miller_loop_components_test_suite)

BOOST_AUTO_TEST_CASE(weierstrass_miller_loop_mnt4_miller_loop_components_test) {
	test_mnt_miller_loop<curves::mnt4<298>>();
}

BOOST_AUTO_TEST_CASE(weierstrass_miller_loop_mnt6_miller_loop_components_test) {
	test_mnt_miller_loop<curves::mnt6<298>>();
}

BOOST_AUTO_TEST_CASE(weierstrass_miller_loop_mnt4_e_over_e_miller_loop_components_test) {
	test_mnt_e_over_e_miller_loop<curves::mnt4<298>>();
}

BOOST_AUTO_TEST_CASE(weierstrass_miller_loop_mnt6_e_over_e_miller_loop_components_test) {
	test_mnt_e_over_e_miller_loop<curves::mnt6<298>>();
}

BOOST_AUTO_TEST_CASE(weierstrass_miller_loop_mnt4_e_times_e_miller_loop_components_test) {
	test_mnt_e_times_e_over_e_miller_loop<curves::mnt4<298>>();
}

BOOST_AUTO_TEST_CASE(weierstrass_miller_loop_mnt6_e_times_e_miller_loop_components_test) {
	test_mnt_e_times_e_over_e_miller_loop<curves::mnt6<298>>();
}

BOOST_AUTO_TEST_SUITE_END()