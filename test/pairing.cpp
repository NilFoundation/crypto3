//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE curves_algebra_test

#include <iostream>

#include <boost/multiprecision/cpp_modular.hpp>
#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/modular/modular_adaptor.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/algorithms/pair.hpp>

#include <nil/crypto3/algebra/curves/detail/bn128/g1.hpp>

//#include <nil/crypto3/algebra/fields/detail/extension_params/dsa_jce.hpp>
//#include <nil/crypto3/algebra/fields/detail/extension_params/modp_srp.hpp>
//#include <nil/crypto3/algebra/fields/params.hpp>
//#include <nil/crypto3/algebra/fields/bn128/scalar_field.hpp>
//#include <nil/crypto3/algebra/fields/dsa_jce.hpp>
//#include <nil/crypto3/algebra/fields/ed25519_fe.hpp>
//#include <nil/crypto3/algebra/fields/ffdhe_ietf.hpp>
//#include <nil/crypto3/algebra/fields/fp.hpp>
//#include <nil/crypto3/algebra/fields/fp2.hpp>
//#include <nil/crypto3/algebra/fields/fp3.hpp>
//#include <nil/crypto3/algebra/fields/fp4.hpp>
//#include <nil/crypto3/algebra/fields/fp6_2over3.hpp>
//#include <nil/crypto3/algebra/fields/fp6_3over2.hpp>
//#include <nil/crypto3/algebra/fields/fp12_2over3over2.hpp>
//#include <nil/crypto3/algebra/fields/modp_ietf.hpp>
//#include <nil/crypto3/algebra/fields/modp_srp.hpp>

using namespace nil::crypto3::algebra;

BOOST_AUTO_TEST_SUITE(curves_manual_tests)

BOOST_AUTO_TEST_CASE(curves_manual_test1) {

    BOOST_CHECK_EQUAL("", "");
}
BOOST_AUTO_TEST_SUITE_END()
