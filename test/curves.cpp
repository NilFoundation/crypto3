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

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/algebra/curves/alt_bn128.hpp>
#include <nil/algebra/curves/bls12.hpp>
#include <nil/algebra/curves/bn128.hpp>
#include <nil/algebra/curves/brainpool_r1.hpp>
#include <nil/algebra/curves/edwards.hpp>
#include <nil/algebra/curves/frp_v1.hpp>
#include <nil/algebra/curves/gost_A.hpp>
#include <nil/algebra/curves/mnt4.hpp>
#include <nil/algebra/curves/mnt6.hpp>
#include <nil/algebra/curves/p192.hpp>
#include <nil/algebra/curves/p224.hpp>
#include <nil/algebra/curves/p256.hpp>
#include <nil/algebra/curves/p384.hpp>
#include <nil/algebra/curves/p521.hpp>
#include <nil/algebra/curves/secp.hpp>
#include <nil/algebra/curves/sm2p_v1.hpp>
#include <nil/algebra/curves/x962_p.hpp>

using namespace nil::algebra;

BOOST_AUTO_TEST_SUITE(curves_manual_tests)

BOOST_AUTO_TEST_CASE(curves_manual_test1) {

    BOOST_CHECK_EQUAL("", "");
}
BOOST_AUTO_TEST_SUITE_END()
