//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE kzg_test

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kzg.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::math;

BOOST_AUTO_TEST_SUITE(kzg_test_suite)

BOOST_AUTO_TEST_CASE(kzg_basic_test) {

    typedef algebra::curves::mnt4<298> curve_type;
    typedef typename curve_type::base_field_type::value_type base_value_type;
    typedef typename curve_type::base_field_type base_field_type;
    typedef typename curve_type::scalar_field_type scalar_field_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;
    typedef zk::commitments::kzg_commitment<curve_type> kzg_type;

    scalar_value_type alpha = 10;
    scalar_value_type i = 2;
    std::size_t n = 16;
    const polynomial<scalar_value_type> f = {-1, 1, 2, 3};

    auto srs = kzg_type::setup({alpha, n});
    BOOST_CHECK(curve_type::template g1_type<>::value_type::one() == srs.commitment_key[0]);
    BOOST_CHECK(10 * curve_type::template g1_type<>::value_type::one() == srs.commitment_key[1]);
    BOOST_CHECK(100 * curve_type::template g1_type<>::value_type::one() == srs.commitment_key[2]);
    BOOST_CHECK(1000 * curve_type::template g1_type<>::value_type::one() == srs.commitment_key[3]);
    BOOST_CHECK(alpha * curve_type::template g2_type<>::value_type::one() == srs.verification_key);

    auto commit = kzg_type::commit(srs, f);
    BOOST_CHECK(3209 * curve_type::template g1_type<>::value_type::one() == commit);

    auto eval = f.evaluate(i);
    auto proof = kzg_type::proof_eval(srs, i, f);
    BOOST_CHECK(33 * scalar_value_type::one() == eval);
    BOOST_CHECK(397 * curve_type::template g1_type<>::value_type::one() == proof);

    BOOST_CHECK(kzg_type::verify_eval(srs, commit, i, eval, proof));
}

BOOST_AUTO_TEST_SUITE_END()