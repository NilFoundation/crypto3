//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE lpc_test

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>

#include <nil/crypto3/zk/snark/commitments/list_polynomial_commitment.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk::snark;

BOOST_AUTO_TEST_SUITE(lpc_test_suite)

BOOST_AUTO_TEST_CASE(lpc_basic_test) {

    using curve_type = algebra::curves::bls12<381>;
    using FieldType = typename curve_type::base_field_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 5;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef list_polynomial_commitment_scheme<FieldType, merkle_hash_type, lambda, k, r, m> lpc_type;
    typedef typename lpc_type::proof_type proof_type;

    typename FieldType::value_type omega = math::unity_root<FieldType>(math::detail::get_power_of_two(k));

    std::vector<typename FieldType::value_type> D_0(10);
    for (std::size_t power = 1; power <= 10; power++) {
        D_0.emplace_back(omega.pow(power));
    }

    const math::polynomial::polynomial<typename FieldType::value_type> f = {0, 0, 1};

    merkle_tree_type T = lpc_type::commit(f, D_0);

    std::array<typename FieldType::value_type, 1> evaluation_points = {algebra::random_element<FieldType>()};

    BOOST_CHECK(lpc_type::proof_eval(evaluation_points, T, f, D_0) != proof_type());
}

BOOST_AUTO_TEST_SUITE_END()