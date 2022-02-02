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

#define BOOST_TEST_MODULE fri_test

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>

#include <nil/crypto3/merkle/tree.hpp> // until fri inclusion
#include <nil/crypto3/zk/snark/transcript/fiat_shamir.hpp> // until fri inclusion
#include <nil/crypto3/zk/snark/commitments/fri_commitment.hpp>

using namespace nil::crypto3;

template<typename FieldType> 
std::vector<typename FieldType::value_type> prepare_domain(const std::size_t d) {
    typename FieldType::value_type omega = math::unity_root<FieldType>(math::detail::get_power_of_two(d));
    std::vector<typename FieldType::value_type> D_0(d);
    for (std::size_t power = 1; power <= d; power++) {
        D_0.emplace_back(omega.pow(power));
    }
    return D_0;
}

BOOST_AUTO_TEST_SUITE(fri_test_suite)

BOOST_AUTO_TEST_CASE(fri_basic_test) {

    // fri params
    using curve_type = algebra::curves::mnt4<298>;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 4;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;

    // typedef fri_commitment_scheme<FieldType, merkle_hash_type, lambda, k, r, m> fri_type;
    // typedef typename fri_type::proof_type proof_type;

    math::polynomial::polynomial<typename FieldType::value_type> f = {1, 3, 4, 25};

    // create domain D_0
    std::vector<typename FieldType::value_type> D_0 = prepare_domain<FieldType>(d);
    // merkle_tree_type T = fri_type::commit(f, D_0);

    // std::array<typename FieldType::value_type, 1> evaluation_points = {omega.pow(5)};

    // proof_type proof = fri_type::proof_eval(evaluation_points, T, f, D_0)
    // BOOST_CHECK(fry_type::verify_eval(evaluation_points, T, proof, D_0))
}

BOOST_AUTO_TEST_CASE(fri_fold_test) {

    // fri params
    using curve_type = algebra::curves::mnt4<298>;
    using FieldType = typename curve_type::base_field_type;

    constexpr static const std::size_t d = 4;

    // typedef fri_commitment_scheme<FieldType, merkle_hash_type, lambda, k, r, m> fri_type;

    math::polynomial::polynomial<typename FieldType::value_type> f = {1, 3, 4, 25};

    std::vector<typename FieldType::value_type> D_0 = prepare_domain<FieldType>(d);
    typename FieldType::value_type omega = D_0[0];

    // x_next = fri_type::params.q(x)
    typename FieldType::value_type alpha = algebra::random_element<FieldType>();
    // math::polynomial::polynomial<typename FieldType::value_type> f_next = fri_type::fold_polynomial(f, alpha)

    std::vector<std::pair<typename FieldType::value_type, typename FieldType::value_type>> points {
        std::make_pair(omega, f.evaluate(omega)),
        std::make_pair(-omega, f.evaluate(-omega)),
    };
    math::polynomial::polynomial<typename FieldType::value_type> interpolant = math::polynomial::_lagrange_interpolation(points);
    // BOOST_CHECK_EQUAL(interpolant.eval(alpha), f_next.eval(x_next))
}

BOOST_AUTO_TEST_CASE(fri_coset_test) {

    // fri params
    using curve_type = algebra::curves::mnt4<298>;
    using FieldType = typename curve_type::base_field_type;

    // typedef fri_commitment_scheme<FieldType, merkle_hash_type, lambda, k, r, m> fri_type;

    math::polynomial::polynomial<typename FieldType::value_type> f = {1, 3, 4, 25};

    // create domain D_0
    // Get omega from D_0

    // delegate q = fry_type::q()
    // x_next = q(omega)

    // vector s = fri_type::get_coset(x_next)
    //for (std::size_t i = 0; i < s.size(); i++) {
    //    BOOST_CHECK_EQUAL(x_next, s[i]^2);
    //}
}

BOOST_AUTO_TEST_CASE(fri_steps_count_test) {

    // fri params
    using curve_type = algebra::curves::mnt4<298>;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 4;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;

    // typedef fri_commitment_scheme<FieldType, merkle_hash_type, lambda, k, r, m> fri_type;
    // typedef typename fri_type::proof_type proof_type;

    math::polynomial::polynomial<typename FieldType::value_type> f = {1, 3, 4, 25};

    std::vector<typename FieldType::value_type> D_0 = prepare_domain<FieldType>(d);

    // merkle_tree_type T = fri_type::commit(f, D_0);

    // std::array<typename FieldType::value_type, 1> evaluation_points = {omega.pow(algebra::random_element<FieldType>())};

    // proof_type proof = fri_type::proof_eval(evaluation_points, T, f, D_0)
    // math::polynomial::polynomial<typename FieldType::value_type> f_res = proof.last_round.f

    // int expected_deg = def(f) - 2^r

    // BOOST_CHECK_EQUAL(f_res.deg(), expected_deg)
}

BOOST_AUTO_TEST_SUITE_END()