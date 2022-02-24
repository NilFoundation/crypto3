//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/zk/snark/commitments/list_polynomial_commitment.hpp>
#include <nil/crypto3/zk/snark/commitments/fri_commitment.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/params.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk::snark;


BOOST_AUTO_TEST_SUITE(lpc_test_suite)

BOOST_AUTO_TEST_CASE(lpc_basic_test) {

    // setup
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type FieldType;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::snark::fri_commitment_scheme<FieldType, merkle_hash_type, transcript_hash_type, m> fri_type;
    typedef zk::snark::list_polynomial_commitment_scheme<FieldType, merkle_hash_type, transcript_hash_type, zk::snark::redshift_params, k> lpc_type;
    typedef typename lpc_type::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D = fri_type::calculate_domain_set(extended_log, r);

    typename fri_type::params_type fri_params;

    math::polynomial<typename FieldType::value_type> q = {0, 0, 1};
    fri_params.r = r;
    fri_params.D = D;
    fri_params.q = q;
    fri_params.max_degree = d - 1;
    

    // commit

    math::polynomial<typename FieldType::value_type> f = {1, 3, 4, 1,
                                                                        5, 6, 7, 2,
                                                                        8, 7, 5, 6,
                                                                        1, 2, 1, 1};

    merkle_tree_type tree = lpc_type::commit(f, D[0]);

    // TODO: take a point outside of the basic domain
    std::array<typename FieldType::value_type, 1> evaluation_points  = {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator};

    std::array<std::uint8_t, 96> x_data {};
    zk::snark::fiat_shamir_heuristic_updated<transcript_hash_type> transcript(x_data);

    auto proof = lpc_type::proof_eval(evaluation_points, tree, f, transcript, fri_params);

    // verify
    zk::snark::fiat_shamir_heuristic_updated<transcript_hash_type> transcript_verifier(x_data);

    BOOST_CHECK(lpc_type::verify_eval(evaluation_points, proof, transcript_verifier, fri_params));
}

BOOST_AUTO_TEST_SUITE_END()