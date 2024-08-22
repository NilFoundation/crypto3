//---------------------------------------------------------------------------//
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
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

#define BOOST_TEST_MODULE crypto3_marshalling_polys_evaluator_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>

#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>

#include <iostream>
#include <iomanip>
#include <fstream>
#include <regex>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>
#include <boost/multiprecision/number.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/polys_evaluator.hpp>

#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/commitments/batched_commitment.hpp> // contains class polys_evaluator
#include "random_test_data_generation.hpp"

using namespace nil::crypto3;

// *******************************************************************************
// * Test marshalling function
// ******************************************************************************* /

template<typename Endianness, typename PolysEvaluator>
void test_polys_evaluator_marshalling(PolysEvaluator &evaluator) {
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    auto filled_evaluator = nil::crypto3::marshalling::types::fill_polys_evaluator<Endianness, PolysEvaluator>(evaluator);
    auto _evaluator = nil::crypto3::marshalling::types::make_polys_evaluator<Endianness, PolysEvaluator>(filled_evaluator);
    BOOST_CHECK(evaluator == _evaluator);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_evaluator.length(), 0x00);
    auto write_iter = cv.begin();
    auto status = filled_evaluator.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    nil::crypto3::marshalling::types::polys_evaluator<TTypeBase, PolysEvaluator> test_val_read;
    auto read_iter = cv.begin();
    test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    PolysEvaluator constructed_val_read =
            nil::crypto3::marshalling::types::make_polys_evaluator<Endianness, PolysEvaluator>(test_val_read);
    BOOST_CHECK(evaluator == constructed_val_read);
}

BOOST_AUTO_TEST_SUITE(marshalling_real)
    // Setup common types.
    using Endianness = nil::marshalling::option::big_endian;
    using curve_type = nil::crypto3::algebra::curves::vesta;
    using field_type = curve_type::scalar_field_type;
    using merkle_hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using transcript_hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using merkle_tree_type = typename containers::merkle_tree<merkle_hash_type, 2>;

BOOST_FIXTURE_TEST_CASE(batches_num_3_test, zk::test_tools::random_test_initializer<field_type>){
    // Setup types.
    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<field_type, merkle_hash_type, transcript_hash_type, m> fri_type;

    typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, m>
            lpc_params_type;
    typedef zk::commitments::list_polynomial_commitment<field_type, lpc_params_type> lpc_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(zk::is_commitment<lpc_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);
    static_assert(!zk::is_commitment<merkle_tree_type>::value);
    static_assert(!zk::is_commitment<std::size_t>::value);

    std::size_t degree_log = boost::static_log2<d>::value;

    // Setup params
    typename fri_type::params_type fri_params(
        1, /*max_step*/
        degree_log,
        lambda,
        2 /*expand_factor*/
    );

    using lpc_scheme_type = nil::crypto3::zk::commitments::lpc_commitment_scheme<
        lpc_type, math::polynomial<typename field_type::value_type>>;
    using polys_evaluator_type = typename lpc_scheme_type::polys_evaluator_type;

    lpc_scheme_type lpc_scheme_prover(fri_params);

    // Generate polynomials
    lpc_scheme_prover.append_to_batch(0, {1u, 13u, 4u, 1u, 5u, 6u, 7u, 2u, 8u, 7u, 5u, 6u, 1u, 2u, 1u, 1u});
    lpc_scheme_prover.append_to_batch(2, {0u, 1u});
    lpc_scheme_prover.append_to_batch(2, {0u, 1u, 2u});
    lpc_scheme_prover.append_to_batch(2, {0u, 1u, 3u});
    lpc_scheme_prover.append_to_batch(3, {0u});

    // Commit
    std::map<std::size_t, typename lpc_type::commitment_type> commitments;
    commitments[0] = lpc_scheme_prover.commit(0);
    commitments[2] = lpc_scheme_prover.commit(2);
    commitments[3] = lpc_scheme_prover.commit(3);

    auto filled_commitment = nil::crypto3::marshalling::types::fill_commitment<Endianness, lpc_scheme_type>(commitments[0]);
    auto _commitment = nil::crypto3::marshalling::types::make_commitment<Endianness, lpc_scheme_type>(filled_commitment);

    // Generate evaluation points. Generate points outside of the basic domain
    // Generate evaluation points. Choose poin1ts outside the domain
    auto point = algebra::fields::arithmetic_params<field_type>::multiplicative_generator;
    lpc_scheme_prover.append_eval_point(0, point);
    lpc_scheme_prover.append_eval_point(2, point);
    lpc_scheme_prover.append_eval_point(3, point);

    std::array<std::uint8_t, 96> x_data {};

    polys_evaluator_type evaluator = static_cast<polys_evaluator_type>(lpc_scheme_prover);
    test_polys_evaluator_marshalling<Endianness, polys_evaluator_type>(evaluator);
}

BOOST_AUTO_TEST_SUITE_END()
