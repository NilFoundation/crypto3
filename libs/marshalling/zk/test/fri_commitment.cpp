//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022-2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#define BOOST_TEST_MODULE crypto3_marshalling_fri_commitment_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <iomanip>
#include <random>
#include <regex>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>
#include <boost/multiprecision/number.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/zk/commitments/detail/polynomial/basic_fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/test_tools/random_test_initializer.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/fri.hpp>

#include "random_test_data_generation.hpp"

using namespace nil::crypto3;

template<typename Endianness, typename FRI>
void test_fri_proof(typename FRI::proof_type &proof, typename nil::crypto3::marshalling::types::batch_info_type batch_info,
        const typename FRI::params_type& params) {
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    auto filled_proof = nil::crypto3::marshalling::types::fill_fri_proof<Endianness, FRI>(proof, batch_info, params);
    auto _proof = nil::crypto3::marshalling::types::make_fri_proof<Endianness, FRI>(filled_proof, batch_info);
    BOOST_CHECK(proof.fri_roots == _proof.fri_roots);
    BOOST_CHECK(proof.final_polynomial == _proof.final_polynomial);
    BOOST_CHECK(proof.query_proofs[0].initial_proof == _proof.query_proofs[0].initial_proof);
    BOOST_CHECK(proof.query_proofs[0].round_proofs.size() == _proof.query_proofs[0].round_proofs.size());
    for( std::size_t i = 0; i < proof.query_proofs[0].round_proofs.size(); i++ ){
        if (proof.query_proofs[0].round_proofs[i] != _proof.query_proofs[0].round_proofs[i]){
            if (proof.query_proofs[0].round_proofs[i].p != _proof.query_proofs[0].round_proofs[i].p)
                 std::cout << "round proof " << i << "merkle proof is not equal" << std::endl;
            if (proof.query_proofs[0].round_proofs[i].y != _proof.query_proofs[0].round_proofs[i].y)
                 std::cout << "round proof " << i << "poly values are not equal" << std::endl;
        }
    }
    BOOST_CHECK(proof.query_proofs[0] == _proof.query_proofs[0]);
    BOOST_CHECK(proof.proof_of_work == _proof.proof_of_work);
    BOOST_CHECK(proof == _proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_proof.length(), 0x00);
    auto write_iter = cv.begin();
    auto status = filled_proof.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    typename nil::crypto3::marshalling::types::fri_proof<TTypeBase, FRI>::type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    typename FRI::proof_type constructed_val_read = nil::crypto3::marshalling::types::make_fri_proof<Endianness, FRI>(
            test_val_read, batch_info);
    BOOST_CHECK(proof == constructed_val_read);
}

BOOST_FIXTURE_TEST_SUITE(marshalling_fri_proof_elements, zk::test_tools::random_test_initializer<algebra::curves::bls12<381>::scalar_field_type>)
    static constexpr std::size_t lambda = 40;
    static constexpr std::size_t m = 2;

    using curve_type = nil::crypto3::algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;
    using value_type = typename field_type::value_type;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using FRI = typename nil::crypto3::zk::commitments::detail::basic_batched_fri<field_type, hash_type, hash_type, m>;

    BOOST_AUTO_TEST_CASE(polynomial_test) {
        using polynomial_type = math::polynomial<typename field_type::value_type>;
        polynomial_type f = {{1u, 3u, 4u, 1u, 5u, 6u, 7u, 2u, 8u, 7u, 5u, 6u, 1u, 2u, 1u, 1u}};
        auto filled_polynomial = nil::crypto3::marshalling::types::fill_polynomial<Endianness, polynomial_type>(f);

        auto _f = nil::crypto3::marshalling::types::make_polynomial<Endianness, polynomial_type>(filled_polynomial);
        BOOST_CHECK(f == _f);

        f = generate_random_polynomial<field_type>(2048, alg_random_engines.template get_alg_engine<field_type>());
        filled_polynomial = nil::crypto3::marshalling::types::fill_polynomial<Endianness, polynomial_type>(f);

        _f = nil::crypto3::marshalling::types::make_polynomial<Endianness, polynomial_type>(filled_polynomial);
        BOOST_CHECK(f == _f);
    }

    BOOST_AUTO_TEST_CASE(merkle_proof_vector_test) {
        std::vector<typename FRI::merkle_proof_type> mp;
        mp.push_back(generate_random_merkle_proof<FRI>(5, generic_random_engine));
        mp.push_back(generate_random_merkle_proof<FRI>(5, generic_random_engine));
        mp.push_back(generate_random_merkle_proof<FRI>(5, generic_random_engine));
        mp.push_back(generate_random_merkle_proof<FRI>(5, generic_random_engine));
        mp.push_back(generate_random_merkle_proof<FRI>(5, generic_random_engine));
        mp.push_back(generate_random_merkle_proof<FRI>(5, generic_random_engine));
        mp.push_back(generate_random_merkle_proof<FRI>(5, generic_random_engine));

        auto filled = nil::crypto3::marshalling::types::fill_merkle_proof_vector<Endianness, FRI>(mp);
        auto _f = nil::crypto3::marshalling::types::make_merkle_proof_vector<Endianness, FRI>(filled);
        BOOST_CHECK(mp == _f);

        using TTypeBase = nil::marshalling::field_type<Endianness>;
        std::vector<std::uint8_t> cv;
        cv.resize(filled.length(), 0x00);
        auto write_iter = cv.begin();
        auto status = filled.write(write_iter, cv.size());
        BOOST_CHECK(status == nil::marshalling::status_type::success);

        nil::crypto3::marshalling::types::merkle_proof_vector_type<TTypeBase, FRI> test_val_read;
        auto read_iter = cv.begin();
        test_val_read.read(read_iter, cv.size());
        BOOST_CHECK(status == nil::marshalling::status_type::success);
        auto constructed_val_read = nil::crypto3::marshalling::types::make_merkle_proof_vector<Endianness, FRI>(test_val_read);
        BOOST_CHECK(mp == constructed_val_read);
    }

    BOOST_AUTO_TEST_CASE(fri_proof_test){
        nil::crypto3::marshalling::types::batch_info_type batch_info;
        batch_info[0] = 1;
        batch_info[1] = 5;
        batch_info[3] = 6;
        batch_info[4] = 3;

        typename FRI::params_type fri_params(
            1, // max_step
            11, // degree_log
            lambda,
            4 // expand_factor
        );

        auto proof = generate_random_fri_proof<FRI>(
                2, 5,
                fri_params.step_list,
                lambda,
                false,
                batch_info,
                alg_random_engines.template get_alg_engine<field_type>(),
                generic_random_engine
        );
        test_fri_proof<Endianness, FRI>(proof, batch_info, fri_params);
    }

    BOOST_AUTO_TEST_CASE(fri_grinding_proof_test) {
        nil::crypto3::marshalling::types::batch_info_type batch_info;
        batch_info[0] = 1;
        batch_info[1] = 5;
        batch_info[3] = 6;
        batch_info[4] = 3;

        typename FRI::params_type fri_params(1, 11, lambda, 4, true);

        auto proof = generate_random_fri_proof<FRI>(
                2, 5,
                fri_params.step_list,
                lambda,
                true,
                batch_info,
                alg_random_engines.template get_alg_engine<field_type>(),
                generic_random_engine
        );
        test_fri_proof<Endianness, FRI>(proof, batch_info, fri_params);
    }
BOOST_AUTO_TEST_SUITE_END()


BOOST_FIXTURE_TEST_SUITE(marshalling_real_fri_proofs, zk::test_tools::random_test_initializer<algebra::curves::pallas::base_field_type>)
    using Endianness = nil::marshalling::option::big_endian;

BOOST_AUTO_TEST_CASE(marshalling_fri_basic_test) {
    // setup
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;
    constexpr static const std::size_t lambda = 40;

    typedef zk::commitments::fri<field_type, merkle_hash_type, transcript_hash_type, m> fri_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename fri_type::proof_type proof_type;
    typedef typename fri_type::params_type params_type;

    // Setup params
    std::size_t degree_log = std::ceil(std::log2(d - 1));
    typename fri_type::params_type fri_params(
            3, /*max_step*/
            degree_log,
            lambda,
            2 //expand_factor
            );

    // commit
    math::polynomial<typename field_type::value_type> f = {{
        1u, 3u, 4u, 1u, 5u, 6u, 7u, 2u, 8u, 7u, 5u, 6u, 1u, 2u, 1u, 1u}};
    std::array<std::vector<math::polynomial<typename field_type::value_type>>, 1> fs;
    fs[0].resize(1);
    fs[0][0] = f;
    typename fri_type::merkle_tree_type tree = zk::algorithms::precommit<fri_type>(
        fs[0], fri_params.D[0], fri_params.step_list[0]);
    auto root = zk::algorithms::commit<fri_type>(tree);

    // eval
    std::vector<std::uint8_t> init_blob{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(init_blob);

    proof_type proof = zk::algorithms::proof_eval<fri_type>(f, tree, fri_params, transcript);
    nil::crypto3::marshalling::types::batch_info_type batch_info;
    batch_info[0] = 1;
    test_fri_proof<Endianness, fri_type>(proof, batch_info, fri_params);
}

BOOST_AUTO_TEST_SUITE_END()
