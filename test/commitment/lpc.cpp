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
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/zk/snark/commitments/list_polynomial_commitment.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk::snark;

template<typename FieldType> 
std::shared_ptr<math::evaluation_domain<FieldType>> prepare_domain(const std::size_t d) {
    return math::make_evaluation_domain<FieldType>(d);                        
}

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<>
            struct print_log_value<nil::crypto3::math::polynomial::polynomial<
                algebra::fields::detail::element_fp<algebra::fields::params<algebra::fields::bls12_base_field<381>>>>> {
                void operator()(std::ostream &,
                                const nil::crypto3::math::polynomial::polynomial<algebra::fields::detail::element_fp<
                                    algebra::fields::params<algebra::fields::bls12_base_field<381>>>> &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

template<typename FieldType, typename NumberType>
std::vector<math::polynomial::polynomial<typename FieldType::value_type>> generate(NumberType degree) {
    typedef boost::random::independent_bits_engine<boost::random::mt19937, FieldType::modulus_bits,
                                                   typename FieldType::value_type::integral_type>
        random_polynomial_generator_type;

    std::vector<math::polynomial::polynomial<typename FieldType::value_type>> res;

    boost::random::random_device rd;     // Will be used to obtain a seed for the random number engine
    boost::random::mt19937 gen(rd());    // Standard mersenne_twister_engine seeded with rd()
    boost::random::uniform_int_distribution<> distrib(std::numeric_limits<int>::min(), std::numeric_limits<int>::max());

    random_polynomial_generator_type polynomial_element_gen;
    std::size_t height = 1;
    res.reserve(height);

    for (int i = 0; i < height; i++) {
        math::polynomial::polynomial<typename FieldType::value_type> poly;
        for (int j = 0; j < degree; j++) {
            poly.push_back(typename FieldType::value_type(polynomial_element_gen()));
        }
        res.push_back(poly);
    }

    return res;
}

BOOST_AUTO_TEST_SUITE(lpc_test_suite)

BOOST_AUTO_TEST_CASE(lpc_performance_test) {
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d_power_two = 5;
    constexpr static const std::size_t d = 1 << d_power_two -1;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef list_polynomial_commitment_scheme<field_type, merkle_hash_type, lambda, k, r, m> lpc_type;
    typedef typename lpc_type::proof_type proof_type;

    std::shared_ptr<math::evaluation_domain<field_type>> D_0 = prepare_domain<field_type>(d);

    typedef boost::random::independent_bits_engine<boost::random::mt19937, field_type::modulus_bits,
                                                   typename field_type::value_type::integral_type>
        random_polynomial_generator_type;

    std::vector<math::polynomial::polynomial<typename field_type::value_type>> res;

    boost::random::random_device rd;     // Will be used to obtain a seed for the random number engine
    boost::random::mt19937 gen(rd());    // Standard mersenne_twister_engine seeded with rd()
    boost::random::uniform_int_distribution<> distrib(std::numeric_limits<int>::min(), std::numeric_limits<int>::max());

    random_polynomial_generator_type polynomial_element_gen;
    std::size_t height = 1;
    res.reserve(height);

    for (int i = 0; i < height; i++) {
        math::polynomial::polynomial<typename field_type::value_type> poly;
        for (int j = 0; j < (1 << d_power_two); j++) {
            poly.push_back(typename field_type::value_type(polynomial_element_gen()));
        }
        merkle_tree_type tree = lpc_type::commit(poly, D_0);

        std::array<typename field_type::value_type, 1> evaluation_points = {algebra::random_element<field_type>()};

        std::array<std::uint8_t, 96> x_data {};
        zk::snark::fiat_shamir_heuristic_updated<transcript_hash_type> transcript(x_data);

        auto proof = lpc_type::proof_eval(evaluation_points, tree, poly, transcript);
    }
}

BOOST_AUTO_TEST_CASE(lpc_basic_test) {

    /*typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::base_field_type FieldType;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 5;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef list_polynomial_commitment_scheme<FieldType, merkle_hash_type, lambda, k, r, m> lpc_type;
    typedef typename lpc_type::proof_type proof_type;

    math::polynomial::polynomial<typename FieldType::value_type> f = {0, 0, 1};

    std::shared_ptr<math::evaluation_domain<FieldType>> D_0 = prepare_domain<FieldType>(d);

    merkle_tree_type tree = lpc_type::commit(f, D_0);

    std::array<typename FieldType::value_type, 1> evaluation_points = {algebra::random_element<FieldType>()};

    std::array<std::uint8_t, 96> x_data {};
    zk::snark::fiat_shamir_heuristic_updated<transcript_hash_type> transcript(x_data);

    auto proof = lpc_type::proof_eval(evaluation_points, tree, f, transcript);*/
}

BOOST_AUTO_TEST_SUITE_END()