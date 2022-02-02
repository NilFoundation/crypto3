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

// Generates a Fibonacci sequence
std::vector<float> fibonacci() {
    std::vector<float> ret(8);
    ret[0] = 0;
    ret[1] = 1;

    for (std::size_t s(2); s < ret.size(); s++) {
        ret[s] = ret[s - 1] + ret[s - 2];
    }
    return ret;
}

template<typename FieldValueType, typename NumberType>
std::vector<math::polynomial::polynomial<FieldValueType>> generate(NumberType degree) {
    typedef boost::random::independent_bits_engine<boost::random::mt19937,
                                                   FieldValueType::modulus_bits,
                                                   typename FieldValueType::value_type::data_type>
        random_polynomial_generator_type;

    std::vector<math::polynomial::polynomial<FieldValueType>> res;

    boost::random::random_device rd;     // Will be used to obtain a seed for the random number engine
    boost::random::mt19937 gen(rd());    // Standard mersenne_twister_engine seeded with rd()
    boost::random::uniform_int_distribution<> distrib(std::numeric_limits<int>::min(), std::numeric_limits<int>::max());

    random_polynomial_generator_type polynomial_element_gen;
    std::size_t height = distrib(gen);
    res.reserve(height);

    for (int i = 0; i < height; i++) {
        math::polynomial::polynomial<FieldValueType> poly;
        for (int j = 0; j < degree; j++) {
            poly.push_back(polynomial_element_gen());
        }
        res.push_back(poly);
    }

    return res;
}

// Generates a map from a vector
std::map<std::string, float> vect_2_str(const std::vector<float> &v) {
    std::map<std::string, float> out;
    for (float s : v) {
        std::ostringstream o;
        o << s;
        out[o.str()] = s;
    }
    return out;
}

typedef std::pair<const std::string, float> pair_map_t;
BOOST_TEST_DONT_PRINT_LOG_VALUE(pair_map_t)

BOOST_AUTO_TEST_SUITE(lpc_test_suite)

BOOST_DATA_TEST_CASE(test2,
                     ::boost::unit_test::data::make(
                         generate<typename algebra::curves::bls12<381>::base_field_type>(multiprecision::pow(2, 24))),
                     array_element) {
    std::cout << "test 2: \"" << array_element.first << "\", " << array_element.second << std::endl;
    BOOST_TEST(array_element.second <= 13);
}

BOOST_AUTO_TEST_CASE(lpc_basic_test) {

    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::base_field_type field_type;
    typedef hashes::sha2<256> merkle_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 5;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef list_polynomial_commitment_scheme<field_type, merkle_hash_type, lambda, k, r, m> lpc_type;
    typedef typename lpc_type::proof_type proof_type;

    typename field_type::value_type omega = math::unity_root<field_type>(math::detail::get_power_of_two(k));

    std::vector<typename field_type::value_type> D_0(10);
    for (std::size_t power = 1; power <= 10; power++) {
        D_0.emplace_back(omega.pow(power));
    }

    const math::polynomial::polynomial<typename field_type::value_type> f = {0, 0, 1};

    merkle_tree_type T = lpc_type::commit(f, D_0);

    std::array<typename field_type::value_type, 1> evaluation_points = {algebra::random_element<field_type>()};

    BOOST_CHECK(lpc_type::proof_eval(evaluation_points, T, f, D_0) != proof_type());
}

BOOST_AUTO_TEST_SUITE_END()