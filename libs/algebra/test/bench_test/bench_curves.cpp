//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#define BOOST_TEST_MODULE algebra_curves_bench_test

#include <iostream>
#include <chrono>
#include <type_traits>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/curves/jubjub.hpp>
#include <nil/crypto3/algebra/curves/babyjubjub.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/curves/secp_k1.hpp>
#include <nil/crypto3/algebra/curves/secp_r1.hpp>
#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/curves/curve25519.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp3.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>

using namespace nil::crypto3::algebra;

BOOST_AUTO_TEST_SUITE(curves_manual_tests)
/**/


template<typename CurveGroup>
void curve_operations_perf_test() {
    using namespace nil::crypto3;
    using namespace nil::crypto3::algebra;

    typedef typename CurveGroup::value_type value_type;
    typedef typename CurveGroup::field_type::integral_type integral_type;

    std::vector<value_type> points1;
    std::vector<value_type> points2;
    std::vector<integral_type> constants;

    for (int i = 0; i < 1000; ++i) {
        points1.push_back(algebra::random_element<CurveGroup>());
        // We convert the number into string and back into number to convert the type, they are slightly different.
        std::stringstream ss;
        ss << algebra::random_element<typename CurveGroup::field_type>();

        // For G2 group, we wil have 2 integral values in the ss, so taking only the first one.
        constants.push_back(integral_type(ss.str().substr(0, ss.str().find(' '))));
    }
    points2 = points1;

    std::chrono::time_point<std::chrono::high_resolution_clock> start(std::chrono::high_resolution_clock::now());

    size_t SAMPLES = 10000;
    for (int i = 0; i < SAMPLES; ++i) {
        int index = i % points1.size();
        points2[index] *= constants[index];
    }
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now() - start);
    std::cout << "Scalar Multiplication time: " << std::fixed << std::setprecision(3)
        << elapsed.count() / SAMPLES << " ns" << std::endl;

    start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < SAMPLES; ++i) {
        int index = i % points1.size();
        points2[index] += points1[index];
    }
    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now() - start);
    std::cout << "Addition time: " << std::fixed << std::setprecision(3)
        << elapsed.count() / SAMPLES << " ns" << std::endl;

    start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < SAMPLES; ++i) {
        int index = i % points1.size();
        points2[index] -= points1[index];
    }

    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now() - start);
    std::cout << "Substraction time: " << std::fixed << std::setprecision(3)
        << elapsed.count() / SAMPLES << " ns" << std::endl;
}

BOOST_AUTO_TEST_CASE(curve_operations_perf_test_bls12_381_g1) {
    using policy_type = curves::bls12<381>::g1_type<>;

    curve_operations_perf_test<policy_type>();
}

BOOST_AUTO_TEST_CASE(curve_operations_perf_test_bls12_381_g2) {
    using policy_type = curves::bls12<381>::g2_type<>;

    curve_operations_perf_test<policy_type>();
}

BOOST_AUTO_TEST_SUITE_END()
