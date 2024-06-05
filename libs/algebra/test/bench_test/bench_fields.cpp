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

#include <chrono>
#include <cstdint>
#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/algebra/fields/pallas/base_field.hpp>
#include <nil/crypto3/algebra/fields/pallas/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/secp/secp_k1/base_field.hpp>
#include <nil/crypto3/algebra/fields/secp/secp_k1/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/secp/secp_r1/base_field.hpp>
#include <nil/crypto3/algebra/fields/secp/secp_r1/scalar_field.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

using namespace nil::crypto3::algebra;

BOOST_AUTO_TEST_SUITE(fields_manual_tests)

template<class Field>
void run_perf_test() {
    using namespace nil::crypto3;
    using namespace nil::crypto3::algebra;
    using namespace nil::crypto3::algebra::fields;

    typedef typename Field::value_type value_type;
    std::vector<value_type> points1;
    std::vector<value_type> points2;
    for (int i = 0; i < 1000; ++i) {
        points1.push_back(algebra::random_element<Field>());
    }
    points2 = points1;

    std::chrono::time_point<std::chrono::high_resolution_clock> start(std::chrono::high_resolution_clock::now());

    size_t SAMPLES = 10000000;
    for (int i = 0; i < SAMPLES; ++i) {
        int index = i % points1.size();
        points2[index] *= points1[index];
    }
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now() - start);
    std::cout << "Multiplication time: " << std::fixed << std::setprecision(3)
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

    start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < SAMPLES / 1000; ++i) {
        int index = i % points1.size();
        points2[index] = points1[index].inversed();
    }

    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now() - start);
    std::cout << "Inversion time: " << std::fixed << std::setprecision(3)
        << elapsed.count() / (SAMPLES / 1000) << " ns" << std::endl;
}

BOOST_AUTO_TEST_CASE(field_operation_perf_test_pallas) {
    run_perf_test<nil::crypto3::algebra::fields::pallas_base_field>();
}

BOOST_AUTO_TEST_CASE(field_operation_perf_test_bls12_381) {
    run_perf_test<nil::crypto3::algebra::fields::bls12_base_field<381u>>();
}

BOOST_AUTO_TEST_SUITE_END()
