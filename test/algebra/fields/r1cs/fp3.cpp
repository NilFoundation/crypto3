//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE element_fp3_test

#include <chrono>
#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/blueprint/blueprint/r1cs/circuit.hpp>
#include <nil/blueprint/blueprint/r1cs/assignment.hpp>

#include <nil/blueprint/components/algebra/fields/element_fp3.hpp>

#include "arithmetic.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::algebra;

BOOST_AUTO_TEST_SUITE(field_element_arithmetic_component_test_suite)

BOOST_AUTO_TEST_CASE(field_element_mul_component_test_mnt6_case) {
    using curve_type = typename curves::mnt6<298>;
    using field_type = typename curve_type::template g2_type<>::field_type;
    using base_field_type = typename curve_type::base_field_type;

    std::size_t tries_quantity = 500;
    std::cout << "Starting element Fp3 mul component test for MNT6-298 " << tries_quantity << " times ..." << std::endl;
    auto begin = std::chrono::high_resolution_clock::now();

    for (std::size_t i = 0; i < tries_quantity; i++) {
        typename field_type::value_type a_value = random_element<field_type>();
        typename field_type::value_type b_value = random_element<field_type>();

        blueprint<base_field_type> bp =
            test_field_element_mul<field_type, components::element_fp3, components::element_fp3_mul>(a_value, b_value);

        BOOST_CHECK(bp.is_satisfied());
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    std::cout << "Element Fp3 mul component test for MNT6-298 finished, average time: "
              << elapsed.count() * 1e-9 / tries_quantity << std::endl;
}

BOOST_AUTO_TEST_CASE(field_element_squared_component_test_mnt6_case) {
    using curve_type = typename curves::mnt6<298>;
    using field_type = typename curve_type::template g2_type<>::field_type;
    using base_field_type = typename curve_type::base_field_type;

    std::size_t tries_quantity = 500;
    std::cout << "Starting element Fp3 squared component test for MNT6-298 " << tries_quantity << " times ..."
              << std::endl;
    auto begin = std::chrono::high_resolution_clock::now();

    for (std::size_t i = 0; i < tries_quantity; i++) {
        typename field_type::value_type a_value = random_element<field_type>();

        blueprint<base_field_type> bp =
            test_field_element_squared<field_type, components::element_fp3, components::element_fp3_squared>(a_value);

        BOOST_CHECK(bp.is_satisfied());
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    std::cout << "Element Fp3 squared component test for MNT6-298 finished, average time: "
              << elapsed.count() * 1e-9 / tries_quantity << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()