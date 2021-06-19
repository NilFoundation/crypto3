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

#define BOOST_TEST_MODULE sha256_verification_test

#include <chrono>

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/mnt4.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/fields/mnt6/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt6.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/mnt6.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/mnt6.hpp>
#include <nil/crypto3/algebra/curves/edwards.hpp>
// #include <nil/crypto3/algebra/fields/edwards/base_field.hpp>
// #include <nil/crypto3/algebra/fields/edwards/scalar_field.hpp>
// #include <nil/crypto3/algebra/fields/arithmetic_params/edwards.hpp>
// #include <nil/crypto3/algebra/curves/params/multiexp/edwards.hpp>
// #include <nil/crypto3/algebra/curves/params/wnaf/edwards.hpp>

#include "sha256.hpp"
#include "../verify_r1cs_scheme.hpp"

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::zk;

BOOST_AUTO_TEST_SUITE(sha256_component_test_suite)

BOOST_AUTO_TEST_CASE(sha256_component_test_bls12_381_case) {
    using curve_type = curves::bls12<381>;
    using scalar_field_type = typename curve_type::scalar_field_type;

    std::cout << "Starting SHA-256 component verification test for BLS12-381 ..." << std::endl;
    auto begin = std::chrono::high_resolution_clock::now();
    components::blueprint<scalar_field_type> bp = 
        sha2_two_to_one_bp<scalar_field_type>();

    BOOST_CHECK(verify_component<curve_type>(bp));

    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    std::cout << "SHA-256 component verification test for BLS12-381 finished, time: " << elapsed.count() * 1e-9 << std::endl;
}

BOOST_AUTO_TEST_CASE(sha256_component_test_mnt4_case) {
    using curve_type = curves::mnt4<298>;
    using scalar_field_type = typename curve_type::scalar_field_type;

    std::cout << "Starting SHA-256 component verification test for MNT4-298 ..." << std::endl;
    auto begin = std::chrono::high_resolution_clock::now();
    components::blueprint<scalar_field_type> bp = 
        sha2_two_to_one_bp<scalar_field_type>();

    BOOST_CHECK(verify_component<curve_type>(bp));

    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    std::cout << "SHA-256 component verification test for MNT4-298 finished, time: " << elapsed.count() * 1e-9 << std::endl;
}

BOOST_AUTO_TEST_CASE(sha256_component_test_mnt6_case) {
    using curve_type = curves::mnt6<298>;
    using scalar_field_type = typename curve_type::scalar_field_type;

    std::cout << "Starting SHA-256 component verification test for MNT6-298 ..." << std::endl;
    auto begin = std::chrono::high_resolution_clock::now();
    components::blueprint<scalar_field_type> bp = 
        sha2_two_to_one_bp<scalar_field_type>();

    BOOST_CHECK(verify_component<curve_type>(bp));

    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    std::cout << "SHA-256 component verification test for MNT6-298 finished, time: " << elapsed.count() * 1e-9 << std::endl;
}

BOOST_AUTO_TEST_CASE(sha256_component_test_edwards_183_case) {
    using curve_type = curves::edwards<183>;
    using scalar_field_type = typename curve_type::scalar_field_type;

    std::cout << "Starting SHA-256 component verification test for Edwards-183 ..." << std::endl;
    auto begin = std::chrono::high_resolution_clock::now();
    components::blueprint<scalar_field_type> bp = 
        sha2_two_to_one_bp<scalar_field_type>();

    BOOST_CHECK(verify_component<curve_type>(bp));

    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    std::cout << "SHA-256 component verification test for Edwards-183 finished, time: " << elapsed.count() * 1e-9 << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
