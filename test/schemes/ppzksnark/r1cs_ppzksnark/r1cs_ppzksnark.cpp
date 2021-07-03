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
// @file Test program that exercises the ppzkSNARK (first generator, then
// prover, then verifier) on a synthetic R1CS instance.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE r1cs_ppzksnark_test

#include <boost/test/unit_test.hpp>

#include <cassert>
#include <cstdio>

#include "../r1cs_examples.hpp"
#include "run_r1cs_ppzksnark.hpp"

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/mnt4.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/mnt4.hpp>

using namespace nil::crypto3::zk::snark;
using namespace nil::crypto3::algebra;

template<typename CurveType>
void test_r1cs_ppzksnark(std::size_t num_constraints, std::size_t input_size) {
    r1cs_example<typename CurveType::scalar_field_type> example =
        generate_r1cs_example_with_binary_input<typename CurveType::scalar_field_type>(num_constraints, input_size);
    const bool bit = run_r1cs_ppzksnark<CurveType>(example);
    BOOST_CHECK(bit);
}

BOOST_AUTO_TEST_SUITE(r1cs_ppzksnark_test_suite)

BOOST_AUTO_TEST_CASE(r1cs_ppzksnark_test) {
    test_r1cs_ppzksnark<curves::mnt4<298>>(1000, 100);
}

BOOST_AUTO_TEST_SUITE_END()