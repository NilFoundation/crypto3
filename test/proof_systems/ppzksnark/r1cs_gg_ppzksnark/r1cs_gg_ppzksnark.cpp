//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Test program that exercises the ppzkSNARK (first generator, then
// prover, then verifier) on a synthetic R1CS instance.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE r1cs_gg_ppzksnark_test

#include <boost/test/unit_test.hpp>

#include <cassert>
#include <cstdio>

#include "r1cs_examples.hpp"
#include "run_r1cs_gg_ppzksnark.hpp"

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>

using namespace nil::crypto3::zk::snark;
using namespace nil::crypto3::algebra;

template<typename CurveType>
void test_r1cs_gg_ppzksnark(std::size_t num_constraints, std::size_t input_size) {
    r1cs_example<typename CurveType::scalar_field_type> example =
        generate_r1cs_example_with_binary_input<typename CurveType::scalar_field_type>(num_constraints, input_size);
    const bool bit = run_r1cs_gg_ppzksnark<CurveType>(example);
    BOOST_CHECK(bit);
}

BOOST_AUTO_TEST_SUITE(r1cs_gg_ppzksnark_test_suite)

BOOST_AUTO_TEST_CASE(r1cs_gg_ppzksnark_test){
    test_r1cs_gg_ppzksnark<curves::bls12<381>>(1000, 100);
}

BOOST_AUTO_TEST_SUITE_END()
