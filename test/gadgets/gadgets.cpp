//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE gadgetlib1_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include "simple_example.hpp"

#include <nil/crypto3/zk/snark/examples/proof_systems/ppzksnark/r1cs_ppzksnark/run_r1cs_ppzksnark.hpp>

using namespace nil::algebra;
using namespace nil::crypto3::zk::snark;

namespace {

    TEST(gadgetLib1, Integration) {
        typedef algebra::Fr<algebra::default_ec_pp> FieldType;
        // Create an example constraint system and translate to snark format
        algebra::default_ec_pp::init_public_params();
        const auto example = nil::crypto3::zk::snark::gen_r1cs_example_from_protoboard<FieldType>(100);
        const bool test_serialization = false;
        // Run ppzksnark. Jump into function for breakdown
        const bool bit = nil::crypto3::zk::snark::run_r1cs_ppzksnark<algebra::default_ec_pp>(example, test_serialization);
        EXPECT_TRUE(bit);
    };

}    // namespace
