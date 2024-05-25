//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#define BOOST_TEST_MODULE pickles_test

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/pickles/detail.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk::snark;

BOOST_AUTO_TEST_SUITE(pickles_kimchi_to_field_test_suite)

template<typename field_type>
typename field_type::value_type to_field(typename field_type::value_type endo,
            typename field_type::value_type input) {
    ScalarChallenge<field_type> scalar_challenge {input};
    return scalar_challenge.to_field(endo);
}

BOOST_AUTO_TEST_CASE(pickles_kimchi_to_field_vesta_test) {
    using curve_type = algebra::curves::vesta;
    using field_type = curve_type::scalar_field_type;

    typename field_type::value_type endo_r = 0x12CCCA834ACDBA712CAAD5DC57AAB1B01D1F8BD237AD31491DAD5EBDFDFE4AB9_cppui_modular256;
    std::vector<field_type::value_type> inputs = {0, 0x00000000000000000000000000000000347936BC4A445B92516BE8A8EAB7D2B9_cppui_modular256};
    std::vector<field_type::value_type> expected_results = {0x1955ABB8AF556360261C069D1C8AEB8444BD73BE7B3163ADBE2E2610A9922C78_cppui_modular256,
        0x01FD131CD87BB2DDCF0D446F7E0EEBCDCE145EE5CA5C7851FC5D22AC186BDDBB_cppui_modular256};
    for (std::size_t i = 0; i < inputs.size(); i++) {
        typename field_type::value_type res = to_field<field_type>(endo_r, inputs[i]);
        BOOST_CHECK(res == expected_results[i]);
    }
}

BOOST_AUTO_TEST_SUITE_END()