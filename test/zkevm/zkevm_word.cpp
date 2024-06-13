//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_zkevm_word_utils_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/pallas/base_field.hpp>
#include <nil/crypto3/algebra/fields/goldilocks64/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/goldilocks64.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/blueprint/zkevm/zkevm_word.hpp>

using namespace nil;
using namespace nil::blueprint;

BOOST_AUTO_TEST_SUITE(blueprint_zkevm_word_utils_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_zkevm_word_goldilocks64_test, * boost::unit_test::disabled()) {
    using field_type = crypto3::algebra::fields::goldilocks64;
    using value_type = field_type::value_type;
    using word_type = zkevm_word_type;

    word_type word = 0x123456789abcdef0;
    std::vector<value_type> chunks = zkevm_word_to_field_element<field_type>(word);
    BOOST_CHECK_EQUAL(chunks.size(), 16);
    BOOST_CHECK_EQUAL(chunks[0], 0xdef0);
    BOOST_CHECK_EQUAL(chunks[1], 0x9abc);
    BOOST_CHECK_EQUAL(chunks[2], 0x5678);
    BOOST_CHECK_EQUAL(chunks[3], 0x1234);
    for (std::size_t i = 4; i < 16; ++i) {
        BOOST_CHECK_EQUAL(chunks[i], 0);
    }
}

BOOST_AUTO_TEST_CASE(blueprint_zkevm_word_pallas_test) {
    using field_type = crypto3::algebra::fields::pallas_base_field;
    using value_type = field_type::value_type;
    using word_type = zkevm_word_type;

    word_type word = 0x123456789abcdef0;
    std::vector<value_type> chunks = zkevm_word_to_field_element<field_type>(word);
    BOOST_CHECK_EQUAL(chunks.size(), 16);
    BOOST_CHECK_EQUAL(chunks[0], 0xdef0);
    BOOST_CHECK_EQUAL(chunks[1], 0x9abc);
    BOOST_CHECK_EQUAL(chunks[2], 0x5678);
    BOOST_CHECK_EQUAL(chunks[3], 0x1234);
    for (std::size_t i = 4; i < 16; ++i) {
        BOOST_CHECK_EQUAL(chunks[i], 0);
    }
}

BOOST_AUTO_TEST_SUITE_END()
