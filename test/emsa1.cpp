//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#define BOOST_TEST_MODULE emsa1_encoding_test

#include <iostream>
#include <unordered_map>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/pkpad/emsa/emsa1.hpp>

#include <nil/crypto3/pkpad/algorithms/encode.hpp>
#include <nil/crypto3/pkpad/algorithms/verify.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/hash/sha1.hpp>

using namespace nil::crypto3;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename algebra::fields::detail::element_fp<FieldParams> &e) {
    os << e.data << std::endl;
}

BOOST_AUTO_TEST_SUITE(emsa_bls12_fr_test_suite)

BOOST_AUTO_TEST_CASE(emsa1_single_range_encode) {
    using curve_type = algebra::curves::bls12_381;
    using field_type = typename curve_type::scalar_field_type;
    using field_value_type = typename field_type::value_type;

    using hash_type = hashes::sha1;

    using padding_type = pubkey::padding::emsa1<field_value_type, hash_type>;

    std::vector<std::uint8_t> in {0,0,0,0,1};
    field_value_type out = pubkey::encode<padding_type>(in);
    print_field_element(std::cout, out);
}

BOOST_AUTO_TEST_SUITE_END()
