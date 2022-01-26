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

#define BOOST_TEST_MODULE zk_transcript_test

#include <vector>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>

#include <nil/crypto3/zk/snark/transcript/fiat_shamir.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk::snark;

BOOST_AUTO_TEST_SUITE(zk_transcript_test_suite)

BOOST_AUTO_TEST_CASE(zk_transcript_manual_test) {
    using field_type = algebra::curves::alt_bn128_254::scalar_field_type;
    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    fiat_shamir_heuristic_updated tr(init_blob);
    auto ch1 = tr.get_challenge<field_type>();
    auto ch2 = tr.get_challenge<field_type>();
    auto ch_n = tr.get_challenges<field_type, 3>();

    std::cout << ch1.data << std::endl;
    std::cout << ch2.data << std::endl;
    for (const auto &ch : ch_n) {
        std::cout << ch.data << std::endl;
    }

    std::vector<std::uint8_t> updated_blob {0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
    tr(updated_blob);

    ch_n = tr.get_challenges<field_type, 3>();
    for (const auto &ch : ch_n) {
        std::cout << ch.data << std::endl;
    }
}

BOOST_AUTO_TEST_SUITE_END()
