//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#define BOOST_TEST_MODULE curves_algebra_test

#include <iostream>
#include <cstdint>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/multiprecision/cpp_int.hpp>

#include <nil/crypto3/algebra/curves/detail/h2c/h2c_utils.hpp>
#include <nil/crypto3/algebra/curves/detail/h2c/ep.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/accumulators/hash.hpp>

using namespace boost::multiprecision;
using namespace nil::crypto3;
using namespace nil::crypto3::algebra::curves::detail;
using namespace nil::crypto3::algebra::curves;

BOOST_AUTO_TEST_SUITE(h2c_manual_tests)

    BOOST_AUTO_TEST_CASE(i2osp_manual_test) {

        constexpr std::size_t len_in_bytes = 128;
        std::array<std::uint8_t, 10> msg{12};
        std::array<std::uint8_t, 10> dst{15};
        std::array<std::uint8_t, len_in_bytes> output{0};
        expand_message_xmd<hashes::sha2<256>, len_in_bytes>::process<1>(msg, dst, output);

        for (auto &c : output) {
            std::cout << static_cast<int>(c) << ", ";
        }
        std::cout << std::endl;

        using ep_map_bls12_g1 = ep_map<typename bls12_381::g1_type>;
        auto ret = ep_map_bls12_g1::hash_to_field<2>(msg);
        for (auto &c : ret) {
            std::cout << c.data << ", ";
        }
        std::cout << std::endl;

        using field_type = fields::bls12_fq<381>;
        using field_value_type = field_type::value_type;
        auto e1 = field_value_type(12341234);
        auto e2 = field_value_type(23451345);
        std::cout << sgn0(e1) << std::endl;
        std::cout << sgn0(e2) << std::endl;

        using fp2_type = fields::fp2<fields::bls12_fq<381>>;
        using fp2_value_type = fp2_type::value_type;
        auto fp2_e1 = fp2_value_type(e1, e2);
        std::cout << sgn0(fp2_e1) << std::endl;

        std::cout << e1.is_square() << std::endl;
        std::cout << e1.squared().is_square() << std::endl;
        std::cout << fp2_e1.is_square() << std::endl;
        std::cout << fp2_e1.squared().is_square() << std::endl;

    }

BOOST_AUTO_TEST_SUITE_END()

