//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
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

#define BOOST_TEST_MODULE crypto3_marshalling_eddsa_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <iomanip>
#include <fstream>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/number.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>

#include <nil/crypto3/marshalling/pubkey/types/eddsa.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::marshalling;

template<typename TIter>
void print_byteblob(TIter iter_begin, TIter iter_end) {
    for (TIter it = iter_begin; it != iter_end; it++) {
        std::cout << std::hex << int(*it) << std::endl;
    }
}

template<typename FpCurveGroupElement>
void print_fp_curve_group_element(FpCurveGroupElement e) {
    std::cout << e.X.data << " " << e.Y.data << " " << e.Z.data << std::endl;
}

template<typename Fp2CurveGroupElement>
void print_fp2_curve_group_element(Fp2CurveGroupElement e) {
    std::cout << "(" << e.X.data[0].data << " " << e.X.data[1].data << ") (" << e.Y.data[0].data << " "
              << e.Y.data[1].data << ") (" << e.Z.data[0].data << " " << e.Z.data[1].data << ")" << std::endl;
}


BOOST_AUTO_TEST_SUITE(lpc_test_suite)

    BOOST_AUTO_TEST_CASE(lpc_bls12_381_be) {
        using curve_type = algebra::curves::curve25519;
        using group_type = typename curve_type::g1_type<>;
        using group_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
        using group_value_type = typename group_type::value_type;
        using group_affine_value_type = typename group_affine_type::value_type;

        using params_type = void;
        using scheme_type = pubkey::eddsa<group_type, pubkey::eddsa_type::basic, params_type>;
        using private_key_type = pubkey::private_key<scheme_type>;
        using public_key_type = pubkey::public_key<scheme_type>;
        using _private_key_type = typename private_key_type::private_key_type;
        using _public_key_type = typename public_key_type::public_key_type;

        // -----TEST 1
        _private_key_type privkey1 = {0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a,
                                      0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32,
                                      0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};
        _public_key_type etalon_pubkey1 = {0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe,
                                           0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6,
                                           0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};
        std::array<std::uint8_t, 0> msg1 = {};
        typename private_key_type::signature_type etalon_sig1 = {
                0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
                0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
                0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
                0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b};

        using endianness = nil::marshalling::option::big_endian;
        public_key_type pub_k(etalon_pubkey1);
        private_key_type priv_k(privkey1);

        auto filled_key = nil::crypto3::marshalling::types::fill_eddsa_public_key<
                public_key_type, endianness>(pub_k);

        auto made_key = nil::crypto3::marshalling::types::make_eddsa_public_key<
                public_key_type, endianness>(filled_key);

        BOOST_CHECK(made_key.pubkey_point == pub_k.pubkey_point);
        BOOST_CHECK(std::equal(made_key.pubkey.begin(), made_key.pubkey.end(), pub_k.pubkey.begin()));

        auto filled_priv_key = nil::crypto3::marshalling::types::fill_eddsa_private_key<
                private_key_type, endianness>(priv_k);

        auto made_priv_key = nil::crypto3::marshalling::types::make_eddsa_private_key<
                private_key_type, endianness>(filled_priv_key);

        BOOST_CHECK(made_priv_key.s_reduced == priv_k.s_reduced);
        BOOST_CHECK(std::equal(made_priv_key.privkey.begin(), made_priv_key.privkey.end(), priv_k.privkey.begin()));
        BOOST_CHECK(
                std::equal(made_priv_key.h_privkey.begin(), made_priv_key.h_privkey.end(), priv_k.h_privkey.begin()));
    }

BOOST_AUTO_TEST_SUITE_END()
