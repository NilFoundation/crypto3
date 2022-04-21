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

#define BOOST_TEST_MODULE zk_sponge_test

#include <vector>
#include <iostream>
#include <random>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/fields/vesta/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/vesta/base_field.hpp>

#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/crypto3/zk/transcript/sponge_transcript.hpp>

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(zk_sponge_test_suite)

BOOST_AUTO_TEST_CASE(zk_sponge_test_1) {
    using curve_type = algebra::curves::vesta;
    using group_type = typename curve_type::g1_type<algebra::curves::coordinates::affine>;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using base_field_type = typename curve_type::base_field_type;

    using sponge_type = typename zk::transcript::sponge<curve_type>;
    sponge_type spng;

    std::vector<group_type::value_type> input = {
            {0x3C72072C4C2D6C79918C618C0C0558775A80DDA8ABC694DE53EA5262EF0A52F6_cppui256,
            0x026268186EF91A296845D36EACFE4130450D3B0C00CB1C3318E328BA1CD82111_cppui256},
            {0x11E17954AF9AF8608FF055A7CF2830C0E44A971251F3A0D077D1C0F3A4DFFB40_cppui256,
            0x317190C083716503FB7E4296B2F9D25EC314A1A02F6534272C492425BD282D4E_cppui256},
            {0x3AC575F9C5B610497986839122AD62C9449994A3E5F12C645150254C884FED0A_cppui256,
            0x3D729B10FDA41BD3D4D74E71EF713E471DEBC3538B2AC1EB08D31614314A28B6_cppui256}
        };

    std::vector<std::array<base_field_type::value_type, 3>> expected_state = {
            {0x3C72072C4C2D6C79918C618C0C0558775A80DDA8ABC694DE53EA5262EF0A52F6_cppui256,
            0x026268186EF91A296845D36EACFE4130450D3B0C00CB1C3318E328BA1CD82111_cppui256,
            0x0000000000000000000000000000000000000000000000000000000000000000_cppui256},
            {0x0A11664ADEC02638C98CDBE0F73209B3E7F34B66F956F8803A4CA70024B1EE32_cppui256,
            0x13B70FE1FA9AE8CC3A2F59D8366ACCF51AEF7EE583034F89219C2E8E44ED1013_cppui256,
            0x0CFACA0D7A731C844989A15859F7751D01BBBF50280DB8C9275C45EED05C2B73_cppui256},
            {0x051F50E029D44FBAF50279A387AB5185904C07508E93997BA82734D1F42F07DC_cppui256,
            0x2550685C1DA8481228D4CAA4B07E389B54247BEE80E8BBB68926DF7D52260913_cppui256,
            0x3D23DDDEA2C0DDD1F1AA3AAC55578993454F78BC6CCBE0B56AF2AA45C62DBCEE_cppui256}
    };
    BOOST_CHECK(input.size() == expected_state.size());
    typename scalar_field_type::value_type expected_chal1 = 
                0x000000000000000000000000000000009743EFEDDCA690C49721C1DE84932924_cppui256;
    typename scalar_field_type::value_type expected_chal2 = 
                0x0000000000000000000000000000000077BD26F3574C9051D829A7F0CCD7B53F_cppui256;

    for (std::size_t i = 0; i < input.size(); i++) {
        spng.absorb_g({input[i]});
        for (std::size_t j = 0; j < 3; j++) {
                BOOST_CHECK(spng.pos_sponge.state[j] == expected_state[i][j]);
        }
    }
    BOOST_CHECK(spng.challenge() == expected_chal1);
    BOOST_CHECK(spng.challenge() == expected_chal2);
}

BOOST_AUTO_TEST_SUITE_END()
