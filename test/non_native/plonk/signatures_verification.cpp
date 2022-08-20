//---------------------------------------------------------------------------//
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_signatures_verification_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/ed25519.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/signatures_verification.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/ed25519.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

template<typename ed25519_type>
typename ed25519_type::scalar_field_type::value_type sha512(typename ed25519_type::template g1_type<algebra::curves::coordinates::affine>::value_type R,
 typename ed25519_type::template g1_type<algebra::curves::coordinates::affine>::value_type pk, std::array<typename ed25519_type::base_field_type::integral_type, 4> M) {
     std::array<typename ed25519_type::base_field_type::integral_type, 80>
                        round_constant = {
                            0x428a2f98d728ae22_cppui64, 0x7137449123ef65cd_cppui64, 0xb5c0fbcfec4d3b2f_cppui64, 0xe9b5dba58189dbbc_cppui64,
                            0x3956c25bf348b538_cppui64, 0x59f111f1b605d019_cppui64, 0x923f82a4af194f9b_cppui64, 0xab1c5ed5da6d8118_cppui64,
                            0xd807aa98a3030242_cppui64, 0x12835b0145706fbe_cppui64, 0x243185be4ee4b28c_cppui64, 0x550c7dc3d5ffb4e2_cppui64,
                            0x72be5d74f27b896f_cppui64, 0x80deb1fe3b1696b1_cppui64, 0x9bdc06a725c71235_cppui64, 0xc19bf174cf692694_cppui64,
                            0xe49b69c19ef14ad2_cppui64, 0xefbe4786384f25e3_cppui64, 0x0fc19dc68b8cd5b5_cppui64, 0x240ca1cc77ac9c65_cppui64,
                            0x2de92c6f592b0275_cppui64, 0x4a7484aa6ea6e483_cppui64, 0x5cb0a9dcbd41fbd4_cppui64, 0x76f988da831153b5_cppui64,
                            0x983e5152ee66dfab_cppui64, 0xa831c66d2db43210_cppui64, 0xb00327c898fb213f_cppui64, 0xbf597fc7beef0ee4_cppui64,
                            0xc6e00bf33da88fc2_cppui64, 0xd5a79147930aa725_cppui64, 0x06ca6351e003826f_cppui64, 0x142929670a0e6e70_cppui64,
                            0x27b70a8546d22ffc_cppui64, 0x2e1b21385c26c926_cppui64, 0x4d2c6dfc5ac42aed_cppui64, 0x53380d139d95b3df_cppui64,
                            0x650a73548baf63de_cppui64, 0x766a0abb3c77b2a8_cppui64, 0x81c2c92e47edaee6_cppui64, 0x92722c851482353b_cppui64,
                            0xa2bfe8a14cf10364_cppui64, 0xa81a664bbc423001_cppui64, 0xc24b8b70d0f89791_cppui64, 0xc76c51a30654be30_cppui64,
                            0xd192e819d6ef5218_cppui64, 0xd69906245565a910_cppui64, 0xf40e35855771202a_cppui64, 0x106aa07032bbd1b8_cppui64,
                            0x19a4c116b8d2d0c8_cppui64, 0x1e376c085141ab53_cppui64, 0x2748774cdf8eeb99_cppui64, 0x34b0bcb5e19b48a8_cppui64,
                            0x391c0cb3c5c95a63_cppui64, 0x4ed8aa4ae3418acb_cppui64, 0x5b9cca4f7763e373_cppui64, 0x682e6ff3d6b2b8a3_cppui64,
                            0x748f82ee5defb2fc_cppui64, 0x78a5636f43172f60_cppui64, 0x84c87814a1f0ab72_cppui64, 0x8cc702081a6439ec_cppui64,
                            0x90befffa23631e28_cppui64, 0xa4506cebde82bde9_cppui64, 0xbef9a3f7b2c67915_cppui64, 0xc67178f2e372532b_cppui64,
                            0xca273eceea26619c_cppui64, 0xd186b8c721c0c207_cppui64, 0xeada7dd6cde0eb1e_cppui64, 0xf57d4f7fee6ed178_cppui64,
                            0x06f067aa72176fba_cppui64, 0x0a637dc5a2c898a6_cppui64, 0x113f9804bef90dae_cppui64, 0x1b710b35131c471b_cppui64,
                            0x28db77f523047d84_cppui64, 0x32caab7b40c72493_cppui64, 0x3c9ebe0a15c9bebc_cppui64, 0x431d67c49c100d4c_cppui64,
                            0x4cc5d4becb3e42b6_cppui64, 0x597f299cfc657e2a_cppui64, 0x5fcb6fab3ad6faec_cppui64, 0x6c44198c4a475817_cppui64};

    std::array<typename ed25519_type::base_field_type::integral_type, 80> message_schedule_array;
    std::array<typename ed25519_type::base_field_type::integral_type, 8> public_input = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                            0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};
    typename ed25519_type::base_field_type::integral_type one = 1;
    typename ed25519_type::base_field_type::integral_type mask = (one << 64) - 1;
    typename ed25519_type::base_field_type::integral_type Rx = typename ed25519_type::base_field_type::integral_type(R.X.data);
    typename ed25519_type::base_field_type::integral_type Ry = typename ed25519_type::base_field_type::integral_type(R.Y.data);
    typename ed25519_type::base_field_type::integral_type pkx = typename ed25519_type::base_field_type::integral_type(pk.X.data);
    typename ed25519_type::base_field_type::integral_type pky = typename ed25519_type::base_field_type::integral_type(pk.Y.data);
    message_schedule_array[0] = Rx & mask;
    message_schedule_array[1] = (Rx >> 64) & mask;
    message_schedule_array[2] = (Rx >> 128) & mask;
    message_schedule_array[3] = ((Rx >> 192) & mask) + (Ry & 1) * (one << 63);
    message_schedule_array[4] = (Ry >> 1) & mask;
    message_schedule_array[5] = (Ry >> 65) & mask;
    message_schedule_array[6] = (Ry >> 129) & mask;
    message_schedule_array[7] = ((Ry >> 193) & mask) + (pkx & 3) * (one << 62);
    message_schedule_array[8] = (pkx >> 2) & mask;
    message_schedule_array[9] = (pkx >> 66) & mask;
    message_schedule_array[10] = (pkx >> 130) & mask;
    message_schedule_array[11] = ((pkx >> 194) & mask) + (pky & 7) * (one << 61);
    message_schedule_array[12] = (pky >> 3) & mask;
    message_schedule_array[13] = (pky >> 67) & mask;
    message_schedule_array[14] = (pky >> 131) & mask;
    message_schedule_array[15] = ((pky >> 195) & mask) + (M[0] & 15) * (one << 60);
    for(std::size_t i = 16; i < 80; i ++){
        typename ed25519_type::base_field_type::integral_type s0 = ((message_schedule_array[i - 15] >> 1)|((message_schedule_array[i - 15] << (64 - 1)) 
        & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data))) ^
        ((message_schedule_array[i - 15] >> 8)|((message_schedule_array[i - 15] << (64 - 8))
        & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)))
         ^ (message_schedule_array[i - 15] >> 7);
        typename ed25519_type::base_field_type::integral_type s1 = ((message_schedule_array[i - 2] >> 19)|((message_schedule_array[i - 2] << (64 - 19))
        & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data))) ^
        ((message_schedule_array[i - 2] >> 61)|((message_schedule_array[i - 2] << (64 - 61))
        & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)))
         ^ (message_schedule_array[i - 2] >> 6);
        message_schedule_array[i] = (message_schedule_array[i - 16] + s0 + s1 + message_schedule_array[i - 7])%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data);
    }
    typename ed25519_type::base_field_type::integral_type a = typename ed25519_type::base_field_type::integral_type(public_input[0]);
    typename ed25519_type::base_field_type::integral_type b = typename ed25519_type::base_field_type::integral_type(public_input[1]);
    typename ed25519_type::base_field_type::integral_type c = typename ed25519_type::base_field_type::integral_type(public_input[2]);
    typename ed25519_type::base_field_type::integral_type d = typename ed25519_type::base_field_type::integral_type(public_input[3]);
    typename ed25519_type::base_field_type::integral_type e = typename ed25519_type::base_field_type::integral_type(public_input[4]);
    typename ed25519_type::base_field_type::integral_type f = typename ed25519_type::base_field_type::integral_type(public_input[5]);
    typename ed25519_type::base_field_type::integral_type g = typename ed25519_type::base_field_type::integral_type(public_input[6]);
    typename ed25519_type::base_field_type::integral_type h = typename ed25519_type::base_field_type::integral_type(public_input[7]);
    for(std::size_t i = 0; i < 80; i ++){
        typename ed25519_type::base_field_type::integral_type S0 = ((a >> 28)|((a << (64 - 28)) 
        & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data))) ^
        ((a >> 34)|((a << (64 - 34))
        & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)))
         ^ ((a >> 39)|((a << (64 - 39))
        & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)));

        typename ed25519_type::base_field_type::integral_type S1 = ((e >> 14)|((e << (64 - 14)) 
        & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data))) ^
        ((e >> 18)|((e << (64 - 18))
        & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)))
         ^ ((e >> 41)|((e << (64 - 41))
        & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)));

        typename ed25519_type::base_field_type::integral_type maj = (a & b) ^ (a & c) ^ (b & c);
        typename ed25519_type::base_field_type::integral_type ch = (e & f) ^ ((~e)& g);
        typename ed25519_type::base_field_type::integral_type tmp1 = h + S1 + ch + round_constant[i] + message_schedule_array[i];
        typename ed25519_type::base_field_type::integral_type tmp2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = (d + tmp1)%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data);
        d = c;
        c = b;
        b = a;
        a = (tmp1 + tmp2)%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data);
    }
    std::array<typename ed25519_type::base_field_type::integral_type, 8> output_state = {(a + typename ed25519_type::base_field_type::integral_type(public_input[0]))%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
    (b + typename ed25519_type::base_field_type::integral_type(public_input[1]))%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data), 
    (c + typename ed25519_type::base_field_type::integral_type(public_input[2]))%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
    (d + typename ed25519_type::base_field_type::integral_type(public_input[3]))%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
    (e + typename ed25519_type::base_field_type::integral_type(public_input[4]))%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
    (f + typename ed25519_type::base_field_type::integral_type(public_input[5]))%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
    (g + typename ed25519_type::base_field_type::integral_type(public_input[6]))%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
    (h + typename ed25519_type::base_field_type::integral_type(public_input[7]))%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data)};
    typename ed25519_type::base_field_type::integral_type bits_amount = 255*4+256;
    message_schedule_array[0] = ((M[0] >> 4) & mask) + (M[1] & 3) * (one << 62);
    message_schedule_array[1] = (M[1] >> 2) & mask;
    message_schedule_array[2] =  M[2] & mask;
    message_schedule_array[3] = (M[2] >> 64) + (M[3]) * (one << 2) + 1 * (one << 60);
    message_schedule_array[4] = 0;
    message_schedule_array[5] = 0;
    message_schedule_array[6] = 0;
    message_schedule_array[7] = 0;
    message_schedule_array[8] = 0;
    message_schedule_array[9] = 0;
    message_schedule_array[10] = 0;
    message_schedule_array[11] = 0;
    message_schedule_array[12] = 0;
    message_schedule_array[13] = 0;
    message_schedule_array[14] = 0;
    message_schedule_array[15] = bits_amount;
        for(std::size_t i = 16; i < 80; i ++){
        typename ed25519_type::base_field_type::integral_type s0 = ((message_schedule_array[i - 15] >> 1)|((message_schedule_array[i - 15] << (64 - 1)) 
        & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data))) ^
        ((message_schedule_array[i - 15] >> 8)|((message_schedule_array[i - 15] << (64 - 8))
        & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)))
         ^ (message_schedule_array[i - 15] >> 7);
        typename ed25519_type::base_field_type::integral_type s1 = ((message_schedule_array[i - 2] >> 19)|((message_schedule_array[i - 2] << (64 - 19))
        & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data))) ^
        ((message_schedule_array[i - 2] >> 61)|((message_schedule_array[i - 2] << (64 - 61))
        & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)))
         ^ (message_schedule_array[i - 2] >> 6);
        message_schedule_array[i] = (message_schedule_array[i - 16] + s0 + s1 + message_schedule_array[i - 7])%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data);
    }
    a = typename ed25519_type::base_field_type::integral_type(output_state[0]);
    b = typename ed25519_type::base_field_type::integral_type(output_state[1]);
    c = typename ed25519_type::base_field_type::integral_type(output_state[2]);
    d = typename ed25519_type::base_field_type::integral_type(output_state[3]);
    e = typename ed25519_type::base_field_type::integral_type(output_state[4]);
    f = typename ed25519_type::base_field_type::integral_type(output_state[5]);
    g = typename ed25519_type::base_field_type::integral_type(output_state[6]);
    h = typename ed25519_type::base_field_type::integral_type(output_state[7]);
    for(std::size_t i = 0; i < 80; i ++){
        typename ed25519_type::base_field_type::integral_type S0 = ((a >> 28)|((a << (64 - 28)) 
        & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data))) ^
        ((a >> 34)|((a << (64 - 34))
        & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)))
         ^ ((a >> 39)|((a << (64 - 39))
        & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)));

        typename ed25519_type::base_field_type::integral_type S1 = ((e >> 14)|((e << (64 - 14)) 
        & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data))) ^
        ((e >> 18)|((e << (64 - 18))
        & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)))
         ^ ((e >> 41)|((e << (64 - 41))
        & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)));

        typename ed25519_type::base_field_type::integral_type maj = (a & b) ^ (a & c) ^ (b & c);
        typename ed25519_type::base_field_type::integral_type ch = (e & f) ^ ((~e)& g);
        typename ed25519_type::base_field_type::integral_type tmp1 = h + S1 + ch + round_constant[i] + message_schedule_array[i];
        typename ed25519_type::base_field_type::integral_type tmp2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = (d + tmp1)%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data);
        d = c;
        c = b;
        b = a;
        a = (tmp1 + tmp2)%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data);
    }
    std::array<typename ed25519_type::base_field_type::extended_integral_type, 8> result_state1 = {(a + typename ed25519_type::base_field_type::integral_type(output_state[0]))%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
    (b + typename ed25519_type::base_field_type::integral_type(output_state[1]))%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data), 
    (c + typename ed25519_type::base_field_type::integral_type(output_state[2]))%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
    (d + typename ed25519_type::base_field_type::integral_type(output_state[3]))%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
    (e + typename ed25519_type::base_field_type::integral_type(output_state[4]))%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
    (f + typename ed25519_type::base_field_type::integral_type(output_state[5]))%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
    (g + typename ed25519_type::base_field_type::integral_type(output_state[6]))%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
    (h + typename ed25519_type::base_field_type::integral_type(output_state[7]))%
        typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data)};
    typename ed25519_type::scalar_field_type::value_type two = 2;
    typename ed25519_type::scalar_field_type::value_type res = result_state1[0] + result_state1[1] * two.pow(64) + result_state1[2] * two.pow(128)
    + result_state1[3] * two.pow(192) + result_state1[4] * two.pow(256) + result_state1[5] * two.pow(320) + result_state1[6] * two.pow(384) +
    result_state1[7] * two.pow(448);

    return res;
 }

BOOST_AUTO_TEST_CASE(blueprint_signatures_verification) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::pallas;
    using ed25519_type = algebra::curves::ed25519;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 21;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;
    constexpr const std::size_t k = 1;
    using component_type = zk::components::signatures_verification<ArithmetizationType, curve_type, ed25519_type, k, 0, 1, 2, 3,
                                                                          4, 5, 6, 7, 8>;
    using ed25519_component = zk::components::eddsa25519<ArithmetizationType, curve_type, ed25519_type,
                    0, 1, 2, 3, 4, 5, 6, 7, 8>; 
    using var_ec_point = typename ed25519_component::params_type::var_ec_point;
    using signature = typename ed25519_component::params_type::signature;

    ed25519_type::template g1_type<algebra::curves::coordinates::affine>::value_type B =
    ed25519_type::template g1_type<algebra::curves::coordinates::affine>::value_type::one();
    auto M = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001_cppui256;
    
    std::vector<typename BlueprintFieldType::value_type> public_input;
    typename ed25519_type::base_field_type::integral_type base = 1;
    typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;
    std::array<signature, k> Signatures;
    std::array<var_ec_point, k> Public_keys;
    std::array<ed25519_type::template g1_type<algebra::curves::coordinates::affine>::value_type, k> Signatures_point;
    std::array<ed25519_type::scalar_field_type::value_type, k> Signatures_scalar;
    std::array<ed25519_type::template g1_type<algebra::curves::coordinates::affine>::value_type, k> Public_keys_values;
    for(std::size_t i = 0; i < k; i++) {
        ed25519_type::scalar_field_type::value_type r = algebra::random_element<ed25519_type::scalar_field_type>();
        ed25519_type::scalar_field_type::value_type c = algebra::random_element<ed25519_type::scalar_field_type>();
        ed25519_type::template g1_type<algebra::curves::coordinates::affine>::value_type R = r*B;
        Signatures_point[i] = R;
        ed25519_type::template g1_type<algebra::curves::coordinates::affine>::value_type P = c*B;
        Public_keys_values[i] = P;
        auto sha_output = sha512<ed25519_type>(R, P, {ed25519_type::base_field_type::integral_type(M & mask), ed25519_type::base_field_type::integral_type((M >> 66) & mask)
        , ed25519_type::base_field_type::integral_type((M >> 132) & mask), ed25519_type::base_field_type::integral_type((M >> 198) & mask)});
        ed25519_type::scalar_field_type::value_type s = r + sha_output*c;
        Signatures_scalar[i] = s;
        ed25519_type::base_field_type::integral_type Rx = ed25519_type::base_field_type::integral_type(R.X.data);
        ed25519_type::base_field_type::integral_type Ry = ed25519_type::base_field_type::integral_type(R.Y.data);
        ed25519_type::base_field_type::integral_type Px = ed25519_type::base_field_type::integral_type(P.X.data);
        ed25519_type::base_field_type::integral_type Py = ed25519_type::base_field_type::integral_type(P.Y.data);
        public_input.insert(public_input.end(), {Rx & mask, (Rx >> 66) & mask, (Rx >> 132) & mask, (Rx >> 198) & mask,
        Ry & mask, (Ry >> 66) & mask, (Ry >> 132) & mask, (Ry >> 198) & mask, typename BlueprintFieldType::integral_type(s.data), 
        Px & mask, (Px >> 66) & mask, (Px >> 132) & mask, (Px >> 198) & mask,
        Py & mask, (Py >> 66) & mask, (Py >> 132) & mask, (Py >> 198) & mask});
        std::array<var, 4> e_R_x = {var(0, i*17 + 0, false, var::column_type::public_input), var(0, i*17 + 1, false, var::column_type::public_input),
        var(0, i*17 + 2, false, var::column_type::public_input), var(0, i*17 + 3, false, var::column_type::public_input)};
        std::array<var, 4> e_R_y = {var(0, i*17 + 4, false, var::column_type::public_input), var(0, i*17 + 5, false, var::column_type::public_input),
            var(0, i*17 + 6, false, var::column_type::public_input), var(0, i*17 + 7, false, var::column_type::public_input)};
        var_ec_point R_i = {e_R_x, e_R_y};
        var e_s = var(0, i*17 + 8, false, var::column_type::public_input);
        Signatures[i] = {R_i, e_s};
        std::array<var, 4> pk_x = {var(0, i*17 + 9, false, var::column_type::public_input), var(0, i*17 + 10, false, var::column_type::public_input),
            var(0, i*17 + 11, false, var::column_type::public_input), var(0, i*17 + 12, false, var::column_type::public_input)};
        std::array<var, 4> pk_y = {var(0, i*17 + 13, false, var::column_type::public_input), var(0, i*17 + 14, false, var::column_type::public_input), 
            var(0, i*17 + 15, false, var::column_type::public_input), var(0, i*17 + 16, false, var::column_type::public_input)};
        Public_keys[i] = {pk_x, pk_y};
    }
    public_input.insert(public_input.end(), {ed25519_type::base_field_type::integral_type(M & mask), ed25519_type::base_field_type::integral_type((M >> 66) & mask)
        , ed25519_type::base_field_type::integral_type((M >> 132) & mask), ed25519_type::base_field_type::integral_type((M >> 198) & mask)});

    std::array<var, 4> M_var = {var(0, k*17, false, var::column_type::public_input), var(0, k*17 + 1, false, var::column_type::public_input),
        var(0, k*17 + 2, false, var::column_type::public_input), var(0, k*17 + 3, false, var::column_type::public_input)};


    typename component_type::params_type params = {Signatures, Public_keys, M_var};
    
    auto result_check = [](AssignmentType &assignment, 
        component_type::result_type &real_res) {
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "Time_execution: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()