//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE plonk_sha256_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/hashes/sha2/plonk/sha256_process.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_sha256_process) {

    using curve_type = crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 10;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using ArithmetizationParams = crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
    using var = crypto3::zk::snark::plonk_variable<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;

    using component_type = blueprint::components::sha256_process<ArithmetizationType, 9, 1>;

    typename BlueprintFieldType::value_type s = typename BlueprintFieldType::value_type(2).pow(29);
    std::array<typename ArithmetizationType::field_type::value_type, 24> public_input = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        s - 5,      s + 5,      s - 6,      s + 6,      s - 7,      s + 7,      s - 8,      s + 8,
        s - 9,      s + 9,      s + 10,     s - 10,     s + 11,     s - 11,     s + 12,     s - 12};
    std::array<var, 8> input_state_var = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input),
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};

    std::array<typename BlueprintFieldType::integral_type, 64> round_constant = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    std::array<var, 16> input_words_var;
    for (int i = 0; i < 16; i++) {
        input_words_var[i] = var(0, 8 + i, false, var::column_type::public_input);
    }
    std::array<typename BlueprintFieldType::integral_type, 64> message_schedule_array;
    for (std::size_t i = 0; i < 16; i++) {
        message_schedule_array[i] = typename BlueprintFieldType::integral_type(public_input[8 + i].data);
    }

    for(std::size_t i = 16; i < 64; i ++){
        typename BlueprintFieldType::integral_type s0 = ((message_schedule_array[i - 15] >> 7)|((message_schedule_array[i - 15] << (32 - 7)) 
        & typename BlueprintFieldType::integral_type((typename BlueprintFieldType::value_type(2).pow(32) - 1).data))) ^
        ((message_schedule_array[i - 15] >> 18)|((message_schedule_array[i - 15] << (32 - 18))
        & typename BlueprintFieldType::integral_type((typename BlueprintFieldType::value_type(2).pow(32) - 1).data)))
         ^ (message_schedule_array[i - 15] >> 3);
        typename BlueprintFieldType::integral_type s1 = ((message_schedule_array[i - 2] >> 17)|((message_schedule_array[i - 2] << (32 - 17))
        & typename BlueprintFieldType::integral_type((typename BlueprintFieldType::value_type(2).pow(32) - 1).data))) ^
        ((message_schedule_array[i - 2] >> 19)|((message_schedule_array[i - 2] << (32 - 19))
        & typename BlueprintFieldType::integral_type((typename BlueprintFieldType::value_type(2).pow(32) - 1).data)))
         ^ (message_schedule_array[i - 2] >> 10);
        message_schedule_array[i] = (message_schedule_array[i - 16] + s0 + s1 + message_schedule_array[i - 7])%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(32).data); 

    }
    typename ArithmetizationType::field_type::integral_type a =
        typename ArithmetizationType::field_type::integral_type(public_input[0].data);
    typename ArithmetizationType::field_type::integral_type b =
        typename ArithmetizationType::field_type::integral_type(public_input[1].data);
    typename ArithmetizationType::field_type::integral_type c =
        typename ArithmetizationType::field_type::integral_type(public_input[2].data);
    typename ArithmetizationType::field_type::integral_type d =
        typename ArithmetizationType::field_type::integral_type(public_input[3].data);
    typename ArithmetizationType::field_type::integral_type e =
        typename ArithmetizationType::field_type::integral_type(public_input[4].data);
    typename ArithmetizationType::field_type::integral_type f =
        typename ArithmetizationType::field_type::integral_type(public_input[5].data);
    typename ArithmetizationType::field_type::integral_type g =
        typename ArithmetizationType::field_type::integral_type(public_input[6].data);
    typename ArithmetizationType::field_type::integral_type h =
        typename ArithmetizationType::field_type::integral_type(public_input[7].data);
    for (std::size_t i = 0; i < 64; i++) {
        typename BlueprintFieldType::integral_type S0 =
            ((a >> 2) | ((a << (32 - 2)) & typename BlueprintFieldType::integral_type(
                                               (typename BlueprintFieldType::value_type(2).pow(32) - 1).data))) ^
            ((a >> 13) | ((a << (32 - 13)) & typename BlueprintFieldType::integral_type(
                                                 (typename BlueprintFieldType::value_type(2).pow(32) - 1).data))) ^
            ((a >> 22) | ((a << (32 - 22)) & typename BlueprintFieldType::integral_type(
                                                 (typename BlueprintFieldType::value_type(2).pow(32) - 1).data)));
        typename BlueprintFieldType::integral_type S1 =
            ((e >> 6) | ((e << (32 - 6)) & typename BlueprintFieldType::integral_type(
                                               (typename BlueprintFieldType::value_type(2).pow(32) - 1).data))) ^
            ((e >> 11) | ((e << (32 - 11)) & typename BlueprintFieldType::integral_type(
                                                 (typename BlueprintFieldType::value_type(2).pow(32) - 1).data))) ^
            ((e >> 25) | ((e << (32 - 25)) & typename BlueprintFieldType::integral_type(
                                                 (typename BlueprintFieldType::value_type(2).pow(32) - 1).data)));
        typename BlueprintFieldType::integral_type maj = (a & b) ^ (a & c) ^ (b & c);
        typename BlueprintFieldType::integral_type ch = (e & f) ^ ((~e) & g);

        /*std::vector<bool> e_bits(32);
        for (std::size_t j = 0; j < 32; j++) {
            e_bits[32 - j - 1] = multiprecision::bit_test(e, j);
        }
        std::vector<bool> f_bits(32);
        for (std::size_t j = 0; j < 32; j++) {
            f_bits[32 - j - 1] = multiprecision::bit_test(f, j);
        }
        std::vector<bool> g_bits(32);
        for (std::size_t j = 0; j < 32; j++) {
            g_bits[32 - j - 1] = multiprecision::bit_test(g, j);
        }
        std::vector<std::size_t> sizes = {32};
        std::size_t base = 7;

        std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> e_s = 
        component_type::split_and_sparse(e_bits, sizes, base);

        std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> f_s =
        component_type::split_and_sparse(f_bits, sizes, base);

        std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> g_s =
        component_type::split_and_sparse(g_bits, sizes, base);*/
        typename BlueprintFieldType::integral_type tmp1 = h + S1 + ch + round_constant[i] + message_schedule_array[i];
        typename BlueprintFieldType::integral_type tmp2 = S0 + maj;
        h = g;
        g = f;
        f = e;

        e = (d + tmp1)%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(32).data);
        d = c;
        c = b;
        b = a;
        a = (tmp1 + tmp2)%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(32).data);
    }
    std::array<typename BlueprintFieldType::integral_type, 8> result_state = {(a + typename ArithmetizationType::field_type::integral_type(public_input[0].data))%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(32).data),
    (b + typename ArithmetizationType::field_type::integral_type(public_input[1].data))%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(32).data), 
    (c + typename ArithmetizationType::field_type::integral_type(public_input[2].data))%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(32).data),
    (d + typename ArithmetizationType::field_type::integral_type(public_input[3].data))%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(32).data),
    (e + typename ArithmetizationType::field_type::integral_type(public_input[4].data))%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(32).data),
    (f + typename ArithmetizationType::field_type::integral_type(public_input[5].data))%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(32).data),
    (g + typename ArithmetizationType::field_type::integral_type(public_input[6].data))%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(32).data),
    (h + typename ArithmetizationType::field_type::integral_type(public_input[7].data))%
        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(32).data)};
    auto result_check = [result_state](AssignmentType &assignment, 
        component_type::result_type &real_res) {
            for (std::size_t i = 0; i < 8; i++) {
                assert(result_state[i] == typename ArithmetizationType::field_type::integral_type(
                    var_value(assignment, real_res.output_state[i]).data)); 
            }
    };
    typename component_type::input_type instance_input = {input_state_var, input_words_var};

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8},{0},{});
    crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

BOOST_AUTO_TEST_SUITE_END()