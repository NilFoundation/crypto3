//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the SHA512 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_SHA512_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_SHA512_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class sha512;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                         std::size_t W6, std::size_t W7, std::size_t W8>
                class sha512<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, CurveType, W0,
                             W1, W2, W3, W4, W5, W6, W7, W8> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;
                    constexpr static const std::size_t rounds_amount = 80;

                    constexpr static const std::size_t base4 = 4;
                    constexpr static const std::size_t base7 = 7;

                    constexpr static const std::array<typename BlueprintFieldType::value_type, rounds_amount>
                        round_constant = {
                            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
                            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
                            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
                            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
                            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
                            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
                            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
                            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
                            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
                            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
                            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
                            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
                            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
                            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
                            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
                            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
                            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
                            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

                public:
                    constexpr static const std::size_t required_rows_amount = 1248;

                    struct params_type {
                        std::array<var, 8> input_state;
                        std::vector<var> input_words;
                    };

                    struct allocated_data_type {
                        allocated_data_type() {
                            previously_allocated = false;
                        }

                        // TODO access modifiers
                        bool previously_allocated;
                        std::array<std::size_t, 73> selectors;
                    };

                    struct result_type {
                        std::array<var, 8> output_state = {var(0, 0, false), var(0, 0, false), var(0, 0, false),
                                                           var(0, 0, false), var(0, 0, false), var(0, 0, false),
                                                           var(0, 0, false), var(0, 0, false)};

                        result_type(const std::size_t &component_start_row) {
                            std::array<var, 8> output_state = {
                                var(W0, component_start_row + required_rows_amount - 3, false),
                                var(W1, component_start_row + required_rows_amount - 3, false),
                                var(W2, component_start_row + required_rows_amount - 3, false),
                                var(W3, component_start_row + required_rows_amount - 3, false),
                                var(W4, component_start_row + required_rows_amount - 3, false),
                                var(W5, component_start_row + required_rows_amount - 3, false),
                                var(W0, component_start_row + required_rows_amount - 1, false),
                                var(W1, component_start_row + required_rows_amount - 1, false)};
                        }
                    };

                    static std::size_t allocate_rows(blueprint<ArithmetizationType> &bp) {
                        return bp.allocate_rows(required_rows_amount);
                    }

                    static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                                                        blueprint_assignment_table<ArithmetizationType> &assignment,
                                                        const params_type &params,
                                                        allocated_data_type &allocated_data,
                                                        const std::size_t &component_start_row) {

                        generate_gates(bp, assignment, params, allocated_data, component_start_row);
                        generate_copy_constraints(bp, assignment, params, component_start_row);
                        return result_type(component_start_row);
                    }

                    static void generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                     const params_type &params,
                                                     const std::size_t &component_start_row) {
                        std::size_t row = component_start_row;
                        std::array<typename ArithmetizationType::field_type::value_type, 8> input_state = {
                            assignment.var_value(params.input_state[0]), assignment.var_value(params.input_state[1]),
                            assignment.var_value(params.input_state[2]), assignment.var_value(params.input_state[3]),
                            assignment.var_value(params.input_state[4]), assignment.var_value(params.input_state[5]),
                            assignment.var_value(params.input_state[5]), assignment.var_value(params.input_state[7])};
                        std::array<typename ArithmetizationType::field_type::value_type, 64> message_scheduling_words;
                        for (std::size_t i = 0; i < 16; i++) {
                            message_scheduling_words[i] = assignment.var_value(params.input_words[i]);
                        }
                        typename ArithmetizationType::field_type::value_type a = input_state[0];
                        typename ArithmetizationType::field_type::value_type b = input_state[1];
                        typename ArithmetizationType::field_type::value_type c = input_state[2];
                        typename ArithmetizationType::field_type::value_type d = input_state[3];
                        typename ArithmetizationType::field_type::value_type e = input_state[4];
                        typename ArithmetizationType::field_type::value_type f = input_state[5];
                        typename ArithmetizationType::field_type::value_type g = input_state[6];
                        typename ArithmetizationType::field_type::value_type h = input_state[7];

                        std::array<int64_t, 8> sparse_values;
                        for (std::size_t i = 0; i < 4; i++) {
                            assignment.witness(i)[row] = input_state[i];
                            std::vector<bool> input_state_sparse(32);
                            typename CurveType::scalar_field_type::integral_type integral_input_state_sparse =
                                typename CurveType::scalar_field_type::integral_type(input_state[i].data);
                            for (std::size_t i = 0; i < 32; i++) {
                                input_state_sparse[32 - i - 1] =
                                    multiprecision::bit_test(integral_input_state_sparse, i);
                            }
                            std::vector<std::size_t> input_state_sparse_sizes = {32};
                            std::array<std::vector<uint64_t>, 2> input_state_sparse_chunks =
                                split_and_sparse(input_state_sparse, input_state_sparse_sizes, base4);
                            assignment.witness(i)[row + 1] = input_state_sparse_chunks[1][0];
                            sparse_values[i] = input_state_sparse_chunks[1][0];
                            assignment.witness(i)[row + 2] = message_scheduling_words[i];
                            assignment.witness(i)[row + 3] = message_scheduling_words[2 * i];
                        }
                        for (std::size_t i = 4; i < 8; i++) {
                            assignment.witness(i)[row] = input_state[i];
                            std::vector<bool> input_state_sparse(32);
                            typename CurveType::scalar_field_type::integral_type integral_input_state_sparse =
                                typename CurveType::scalar_field_type::integral_type(input_state[i].data);
                            for (std::size_t i = 0; i < 32; i++) {
                                input_state_sparse[32 - i - 1] =
                                    multiprecision::bit_test(integral_input_state_sparse, i);
                            }
                            std::vector<std::size_t> input_state_sparse_sizes = {32};
                            std::array<std::vector<uint64_t>, 2> input_state_sparse_chunks =
                                split_and_sparse(input_state_sparse, input_state_sparse_sizes, base7);
                            assignment.witness(i)[row + 1] = input_state_sparse_chunks[1][0];
                            sparse_values[i] = input_state_sparse_chunks[1][0];
                            assignment.witness(i)[row + 2] = message_scheduling_words[i];
                            assignment.witness(i)[row + 3] = message_scheduling_words[2 * i];
                        }
                        row = row + 4;
                        std::vector<std::size_t> sigma_sizes = {14, 14, 2, 2};
                        std::vector<std::size_t> ch_and_maj_sizes = {8, 8, 8, 8};
                        for (std::size_t i = row; i < row + 240; i = i + 5) {
                            std::vector<bool> a(32);
                            typename CurveType::scalar_field_type::integral_type integral_a =
                                typename CurveType::scalar_field_type::integral_type(
                                    message_scheduling_words[i / 5 + 1].data);
                            assignment.witness(W0)[i] = message_scheduling_words[i / 5 + 1];
                            for (std::size_t i = 0; i < 32; i++) {
                                a[32 - i - 1] = multiprecision::bit_test(integral_a, i);
                            }
                            std::vector<std::size_t> a_sizes = {3, 4, 11, 14};
                            std::array<std::vector<uint64_t>, 2> a_chunks = split_and_sparse(a, a_sizes, base4);
                            assignment.witness(W1)[i] = a_chunks[0][0];
                            assignment.witness(W2)[i] = a_chunks[0][1];
                            assignment.witness(W3)[i] = a_chunks[0][2];
                            assignment.witness(W4)[i] = a_chunks[0][3];
                            assignment.witness(W7)[i] = a_chunks[1][0];
                            assignment.witness(W0)[i + 1] = message_scheduling_words[i / 5 + 9];
                            assignment.witness(W1)[i + 1] = message_scheduling_words[i / 5];
                            assignment.witness(W2)[i + 1] = a_chunks[1][1];
                            assignment.witness(W3)[i + 1] = a_chunks[1][2];
                            assignment.witness(W4)[i + 1] = a_chunks[1][3];
                            typename CurveType::scalar_field_type::integral_type sparse_sigma0 =
                                a_chunks[1][1] * (1 + (1 << 56) + (1 << 54)) +
                                a_chunks[1][2] * ((1 << 8) + 1 + (1 << 42)) +
                                a_chunks[1][3] * ((1 << 30) + (1 << 22) + 1) + a_chunks[1][0] * ((1 << 50) + (1 << 28));
                            static std::array<std::vector<typename CurveType::scalar_field_type::integral_type>, 2>
                                sigma0_chunks = reversed_sparse_and_split(sparse_sigma0, sigma_sizes, base4);
                            assignment.witness(W5)[i + 1] = sigma0_chunks[1][0];
                            assignment.witness(W6)[i + 1] = sigma0_chunks[1][1];
                            assignment.witness(W7)[i + 1] = sigma0_chunks[1][2];
                            assignment.witness(W8)[i + 1] = sigma0_chunks[1][3];

                            assignment.witness(W1)[i + 2] = sigma0_chunks[0][0];
                            assignment.witness(W2)[i + 2] = sigma0_chunks[0][1];
                            assignment.witness(W3)[i + 2] = sigma0_chunks[0][2];
                            assignment.witness(W4)[i + 2] = sigma0_chunks[0][3];

                            std::vector<bool> b(32);
                            typename CurveType::scalar_field_type::integral_type integral_b =
                                typename CurveType::scalar_field_type::integral_type(
                                    message_scheduling_words[i / 5 + 14].data);
                            for (std::size_t i = 0; i < 32; i++) {
                                b[32 - i - 1] = multiprecision::bit_test(integral_b, i);
                            }
                            std::vector<std::size_t> b_sizes = {10, 7, 2, 13};
                            std::array<std::vector<std::size_t>, 2> b_chunks = split_and_sparse(b, b_sizes, base4);
                            assignment.witness(W0)[i + 4] = message_scheduling_words[i / 5 + 14];
                            assignment.witness(W1)[i + 4] = b_chunks[0][0];
                            assignment.witness(W2)[i + 4] = b_chunks[0][1];
                            assignment.witness(W3)[i + 4] = b_chunks[0][2];
                            assignment.witness(W4)[i + 4] = b_chunks[0][3];

                            assignment.witness(W1)[i + 3] = b_chunks[1][0];
                            assignment.witness(W2)[i + 3] = b_chunks[1][1];
                            assignment.witness(W3)[i + 3] = b_chunks[1][2];
                            assignment.witness(W4)[i + 3] = b_chunks[1][3];

                            typename CurveType::scalar_field_type::integral_type sparse_sigma1 =
                                b_chunks[1][1] * (1 + (1 << 50) + (1 << 46)) +
                                b_chunks[1][2] * ((1 << 14) + 1 + (1 << 60)) +
                                b_chunks[1][3] * ((1 << 18) + (1 << 4) + 1) + b_chunks[1][0] * ((1 << 30) + (1 << 26));

                            static std::array<std::vector<typename CurveType::scalar_field_type::integral_type>, 2>
                                sigma1_chunks = reversed_sparse_and_split(sparse_sigma1, sigma_sizes, base4);
                            assignment.witness(W5)[i + 3] = sigma1_chunks[1][0];
                            assignment.witness(W6)[i + 3] = sigma1_chunks[1][1];
                            assignment.witness(W7)[i + 3] = sigma1_chunks[1][2];
                            assignment.witness(W8)[i + 3] = sigma1_chunks[1][3];

                            assignment.witness(W5)[i + 2] = sigma1_chunks[0][0];
                            assignment.witness(W6)[i + 2] = sigma1_chunks[0][1];
                            assignment.witness(W7)[i + 2] = sigma1_chunks[0][2];
                            assignment.witness(W8)[i + 2] = sigma1_chunks[0][3];
                            message_scheduling_words[i / 5 + 16] =
                                message_scheduling_words[i / 5 + 14] + message_scheduling_words[i / 5] +
                                sigma1_chunks[0][0] + sigma0_chunks[0][0] +
                                (1 << 14) * (sigma1_chunks[0][1] + sigma0_chunks[0][1]) +
                                (1 << 28) * (sigma1_chunks[0][2] + sigma0_chunks[0][2]) +
                                (1 << 30) * (sigma1_chunks[0][3] + sigma0_chunks[0][3]);
                            assignment.witness(W0)[i + 2] = message_scheduling_words[i / 5 + 16];
                        }
                        row = row + 240;
                        for (std::size_t i = row; i < row + 512; i = i + 8) {
                            assignment.witness(W0)[i] = e;
                            std::vector<bool> e_bits(32);
                            typename CurveType::scalar_field_type::integral_type integral_e =
                                typename CurveType::scalar_field_type::integral_type(e.data);
                            for (std::size_t i = 0; i < 32; i++) {
                                e_bits[32 - i - 1] = multiprecision::bit_test(integral_e, i);
                            }
                            std::vector<std::size_t> e_sizes = {6, 5, 14, 7};
                            std::array<std::vector<uint64_t>, 2> e_chunks = split_and_sparse(e_bits, e_sizes, base7);
                            assignment.witness(W2)[i] = e_chunks[0][0];
                            assignment.witness(W3)[i] = e_chunks[0][1];
                            assignment.witness(W4)[i] = e_chunks[0][2];
                            assignment.witness(W5)[i] = e_chunks[0][3];

                            assignment.witness(W1)[i] = e_chunks[1][0];
                            assignment.witness(W2)[i + 1] = e_chunks[1][1];
                            assignment.witness(W3)[i + 1] = e_chunks[1][2];
                            assignment.witness(W4)[i + 1] = e_chunks[1][3];

                            sparse_values[4] = e_chunks[1][0] + e_chunks[1][1] * pow(7, e_sizes[0]) +
                                               e_chunks[1][2] * pow(7, e_sizes[0] + e_sizes[1]) +
                                               e_chunks[1][3] * pow(7, e_sizes[0] + e_sizes[1] + e_sizes[2]);
                            assignment.witness(W0)[i + 1] = sparse_values[4];
                            assignment.witness(W1)[i + 1] = sparse_values[5];
                            typename CurveType::scalar_field_type::integral_type sparse_Sigma1 =
                                e_chunks[1][1] * ((1 << 54) + (1 << 26) + 1) +
                                e_chunks[1][2] * ((1 << 10) + 1 + (1 << 54)) +
                                e_chunks[1][3] * ((1 << 38) + (1 << 28) + 1) +
                                e_chunks[1][0] * ((1 << 52) + (1 << 42) + (1 << 14));
                            static std::array<std::vector<typename CurveType::scalar_field_type::integral_type>, 2>
                                Sigma1_chunks = reversed_sparse_and_split(sparse_Sigma1, sigma_sizes, base7);
                            assignment.witness(W5)[i + 2] = Sigma1_chunks[0][0];
                            assignment.witness(W6)[i + 2] = Sigma1_chunks[0][1];
                            assignment.witness(W7)[i + 2] = Sigma1_chunks[0][2];
                            assignment.witness(W8)[i + 2] = Sigma1_chunks[0][3];

                            assignment.witness(W5)[i + 1] = Sigma1_chunks[1][0];
                            assignment.witness(W6)[i + 1] = Sigma1_chunks[1][1];
                            assignment.witness(W7)[i + 1] = Sigma1_chunks[1][2];
                            assignment.witness(W8)[i + 1] = Sigma1_chunks[1][3];
                            typename CurveType::scalar_field_type::integral_type Sigma1 =
                                Sigma1_chunks[0][0] + Sigma1_chunks[0][1] * (1 << (sigma_sizes[0])) +
                                Sigma1_chunks[0][2] * (1 << (sigma_sizes[0] + sigma_sizes[1])) +
                                Sigma1_chunks[0][3] * (1 << (sigma_sizes[0] + sigma_sizes[1] + sigma_sizes[2]));

                            typename CurveType::scalar_field_type::integral_type sparse_ch =
                                sparse_values[4] + 2 * sparse_values[5] + 3 * sparse_values[6];

                            static std::array<std::vector<typename CurveType::scalar_field_type::integral_type>, 2>
                                ch_chunks = reversed_sparse_and_split(sparse_ch, ch_and_maj_sizes, base7);
                            assignment.witness(W5)[i + 3] = ch_chunks[0][0];
                            assignment.witness(W6)[i + 3] = ch_chunks[0][1];
                            assignment.witness(W7)[i + 3] = ch_chunks[0][2];
                            assignment.witness(W8)[i + 3] = ch_chunks[0][3];

                            assignment.witness(W0)[i + 2] = ch_chunks[1][0];
                            assignment.witness(W1)[i + 2] = ch_chunks[1][1];
                            assignment.witness(W2)[i + 2] = ch_chunks[1][2];
                            assignment.witness(W3)[i + 2] = ch_chunks[1][3];

                            assignment.witness(W0)[i + 3] = sparse_values[6];
                            assignment.witness(W1)[i + 3] = d;
                            assignment.witness(W2)[i + 3] = h;
                            assignment.witness(W3)[i + 3] = message_scheduling_words[(i - row) / 8];
                            typename CurveType::scalar_field_type::integral_type ch =
                                ch_chunks[0][0] + ch_chunks[0][1] * (1 << 8) + ch_chunks[0][2] * (1 << 16) +
                                ch_chunks[0][3] * (1 << 24);

                            auto e_new = d + h + Sigma1 + ch + round_constant[(i - row) / 8] +
                                         message_scheduling_words[(i - row) / 8];
                            assignment.witness(W4)[i + 3] = e_new;

                            assignment.witness(W0)[i + 7] = a;
                            std::vector<bool> a_bits(32);
                            typename CurveType::scalar_field_type::integral_type integral_a =
                                typename CurveType::scalar_field_type::integral_type(e.data);
                            for (std::size_t i = 0; i < 32; i++) {
                                a_bits[32 - i - 1] = multiprecision::bit_test(integral_a, i);
                            }
                            std::vector<std::size_t> a_sizes = {2, 11, 9, 10};
                            std::array<std::vector<std::size_t>, 2> a_chunks = split_and_sparse(a_bits, a_sizes, base4);
                            assignment.witness(W2)[i + 7] = a_chunks[0][0];
                            assignment.witness(W3)[i + 7] = a_chunks[0][1];
                            assignment.witness(W4)[i + 7] = a_chunks[0][2];
                            assignment.witness(W5)[i + 7] = a_chunks[0][3];

                            assignment.witness(W2)[i + 6] = a_chunks[1][0];
                            assignment.witness(W3)[i + 6] = a_chunks[1][1];
                            assignment.witness(W4)[i + 6] = a_chunks[1][2];
                            assignment.witness(W5)[i + 6] = a_chunks[1][3];

                            sparse_values[0] = a_chunks[1][0] + a_chunks[1][1] * pow(4, a_sizes[0]) +
                                               a_chunks[1][2] * pow(4, a_sizes[0] + a_sizes[1]) +
                                               a_chunks[1][3] * pow(4, a_sizes[0] + a_sizes[1] + a_sizes[2]);
                            assignment.witness(W0)[i + 5] = sparse_values[0];
                            assignment.witness(W1)[i + 5] = sparse_values[1];
                            typename CurveType::scalar_field_type::integral_type sparse_Sigma0 =
                                (a_chunks[1][0] * ((1 << 38) + (1 << 20) + (1 << 60)) +
                                 a_chunks[1][1] * ((1 << 42) + 1 + (1 << 24)) +
                                 a_chunks[1][2] * ((1 << 22) + (1 << 46) + 1) +
                                 a_chunks[1][3] * ((1 << 40) + (1 << 18) + 1));
                            static std::array<std::vector<typename CurveType::scalar_field_type::integral_type>, 2>
                                Sigma0_chunks = reversed_sparse_and_split(sparse_Sigma0, sigma_sizes, base4);
                            assignment.witness(W5)[i + 5] = Sigma0_chunks[0][0];
                            assignment.witness(W6)[i + 5] = Sigma0_chunks[0][1];
                            assignment.witness(W7)[i + 5] = Sigma0_chunks[0][2];
                            assignment.witness(W8)[i + 5] = Sigma0_chunks[0][3];

                            assignment.witness(W0)[i + 6] = Sigma0_chunks[1][0];
                            assignment.witness(W1)[i + 6] = Sigma0_chunks[1][1];
                            assignment.witness(W6)[i + 6] = Sigma0_chunks[1][2];
                            assignment.witness(W7)[i + 6] = Sigma0_chunks[1][3];

                            typename CurveType::scalar_field_type::integral_type Sigma0 =
                                Sigma0_chunks[0][0] + Sigma0_chunks[0][1] * (1 << sigma_sizes[0]) +
                                Sigma0_chunks[0][2] * (1 << (sigma_sizes[0] + sigma_sizes[1])) +
                                Sigma0_chunks[0][3] * (1 << (sigma_sizes[0] + sigma_sizes[1] + sigma_sizes[2]));

                            typename CurveType::scalar_field_type::integral_type sparse_maj =
                                sparse_values[0] + sparse_values[1] + sparse_values[2];
                            static std::array<std::vector<typename CurveType::scalar_field_type::integral_type>, 2>
                                maj_chunks = reversed_sparse_and_split(sparse_maj, ch_and_maj_sizes, base4);
                            assignment.witness(W5)[i + 4] = maj_chunks[0][0];
                            assignment.witness(W6)[i + 4] = maj_chunks[0][1];
                            assignment.witness(W7)[i + 4] = maj_chunks[0][2];
                            assignment.witness(W8)[i + 4] = maj_chunks[0][3];

                            assignment.witness(W0)[i + 4] = maj_chunks[1][0];
                            assignment.witness(W1)[i + 4] = maj_chunks[1][1];
                            assignment.witness(W2)[i + 4] = maj_chunks[1][2];
                            assignment.witness(W3)[i + 4] = maj_chunks[1][3];
                            typename CurveType::scalar_field_type::integral_type maj =
                                maj_chunks[0][0] + maj_chunks[0][1] * (1 << 8) + maj_chunks[0][2] * (1 << 16) +
                                maj_chunks[0][3] * (1 << 24);
                            assignment.witness(W4)[i + 5] = sparse_values[2];
                            auto a_new = e - d + h + Sigma0 + maj;
                            assignment.witness(W4)[i + 4] = a_new;
                            h = g;
                            sparse_values[7] = sparse_values[6];
                            g = f;
                            sparse_values[6] = sparse_values[5];
                            f = e;
                            sparse_values[5] = sparse_values[4];
                            e = e_new;
                            d = c;
                            sparse_values[3] = sparse_values[2];
                            c = b;
                            sparse_values[2] = sparse_values[1];
                            b = a;
                            sparse_values[1] = sparse_values[0];
                            a = a_new;
                        }

                        /*std::vector<std::size_t> value_sizes = {14};
                        // lookup table for sparse values with base = 4
                        for(typename CurveType::scalar_field_type::integral_type i = 0; i < typename
                        CurveType::scalar_field_type::integral_type(16384); i++){ std::vector<bool> value(14); for
                        (std::size_t j = 0; j < 14; j++) { value[14 - j - 1] = multiprecision::bit_test(i, j);
                            }
                            std::array<std::vector<uint64_t>, 2> value_chunks = split_and_sparse(value, value_sizes,
                        base4); public_assignment.constant(0)[component_start_row + std::size_t(i)] =
                        value_chunks[0][0]; public_assignment.constant(1)[component_start_row + std::size_t(i)] =
                        value_chunks[1][0];
                        }
                        // lookup table for sparse values with base = 7
                        for(typename CurveType::scalar_field_type::integral_type i = 0; i < typename
                        CurveType::scalar_field_type::integral_type(16384); i++){ std::vector<bool> value(14); for
                        (std::size_t j = 0; j < 14; j++) { value[14 - j - 1] = multiprecision::bit_test(i, j);
                            }
                            std::array<std::vector<uint64_t>, 2> value_chunks = split_and_sparse(value, value_sizes,
                        base7); public_assignment.constant(2)[component_start_row + std::size_t(i)] =
                        value_chunks[0][0]; public_assignment.constant(3)[component_start_row + std::size_t(i)] =
                        value_chunks[1][0];
                        }
                        // lookup table for maj function
                        value_sizes = {8};
                        for(typename CurveType::scalar_field_type::integral_type i = 0; i < typename
                        CurveType::scalar_field_type::integral_type(65535); i++){ static std::array<std::vector<typename
                        CurveType::scalar_field_type::integral_type>, 2> value = reversed_sparse_and_split(i,
                        value_sizes, base4); public_assignment.constant(4)[component_start_row + std::size_t(i)] =
                        value[0][0]; public_assignment.constant(5)[component_start_row + std::size_t(i)] = i;
                        }

                        // lookup table for ch function
                        for(typename CurveType::scalar_field_type::integral_type i = 0; i < typename
                        CurveType::scalar_field_type::integral_type(5765041); i++){ static
                        std::array<std::vector<typename CurveType::scalar_field_type::integral_type>, 2> value =
                        reversed_sparse_and_split(i, value_sizes, base7);
                            public_assignment.constant(4)[component_start_row + std::size_t(i)] = value[0][0];
                            public_assignment.constant(5)[component_start_row + std::size_t(i)] = i;
                        }*/
                    }

                private:
                    static void generate_sigma0_gates(blueprint<ArithmetizationType> &bp,
                                                      blueprint_assignment_table<ArithmetizationType> &assignment,
                                                      allocated_data_type &allocated_data,
                                                      const std::size_t &start_row) {
                        std::size_t j = start_row;
                        std::size_t selector_index;
                        if (!allocated_data.previously_allocated) {
                            selector_index = assignment.add_selector(j, j + 237, 5);
                            allocated_data.selectors[2] = selector_index;
                        } else {
                            selector_index = allocated_data.selectors[2];
                            assignment.enable_selector(selector_index, j, j + 237, 5);
                        }
                        auto constraint_1 = bp.add_constraint(
                            var(W0, -1) -
                            (var(W1, -1) + var(W2, -1) * (1 << 1) + var(W3, -1) * (1 << 7) + var(W4, -1) * (1 << 8) +
                             var(W5, -1) * (1 << 22) + var(W6, -1) * (1 << 36) + var(W7, -1) * (1 << 50)));
                        auto constraint_2 = bp.add_constraint((var(W1, -1) - 1) * var(W1, -1));
                        auto constraint_3 = bp.add_constraint((var(W3, -1) - 1) * var(W3, -1));
                        auto constraint_4 = bp.add_constraint(
                            var(W1, 1) + var(W2, 1) * (1 << 28) + var(W3, 1) * (1 << 56) +
                            var(W4, 1) * (1 << 42) + var(W5, 1) * (1 << 112) -
                            (var(W2, 0) + var(W3, 0) * (1 << 12) + var(W4, 0) * (1 << 14) +
                             var(W5, 0) * (1 << 21) + var(W6, 0) * (1 << 70) + var(W7, 0) * (1 << 98) +
                             var(W1, 0) * (1 << 126) + var(W3, 0) + var(W4, 0) * 4 + var(W5, 0) * (1 << 30) +
                             var(W6, 0) * (1 << 29) + var(W7, 0) * (1 << 86) + var(W4, 0) + var(W5, 0) * (1 << 28) +
                             var(W6, 0) * (1 << 56) + var(W7, 0) * (1 << 42) + var(W1, 0) * (1 << 112) +
                             var(W2, 0) * (1 << 114) + var(W3, 0) * (1 << 126)));

                        if (!allocated_data.previously_allocated) {
                            bp.add_gate(selector_index, {constraint_1, constraint_2, constraint_3, constraint_4});
                        }
                        /*std::size_t selector_lookup_index = public_assignment.add_selector(j, j + 237, 5);
                        auto lookup_constraint_1 = bp.add_lookup_constraint({var(W1, - 1), var(W7, - 1)}, {{0, 0, false,
                        var::column_type::constant}, {1, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_2 = bp.add_lookup_constraint({var(W2, - 1)* 1024}, {{0, 0, false,
                        var::column_type::constant}}); auto lookup_constraint_3 = bp.add_lookup_constraint({var(W2, -
                        1), var(W2, 0)}, {{0, 0, false, var::column_type::constant}, {1, 0, false,
                        var::column_type::constant}}); auto lookup_constraint_4 = bp.add_lookup_constraint({var(W3, - 1)
                        * 8}, {{0, 0, false, var::column_type::constant}}); auto lookup_constraint_5 =
                        bp.add_lookup_constraint({var(W3, - 1), var(W3, 0)}, {{0, 0, false, var::column_type::constant},
                        {1, 0, false, var::column_type::constant}}); auto lookup_constraint_6 =
                        bp.add_lookup_constraint({var(W4, - 1), var(W4, 0)}, {{0, 0, false, var::column_type::constant},
                        {1, 0, false, var::column_type::constant}}); auto lookup_constraint_7 =
                        bp.add_lookup_constraint({var(W1, + 1), var(W5, 0)}, {{0, 0, false, var::column_type::constant},
                        {1, 0, false, var::column_type::constant}}); auto lookup_constraint_8 =
                        bp.add_lookup_constraint({var(W2, + 1), var(W6, 0)}, {{0, 0, false, var::column_type::constant},
                        {1, 0, false, var::column_type::constant}}); auto lookup_constraint_9 =
                        bp.add_lookup_constraint({var(W3, + 1), var(W7, + 1)}, {{0, 0, false,
                        var::column_type::constant}, {1, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_10 = bp.add_lookup_constraint({var(W4, + 1), var(W8, + 1)}, {{0, 0, false,
                        var::column_type::constant}, {1, 0, false, var::column_type::constant}});
                        bp.add_lookup_gate(selector_lookup_index,
                            {lookup_constraint_1, lookup_constraint_2, lookup_constraint_3,
                                          lookup_constraint_4, lookup_constraint_5, lookup_constraint_6,
                                          lookup_constraint_7, lookup_constraint_8,
                                          lookup_constraint_9, lookup_constraint_10});*/
                    }
                    static void generate_sigma1_gates(blueprint<ArithmetizationType> &bp,
                                                      blueprint_assignment_table<ArithmetizationType> &assignment,
                                                      allocated_data_type &allocated_data,
                                                      const std::size_t &start_row) {

                        std::size_t j = start_row;
                        std::size_t selector_index;
                        if (!allocated_data.previously_allocated) {
                            selector_index = assignment.add_selector(j, j + 239, 5);
                            allocated_data.selectors[0] = selector_index;
                        } else {
                            selector_index = allocated_data.selectors[0];
                            assignment.enable_selector(selector_index, j, j + 239, 5);
                        }
                        auto constraint_1 = bp.add_constraint(
                            var(W0, 1) - (var(W1, 1) + var(W2, 1) * (1 << 6) + var(W3, 1) * (1 << 19) +
                                          var(W4, 1) * (1 << 33) + var(W5, 1) * (1 << 47) + var(W6, 1) * (1 << 61)));
                        auto constraint_2 = bp.add_constraint((var(W6, 1) - 7) * (var(W6, 1) - 6) * (var(W6, 1) - 5) *
                                                              (var(W6, 1) - 4) * (var(W6, 1) - 3) * (var(W6, 1) - 2) *
                                                              (var(W6, 1) - 1) * var(W6, 1));
                        auto constraint_3 = bp.add_constraint(
                            var(W0, 0) + var(W7, 0) * (1 << 28) + var(W5, -1) * (1 << 56) + var(W6, -1) * (1 << 42) +
                            var(W7, -1) * (1 << 112) -
                            (var(W2, 0) + var(W3, 0) * (1 << 26) + var(W4, 0) * (1 << 54) + var(W5, 0) * (1 << 41) +
                             var(W6, 0) * (1 << 110) + var(W3, 0) + var(W4, 0) * (1 << 28) + var(W5, 0) * (1 << 56) +
                             var(W6, 0) * (1 << 42) + var(W1, 4) * (1 << 90) + var(W2, 0) * (1 << 102) + var(W6, 0) +
                             var(W1, 0) * (1 << 6) + var(W2, 0) * (1 << 18) + var(W3, 0) * (1 << 22) +
                             var(W4, 0) * (1 << 72) + var(W5, 0) * (1 << 100)));

                        if (!allocated_data.previously_allocated) {
                            bp.add_gate(selector_index, {constraint_1, constraint_2, constraint_3});
                        }
                        /*std::size_t selector_lookup_index = public_assignment.add_selector(j);
                        auto lookup_constraint_1 = bp.add_lookup_constraint({var(W1, +1)* 16}, {{0, 0, false,
                        var::column_type::constant}}); auto lookup_constraint_2 = bp.add_lookup_constraint({var(W1, +1),
                        var(W1, 0)}, {{0, 0, false, var::column_type::constant}, {1, 0, false,
                        var::column_type::constant}}); auto lookup_constraint_3 = bp.add_lookup_constraint({var(W2, +1)*
                        128}, {{0, 0, false, var::column_type::constant}}); auto lookup_constraint_4 =
                        bp.add_lookup_constraint({var(W2, + 1), var(W2, 0)}, {{0, 0, false, var::column_type::constant},
                        {1, 0, false, var::column_type::constant}}); auto lookup_constraint_5 =
                        bp.add_lookup_constraint({var(W4, +1) * 2}, {{0, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_6 = bp.add_lookup_constraint({var(W3, + 1), var(W3, 0)}, {{0, 0, false,
                        var::column_type::constant}, {1, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_7 = bp.add_lookup_constraint({var(W4, + 1), var(W4, 0)}, {{0, 0, false,
                        var::column_type::constant}, {1, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_8 = bp.add_lookup_constraint ({var(W5, - 1), var(W5, 0)}, {{0, 0, false,
                        var::column_type::constant}, {1, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_9 = bp.add_lookup_constraint({var(W6, - 1), var(W6, 0)}, {{0, 0, false,
                        var::column_type::constant}, {1, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_10 = bp.add_lookup_constraint({var(W7, - 1), var(W7, 0)}, {{0, 0, false,
                        var::column_type::constant}, {1, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_11 = bp.add_lookup_constraint({var(W8, - 1), var(W8, 0)}, {{0, 0, false,
                        var::column_type::constant}, {1, 0, false, var::column_type::constant}});
                        bp.add_lookup_gate(selector_lookup_index,
                            {lookup_constraint_1, lookup_constraint_2, lookup_constraint_3,
                                          lookup_constraint_4, lookup_constraint_5, lookup_constraint_6,
                                          lookup_constraint_7, lookup_constraint_8,
                                          lookup_constraint_9, lookup_constraint_10, lookup_constraint_11});*/
                    }

                    static void
                        generate_message_scheduling_gates(blueprint<ArithmetizationType> &bp,
                                                          blueprint_assignment_table<ArithmetizationType> &assignment,
                                                          allocated_data_type &allocated_data,
                                                          const std::size_t &start_row) {
                        std::size_t j = start_row;
                        j++;
                        generate_sigma0_gates(bp, assignment, allocated_data, j);
                        j++;
                        std::size_t selector_index;
                        if (!allocated_data.previously_allocated) {
                            selector_index = assignment.add_selector(j, j + 237, 5);
                            allocated_data.selectors[1] = selector_index;
                        } else {
                            selector_index = allocated_data.selectors[1];
                            assignment.enable_selector(selector_index, j, j + 237, 5);
                        }
                        auto constraint_1 = bp.add_constraint(
                            var(W0, 0) - (var(W0, -1) + var(W1, -1) + var(W1, 0) + var(W2, 0) * (1 << 3) -
                                          var(W3, 0) * (1 << 7) + var(W4, 0) * (1 << 18) + var(W5, 0) +
                                          var(W6, 0) * (1 << 10) + var(W7, 0) * (1 << 17) + var(W8, 0) * (1 << 19)));
                        if (!allocated_data.previously_allocated) {
                            bp.add_gate(selector_index, {constraint_1});
                        }
                        j++;
                        generate_sigma0_gates(bp, assignment, allocated_data, j);
                    }

                    static void generate_Sigma0_gates(blueprint<ArithmetizationType> &bp,
                                                      blueprint_assignment_table<ArithmetizationType> &assignment,
                                                      allocated_data_type &allocated_data,
                                                      const std::size_t &start_row) {
                        std::size_t j = start_row;
                        std::size_t selector_index;
                        if (!allocated_data.previously_allocated) {
                            selector_index = assignment.add_selector(j, j + 505, 8);
                            allocated_data.selectors[70] = selector_index;
                        } else {
                            selector_index = allocated_data.selectors[70];
                            assignment.enable_selector(selector_index, j, j + 505, 8);
                        }
                        auto constraint_1 = bp.add_constraint(
                            var(W0, +1) - (var(W1, +1) + var(W2, 1) * (1 << 14) + var(W3, +1) * (1 << 28) +
                                           var(W4, +1) * (1 << 34) + var(W5, 1) * (1 << 39) + var(W6, 1) * (1 << 53)));

                        auto constraint_2 = bp.add_constraint(
                            var(W4, -1) * (1 << 13) + var(W5, -1) * (1 << 28) + var(W6, -1) * (1 << 56) +
                            var(W7, -1) * (1 << 42) + var(W8, -1) * (1 << 112) -
                            (var(W3, 0) + var(W4, 0) * (1 << 12) + var(W5, 0) * (1 << 22) + var(W6, 0) * (1 << 25) +
                             var(W1, 0) * (1 << 72) + var(W2, 0) * (1 << 100) + var(W4, 0) + var(W5, 0) * (1 << 10) +
                             var(W6, 0) * (1 << 38) + var(W1, 0) * (1 << 30) + var(W2, 0) * (1 << 88) +
                             var(W3, 0) * (1 << 116) + var(W5, 0) + var(W6, 0) * (1 << 28) + var(W1, 0) * (1 << 50) +
                             var(W2, 0) * (1 << 39) + var(W3, 0) * (1 << 106) + var(W4, 0) * (1 << 108)));

                        if (!allocated_data.previously_allocated) {
                            bp.add_gate(selector_index, {constraint_1, constraint_2});
                        }
                        /*std::size_t selector_lookup_index = public_assignment.add_selector(j);
                        auto lookup_constraint_1 = bp.add_lookup_constraint({var(W3, +1)* 8}, {{0, 0, false,
                        var::column_type::constant}}); auto lookup_constraint_2 = bp.add_lookup_constraint({var(W2, +1),
                        var(W2, 0)}, {{0, 0, false, var::column_type::constant}, {1, 0, false,
                        var::column_type::constant}}); auto lookup_constraint_3 = bp.add_lookup_constraint({var(W4, +1)*
                        32}, {{0, 0, false, var::column_type::constant}}); auto lookup_constraint_4 =
                        bp.add_lookup_constraint({var(W3, +1), var(W3, 0)}, {{0, 0, false, var::column_type::constant},
                        {1, 0, false, var::column_type::constant}}); auto lookup_constraint_5 =
                        bp.add_lookup_constraint({var(W5, +1) * 16}, {{0, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_6 = bp.add_lookup_constraint({var(W4, +1), var(W4, 0)}, {{0, 0, false,
                        var::column_type::constant}, {1, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_7 = bp.add_lookup_constraint({var(W5, +1), var(W5, 0)}, {{0, 0, false,
                        var::column_type::constant}, {1, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_8 = bp.add_lookup_constraint({var(W5, - 1), var(W0, 0)}, {{0, 0, false,
                        var::column_type::constant}, {1, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_9 = bp.add_lookup_constraint({var(W6, - 1), var(W1, 0)}, {{0, 0, false,
                        var::column_type::constant}, {1, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_10 = bp.add_lookup_constraint({var(W7, - 1), var(W6, 0)}, {{0, 0, false,
                        var::column_type::constant}, {1, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_11 = bp.add_lookup_constraint({var(W8, - 1), var(W7, 0)}, {{0, 0, false,
                        var::column_type::constant}, {1, 0, false, var::column_type::constant}});
                        bp.add_lookup_gate(selector_lookup_index,
                            {lookup_constraint_1, lookup_constraint_2, lookup_constraint_3,
                                          lookup_constraint_4, lookup_constraint_5, lookup_constraint_6,
                                          lookup_constraint_7, lookup_constraint_8,
                                          lookup_constraint_9, lookup_constraint_10, lookup_constraint_11});*/
                    }

                    static void generate_Sigma1_gates(blueprint<ArithmetizationType> &bp,
                                                      blueprint_assignment_table<ArithmetizationType> &assignment,
                                                      allocated_data_type &allocated_data,
                                                      const std::size_t &start_row) {
                        std::size_t j = start_row;
                        std::size_t selector_index;
                        if (!allocated_data.previously_allocated) {
                            selector_index = assignment.add_selector(j, j + 510, 8);
                            allocated_data.selectors[3] = selector_index;
                        } else {
                            selector_index = allocated_data.selectors[3];
                            assignment.enable_selector(selector_index, j, j + 510, 8);
                        }
                        auto constraint_1 =
                            bp.add_constraint(var(W0, -1) - (var(W1, -1) + var(W2, -1) * (1 << 14) +
                                                             var(W3, -1) * (1 << 18) + var(W4, -1) * (1 << 32) +
                                                             var(W5, -1) * (1 << 41) + var(W6, -1) * (1 << 55)));
                        auto constraint_2 = bp.add_constraint(
                            var(W4, 1) + var(W5, 1) * (1 << 28) + var(W6, 1) * (1 << 56) + var(W7, 1) * (1 << 42) +
                            var(W8, 1) * (1 << 112) -
                            (var(W2, 0) + var(W3, 0) * (1 << 8) + var(W4, 0) * (1 << 36) + var(W5, 0) * (1 << 27) +
                             var(W6, 0) * (1 << 82) + var(W1, 0) * (1 << 100) + var(W3, 0) + var(W4, 0) * (1 << 28) +
                             var(W5, 0) * (1 << 46) + var(W6, 0) * (1 << 37) + var(W1, 0) * (1 << 92) +
                             var(W3, 0) * (1 << 120) + var(W5, 0) + var(W6, 0) * (1 << 28) + var(W1, 0) * (1 << 46) +
                             var(W2, 0) * (1 << 37) + var(W3, 0) * (1 << 82) + var(W4, 0) * (1 << 110)));

                        if (!allocated_data.previously_allocated) {
                            bp.add_gate(selector_index, {constraint_1, constraint_2});
                        }
                        /*std::size_t selector_lookup_index = public_assignment.add_selector(j);
                        auto lookup_constraint_1 = bp.add_lookup_constraint({var(W3, -1)* 256}, {{2, 0, false,
                        var::column_type::constant}}); auto lookup_constraint_2 = bp.add_lookup_constraint({var(W2, -1),
                        var(W1, -1)}, {{2, 0, false, var::column_type::constant}, {3, 0, false,
                        var::column_type::constant}}); auto lookup_constraint_3 = bp.add_lookup_constraint({var(W4, -1)*
                        512}, {{2, 0, false, var::column_type::constant}}); auto lookup_constraint_4 =
                        bp.add_lookup_constraint({var(W3, -1), var(W2, 0)}, {{2, 0, false, var::column_type::constant},
                        {3, 0, false, var::column_type::constant}}); auto lookup_constraint_5 =
                        bp.add_lookup_constraint({var(W5, -1) * 128}, {{2, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_6 = bp.add_lookup_constraint({var(W4, -1), var(W3, 0)}, {{2, 0, false,
                        var::column_type::constant}, {3, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_7 = bp.add_lookup_constraint({var(W5, -1), var(W4, 0)}, {{2, 0, false,
                        var::column_type::constant}, {3, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_8 = bp.add_lookup_constraint({var(W5, + 1), var(W5, 0)}, {{2, 0, false,
                        var::column_type::constant}, {3, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_9 = bp.add_lookup_constraint({var(W6, + 1), var(W6, 0)}, {{2, 0, false,
                        var::column_type::constant}, {3, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_10 = bp.add_lookup_constraint({var(W7, + 1), var(W7, 0)}, {{2, 0, false,
                        var::column_type::constant}, {3, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_11 = bp.add_lookup_constraint({var(W8, + 1), var(W8, 0)}, {{2, 0, false,
                        var::column_type::constant}, {3, 0, false, var::column_type::constant}});
                        bp.add_lookup_gate(selector_lookup_index,
                            {lookup_constraint_1, lookup_constraint_2, lookup_constraint_3,
                                          lookup_constraint_4, lookup_constraint_5, lookup_constraint_6,
                                          lookup_constraint_7, lookup_constraint_8,
                                          lookup_constraint_9, lookup_constraint_10, lookup_constraint_11});*/
                    }

                    static void generate_Maj_gates(blueprint<ArithmetizationType> &bp,
                                                   blueprint_assignment_table<ArithmetizationType> &assignment,
                                                   allocated_data_type &allocated_data,
                                                   const std::size_t &start_row) {
                        std::size_t j = start_row;
                        std::size_t selector_index;
                        if (!allocated_data.previously_allocated) {
                            selector_index = assignment.add_selector(j, j + 507, 8);
                            allocated_data.selectors[69] = selector_index;
                        } else {
                            selector_index = allocated_data.selectors[69];
                            assignment.enable_selector(selector_index, j, j + 507, 8);
                        }
                        auto constraint_1 =
                            bp.add_constraint(var(W0, 0) + var(W1, 0) * (1 << 32) + var(W2, 0) * (1 << 64) +
                                              var(W3, 0) * (1 << 96) - (var(W0, +1) + var(W1, +1) + var(W0, -1)));
                        if (!allocated_data.previously_allocated) {
                            bp.add_gate(selector_index, {constraint_1});
                        }
                        /*std::size_t selector_lookup_index = public_assignment.add_selector(j);
                        auto lookup_constraint_1 = bp.add_lookup_constraint({var(W5, 0), var(W0, 0)}, {{4, 0, false,
                        var::column_type::constant}, {5, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_2 = bp.add_lookup_constraint({var(W6, 0), var(W1, 0)}, {{4, 0, false,
                        var::column_type::constant}, {5, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_3 = bp.add_lookup_constraint({var(W7, 0), var(W2, 0)}, {{4, 0, false,
                        var::column_type::constant}, {5, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_4 = bp.add_lookup_constraint({var(W8, 0), var(W3, 0)}, {{4, 0, false,
                        var::column_type::constant}, {5, 0, false, var::column_type::constant}});
                        bp.add_lookup_gate(selector_lookup_index,
                            {lookup_constraint_1, lookup_constraint_2, lookup_constraint_3,
                                          lookup_constraint_4});*/
                    }

                    static void generate_Ch_gates(blueprint<ArithmetizationType> &bp,
                                                  blueprint_assignment_table<ArithmetizationType> &assignment,
                                                  allocated_data_type &allocated_data,
                                                  const std::size_t &start_row) {
                        std::size_t j = start_row;
                        std::size_t selector_index;
                        if (!allocated_data.previously_allocated) {
                            selector_index = assignment.add_selector(j, j + 509, 8);
                            allocated_data.selectors[4] = selector_index;
                        } else {
                            selector_index = allocated_data.selectors[4];
                            assignment.enable_selector(selector_index, j, j + 509, 8);
                        }
                        typename ArithmetizationType::field_type::value_type base7_value = base7;
                        auto constraint_1 = bp.add_constraint(
                            var(W0, 0) + var(W1, 0) * base7_value.pow(16) + var(W2, 0) * base7_value.pow(32) +
                            var(W3, 0) * base7_value.pow(48) - (var(W0, -1) + 2 * var(W1, -1) + 3 * var(W1, +1)));
                        if (!allocated_data.previously_allocated) {
                            bp.add_gate(selector_index, {constraint_1});
                        }
                        /*std::size_t selector_lookup_index = public_assignment.add_selector(j);
                        auto lookup_constraint_1 = bp.add_lookup_constraint({var(W5, +1), var(W0, 0)}, {{6, 0, false,
                        var::column_type::constant}, {7, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_2 = bp.add_lookup_constraint({var(W6, +1), var(W1, 0)}, {{6, 0, false,
                        var::column_type::constant}, {7, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_3 = bp.add_lookup_constraint({var(W7, +1), var(W2, 0)}, {{6, 0, false,
                        var::column_type::constant}, {7, 0, false, var::column_type::constant}}); auto
                        lookup_constraint_4 = bp.add_lookup_constraint({var(W8, +1), var(W3, 0)}, {{6, 0, false,
                        var::column_type::constant}, {7, 0, false, var::column_type::constant}});
                        bp.add_lookup_gate(selector_lookup_index,
                            {lookup_constraint_1, lookup_constraint_2, lookup_constraint_3,
                                          lookup_constraint_4});*/
                    }

                    static void generate_compression_gates(blueprint<ArithmetizationType> &bp,
                                                           blueprint_assignment_table<ArithmetizationType> &assignment,
                                                           allocated_data_type &allocated_data,
                                                           const std::size_t &start_row) {
                        std::size_t j = start_row;
                        j++;
                        generate_Sigma1_gates(bp, assignment, allocated_data, j);
                        j++;
                        generate_Ch_gates(bp, assignment, allocated_data, j);
                        j++;
                        std::size_t selector_index;
                        for (std::size_t i = j; i < 508; i = i + 8) {
                            if (!allocated_data.previously_allocated) {
                                selector_index = assignment.add_selector(i);
                                allocated_data.selectors[5 + i - j] = selector_index;
                            } else {
                                selector_index = allocated_data.selectors[5 + i - j];
                                assignment.add_selector(selector_index, i);
                            }
                            auto constraint_1 = bp.add_constraint(
                                var(W4, 0) - (var(W1, 0) + var(W2, 0) + var(W5, -1) + var(W6, -1) * (1 << 14) -
                                              var(W7, -1) * (1 << 28) + var(W8, -1) * (1 << 30) + var(W5, 0) +
                                              var(W6, 0) * (1 << 8) + var(W7, 0) * (1 << 16) + var(W8, 0) * (1 << 24) +
                                              round_constant[(i - j) / 8] + var(W3, 0)));
                            if (!allocated_data.previously_allocated) {
                                bp.add_gate(selector_index, {constraint_1});
                            }
                        }
                        j++;
                        if (!allocated_data.previously_allocated) {
                            selector_index = assignment.add_selector(j, j + 507, 8);
                            allocated_data.selectors[68] = selector_index;
                        } else {
                            selector_index = allocated_data.selectors[68];
                            assignment.enable_selector(selector_index, j, j + 507, 8);
                        }
                        auto constraint_1 = bp.add_constraint(
                            var(W4, 0) - (var(W4, -1) + var(W1, -1) + var(W5, +1) + var(W6, +1) * (1 << 14) -
                                          var(W7, +1) * (1 << 28) + var(W8, +1) * (1 << 30) + var(W5, 0) +
                                          var(W6, 0) * (1 << 8) + var(W7, 0) * (1 << 16) + var(W8, 0) * (1 << 24)));
                        if (!allocated_data.previously_allocated) {
                            bp.add_gate(selector_index, {constraint_1});
                        }
                        generate_Maj_gates(bp, assignment, allocated_data, j);
                        j++;
                        j++;
                        generate_Sigma0_gates(bp, assignment, allocated_data, j);
                        j = j + 8 * 63 + 2;
                        std::size_t selector_out_index_1;
                        if (!allocated_data.previously_allocated) {
                            selector_out_index_1 = assignment.add_selector(j);
                            allocated_data.selectors[71] = selector_out_index_1;
                        } else {
                            selector_out_index_1 = allocated_data.selectors[71];
                            assignment.add_selector(selector_out_index_1, j);
                        }
                        auto constraint_out_1 = bp.add_constraint(var(W0, 0) - (var(W0, -1) + var(W0, +1)));
                        auto constraint_out_2 = bp.add_constraint(var(W1, 0) - (var(W1, -1) + var(W1, +1)));
                        auto constraint_out_3 = bp.add_constraint(var(W2, 0) - (var(W2, -1) + var(W2, +1)));
                        auto constraint_out_4 = bp.add_constraint(var(W3, 0) - (var(W3, -1) + var(W3, +1)));
                        auto constraint_out_5 = bp.add_constraint(var(W4, 0) - (var(W4, -1) + var(W4, +1)));
                        auto constraint_out_6 = bp.add_constraint(var(W5, 0) - (var(W5, -1) + var(W5, +1)));
                        if (!allocated_data.previously_allocated) {
                            bp.add_gate(selector_out_index_1,
                                        {constraint_out_1, constraint_out_2, constraint_out_3, constraint_out_4,
                                         constraint_out_5, constraint_out_6});
                        }
                        j++;
                        std::size_t selector_out_index_2;
                        if (!allocated_data.previously_allocated) {
                            selector_out_index_1 = assignment.add_selector(j);
                            allocated_data.selectors[72] = selector_out_index_1;
                        } else {
                            selector_out_index_2 = allocated_data.selectors[72];
                            assignment.add_selector(selector_out_index_1, j);
                        }
                        auto constraint_out_7 = bp.add_constraint(var(W0, +1) - (var(W2, +1) + var(W4, +1)));
                        auto constraint_out_8 = bp.add_constraint(var(W1, +1) - (var(W3, +1) + var(W5, +1)));
                        if (!allocated_data.previously_allocated) {
                            bp.add_gate(selector_out_index_2, {constraint_out_7, constraint_out_8});
                        }
                    }

                    static std::array<std::vector<uint64_t>, 2>
                        split_and_sparse(std::vector<bool> bits, std::vector<std::size_t> sizes, std::size_t base) {
                        std::size_t size = sizes.size();
                        std::array<std::vector<uint64_t>, 2> res = {std::vector<uint64_t>(size),
                                                                    std::vector<uint64_t>(size)};
                        return res;
                    }

                    static std::array<std::vector<typename CurveType::scalar_field_type::integral_type>, 2>
                        reversed_sparse_and_split(typename CurveType::scalar_field_type::integral_type sparse_value,
                                                  std::vector<std::size_t> sizes, std::size_t base) {
                        std::size_t size = sizes.size();
                        std::array<std::vector<typename CurveType::scalar_field_type::integral_type>, 2> res = {
                            std::vector<typename CurveType::scalar_field_type::integral_type>(size),
                            std::vector<typename CurveType::scalar_field_type::integral_type>(size)};

                        return res;
                    }

                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               allocated_data_type &allocated_data,
                                               const std::size_t &component_start_row) {
                        std::size_t j = component_start_row;
                        j = j + 3;
                        generate_message_scheduling_gates(bp, assignment, allocated_data, j);
                        j = j + 5 * 48;
                        generate_compression_gates(bp, assignment, allocated_data, j);
                    }

                    static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                          blueprint_assignment_table<ArithmetizationType> &assignment,
                                                          const params_type &params,
                                                          const std::size_t &component_start_row) {
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_SHA512_HPP
