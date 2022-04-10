//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the SHA256 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_SHA256_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_SHA256_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType,
                         typename CurveType,
                         std::size_t... WireIndexes>
                class sha256;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         typename CurveType,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4,
                         std::size_t W5,
                         std::size_t W6,
                         std::size_t W7,
                         std::size_t W8>
                class sha256<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                                       CurveType,
                                                       W0,
                                                       W1,
                                                       W2,
                                                       W3,
                                                       W4,
                                                       W5,
                                                       W6,
                                                       W7,
                                                       W8> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;
                    enum indices { m2 = 0, m1, cur, p1, p2 };
                public:

                    constexpr static const std::size_t required_rows_amount = 16384;

                    struct public_params_type { };

                    struct private_params_type {
                        std::array<typename ArithmetizationType::field_type::value_type, 8> input_state;
                        std::array<typename ArithmetizationType::field_type::value_type, 16> input_words;
                    };

                    static std::size_t allocate_rows (blueprint<ArithmetizationType> &bp){
                        return bp.allocate_rows(required_rows_amount);
                    }

                private:

                    static void generate_sigma0_gates(blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment, const std::size_t &start_row) {
                        std::size_t j = start_row;
                        std::size_t selector_index = public_assignment.add_selector(j, j + 237, 5);
                        auto constraint_1 = bp.add_constraint(var(W0, -1) - (var(W1, -1) + var(W2, -1) * (1<<3) + var(W3, -1) * (1<<7) +
                         var(W4, -1) * (1<<18)));
                        auto constraint_2 = bp.add_constraint((var(W1, -1) - 7) * (var(W1, -1)  - 6) * (var(W1, -1)  - 5)
                         * (var(W1, -1)  - 4) * (var(W1, -1)  - 3) * (var(W1, -1) - 2) * (var(W1, -1)  - 1) * var(W1, -1) );
                        auto constraint_3 = bp.add_constraint(var(W5, 0) + var(W6, 0) * (1<<28) + var(W7, 0) * (1<<56) + 
                        var(W8, 0) * (1<<60) - 
                            (var(W2, 0) * (1 + (1<<56) + (1<<54)) + var(W3, 0) * ((1<<8) + 1 + (1<<42)) 
                            + var(W4, 0)* ((1<<30) + (1<<22) + 1) + var(W7, -1)* ((1<<50) + (1<<28))));
                        auto constraint_4 = bp.add_constraint((var(W7, 0)- 3) * (var(W7, 0) - 2) * 
                        (var(W7, 0) - 1) * var(W7, 0));
                        auto constraint_5 = bp.add_constraint((var(W8, 0) - 3) * (var(W8, 0) - 2) *
                         (var(W8, 0) - 1) * var(W8, 0));
                        bp.add_gate(selector_index,
                            {constraint_1, constraint_2, constraint_3,
                                          constraint_4, constraint_5});
                        std::size_t selector_lookup_index = public_assignment.add_selector(j, j + 237, 5);
                        auto lookup_constraint_1 = bp.add_lookup_constraint({var(W1, - 1), var(W7, - 1)}, {{0, 0, false, var::column_type::constant}, {1, 0, false, var::column_type::constant}});
                        auto lookup_constraint_2 = bp.add_lookup_constraint({var(W2, - 1)* 1024}, {{0, 0, false, var::column_type::constant}});
                        auto lookup_constraint_3 = bp.add_lookup_constraint({var(W2, - 1), var(W2, 0)}, {{0, 0, false, var::column_type::constant}, {1, 0, false, var::column_type::constant}});
                        auto lookup_constraint_4 = bp.add_lookup_constraint({var(W3, - 1) * 8}, {{0, 0, false, var::column_type::constant}});
                        auto lookup_constraint_5 = bp.add_lookup_constraint({var(W3, - 1), var(W3, 0)}, {{0, 0, false, var::column_type::constant}, {1, 0, false, var::column_type::constant}});
                        auto lookup_constraint_6 = bp.add_lookup_constraint({var(W4, - 1), var(W4, 0)}, {{0, 0, false, var::column_type::constant}, {1, 0, false, var::column_type::constant}});
                        auto lookup_constraint_7 = bp.add_lookup_constraint({var(W1, + 1), var(W5, 0)}, {{0, 0, false, var::column_type::constant}, {1, 0, false, var::column_type::constant}});
                        auto lookup_constraint_8 = bp.add_lookup_constraint({var(W2, + 1), var(W6, 0)}, {{0, 0, false, var::column_type::constant}, {1, 0, false, var::column_type::constant}});
                        auto lookup_constraint_9 = bp.add_lookup_constraint({var(W3, + 1), var(W7, + 1)}, {{0, 0, false, var::column_type::constant}, {1, 0, false, var::column_type::constant}});
                        auto lookup_constraint_10 = bp.add_lookup_constraint({var(W4, + 1), var(W8, + 1)}, {{0, 0, false, var::column_type::constant}, {1, 0, false, var::column_type::constant}});
                        bp.add_lookup_gate(selector_lookup_index,
                            {lookup_constraint_1, lookup_constraint_2, lookup_constraint_3,
                                          lookup_constraint_4, lookup_constraint_5, lookup_constraint_6,
                                          lookup_constraint_7, lookup_constraint_8,
                                          lookup_constraint_9, lookup_constraint_10});
                    }
                    static void generate_sigma1_gates(blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment, const std::size_t &start_row) {

                        std::size_t j = start_row;
                        std::size_t selector_index = public_assignment.add_selector(j, j + 239, 5);
                        auto constraint_1 = bp.add_constraint(var(W0, 0) - (var(W1, 0) + var(W2, 0) * (1<<10) + var(W3, 0) * (1<<17) +
                         var(W4, 0) * (1<<19)));
                        auto constraint_2 = bp.add_constraint((var(W3, 0) - 3) * (var(W3, 0)  - 2) * (var(W3, 0)  - 1)
                         * var(W3, 0) );
                        auto constraint_3 = bp.add_constraint(var(W5, 0) + var(W6, 0) * (1<<28) + var(W7, 0) * (1<<56) + 
                        var(W8, 0) * (1<<60) - 
                            (var(W2, 0) * (1 + (1<<50) + (1<<46)) + var(W3, 0) * ((1<<14) + 1 + (1<<60)) 
                            + var(W4, 0)* ((1<<18) + (1<<4) + 1) + var(W1, 0)* ((1<<30) + (1<<26))));
                        auto constraint_4 = bp.add_constraint((var(W7, 0)- 3) * (var(W7, 0) - 2) * 
                        (var(W7, 0) - 1) * var(W7, 0));
                        auto constraint_5 = bp.add_constraint((var(W8, 0) - 3) * (var(W8, 0) - 2) *
                         (var(W8, 0) - 1) * var(W8, 0));
                        bp.add_gate(selector_index,
                            {constraint_1, constraint_2, constraint_3,
                                          constraint_4, constraint_5});
                        std::size_t selector_lookup_index = public_assignment.add_selector(j);
                        auto lookup_constraint_1 = bp.add_lookup_constraint({var(W1, +1)* 16}, {{0, 0, false, var::column_type::constant}});
                        auto lookup_constraint_2 = bp.add_lookup_constraint({var(W1, +1), var(W1, 0)}, {{0, 0, false, var::column_type::constant}, {1, 0, false, var::column_type::constant}});
                        auto lookup_constraint_3 = bp.add_lookup_constraint({var(W2, +1)* 128}, {{0, 0, false, var::column_type::constant}});
                        auto lookup_constraint_4 = bp.add_lookup_constraint({var(W2, + 1), var(W2, 0)}, {{0, 0, false, var::column_type::constant}, {1, 0, false, var::column_type::constant}});
                        auto lookup_constraint_5 = bp.add_lookup_constraint({var(W4, +1) * 2}, {{0, 0, false, var::column_type::constant}});
                        auto lookup_constraint_6 = bp.add_lookup_constraint({var(W3, + 1), var(W3, 0)}, {{0, 0, false, var::column_type::constant}, {1, 0, false, var::column_type::constant}});
                        auto lookup_constraint_7 = bp.add_lookup_constraint({var(W4, + 1), var(W4, 0)}, {{0, 0, false, var::column_type::constant}, {1, 0, false, var::column_type::constant}});
                        auto lookup_constraint_8 = bp.add_lookup_constraint({var(W5, - 1), var(W5, 0)}, {{0, 0, false, var::column_type::constant}, {1, 0, false, var::column_type::constant}});
                        auto lookup_constraint_9 = bp.add_lookup_constraint({var(W6, - 1), var(W6, 0)}, {{0, 0, false, var::column_type::constant}, {1, 0, false, var::column_type::constant}});
                        auto lookup_constraint_10 = bp.add_lookup_constraint({var(W7, - 1), var(W7, 0)}, {{0, 0, false, var::column_type::constant}, {1, 0, false, var::column_type::constant}});
                        auto lookup_constraint_11 = bp.add_lookup_constraint({var(W8, - 1), var(W8, 0)}, {{0, 0, false, var::column_type::constant}, {1, 0, false, var::column_type::constant}});
                        bp.add_lookup_gate(selector_lookup_index,
                            {lookup_constraint_1, lookup_constraint_2, lookup_constraint_3,
                                          lookup_constraint_4, lookup_constraint_5, lookup_constraint_6,
                                          lookup_constraint_7, lookup_constraint_8,
                                          lookup_constraint_9, lookup_constraint_10, lookup_constraint_11});
                    }

                    static void generate_message_scheduling_gates(blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment, const std::size_t &start_row) {
                        std::size_t j = start_row;
                        j++;
                        generate_sigma0_gates(bp, public_assignment, j);
                        j++;
                        std::size_t selector_index = public_assignment.add_selector(j, j + 237, 5);
                        auto constraint_1 = bp.add_constraint(var(W0, 0) - (var(W0, - 1) + var(W1, - 1) +  var(W1, 0) +
                        var(W2, 0) * (1<<3) - var(W3, 0)*(1<<7) + var(W4, 0)*(1<<18)+ var(W5, 0) + var(W6, 0)*(1<<10) + 
                        var(W7, 0)*(1<<17) + var(W8, 0)*(1<<19)));
                        bp.add_gate(selector_index,
                            {constraint_1});
                        j++;
                        generate_sigma0_gates(bp, public_assignment, j);
                    }

                    /*void generate_Sigma0_gates() {

                        this->bp.add_gate(j + 7, w[0][cur] - (w[2][cur] + w[3][cur] * 2**2 + w[4][cur] * 2**13 + w[5][cur] * 2**22));
                        this->bp.add_gate(j + 5, w[0][cur] - (w[2][p1] + w[3][p1] * 4**2 + w[4][p1] * 4**13 + w[5][p1] * 4**22));
                        this->bp.add_gate(j + 6, (w[2][cur] - 3) * (w[2][cur] - 2) * (w[2][cur] - 1) * w[2][cur]);
                        this->bp.add_gate(j + 6, w[0][cur] + w[1][cur] * 4**14 + w[6][cur] * 4**28 + w[7][cur] * 2**30 -
                            (w[3][cur] + w[4][cur] * 4**11 + w[5][cur] * 4**20 + w[1][cur] * 2**30 + w[4][cur] + 
                            w[5][cur] * 4**[9] + w[2][cur] * 4**19 + w[3][cur] * 4**21 + w[5][cur] + w[2][cur] * 4**10 + 
                            w[3][cur] * 4**12 + w[4][cur] * 4**23));
                        this->bp.add_gate(j + 6, (w[6][cur] - 3) * (w[6][cur] - 2) * (w[6][cur] - 1) * w[6][cur]);
                        this->bp.add_gate(j + 6, (w[7][cur] - 3) * (w[7][cur] - 2) * (w[7][cur] - 1) * w[7][cur]);
                    }

                    void generate_Sigma1_gates() {
                        this->bp.add_gate(j + 0, w[0][cur] - (w[2][cur] + w[3][cur] * 2**[6] + w[4][cur] * 2**[11] + w[5][cur] * 2**[25]));
                        this->bp.add_gate(j + 1, w[0][cur] - (w[1][m1] + w[2][cur] * 7**[6] + w[3][cur] * 7**[11] + w[4][cur] * 7**[25]));
                        this->bp.add_gate(j + 1, w[5][cur] + w[6][cur] * 4**[14] + w[7][cur] * 4**[28] + w[8][cur] * 2**[30] - 
                            (w[2][cur] + w[3][cur] * 4**[5] + w[4][cur] * 4**[19] + w[1][m1] * 2**[26] + w[3][cur] + 
                            w[4][cur] * 4**[14] + w[1][m1] * 4**[21] + w[2][cur] * 4**[27] + w[4][cur] + w[1][m1] * 4**[7] + 
                            w[2][cur] * 4**[13] + w[3][cur] * 4**[27]));
                        this->bp.add_gate(j + 1, (w[3][cur] - 3) * (w[3][cur] - 2) * (w[3][cur] - 1) * w[3][cur]);
                        this->bp.add_gate(j + 1, (w[4][cur] - 3) * (w[4][cur] - 2) * (w[4][cur] - 1) * w[4][cur]);
                    }

                    void generate_Maj_gates() {
                        this->bp.add_gate(j + 4, w[0][cur] + w[1][cur] * 4**8 + w[2][cur] * 4*(8 * 2) + w[3][cur] * 4*(8 * 3) - 
                            (w[0][p1] + w[1][p1] + w[4][p1]));
                    }

                    void generate_Ch_gates(){
                        this->bp.add_gate(j + 2, w[0][cur] + w[1][cur] * 7**8 + w[2][cur] * 7**(8 * 2) + w[3][cur] * 7**(8 * 3) - 
                            (w[0][m1] + 2 * w[1][m1] + 3 * w[0][p1]));
                    }*/

                    static std::array<std::vector<std::size_t>, 2> split_and_sparse(std::vector<bool> bits, std::vector<std::size_t> sizes) {
                        std::size_t size = sizes.size();
                        std::array<std::vector<std::size_t>, 2> res = {std::vector<std::size_t>(size), std::vector<std::size_t>(size)};
                        std::size_t k = 0;
                        for (std::size_t i = sizes.size(); i > - 1; i--) {
                            res[0][i] = bits[k];
                            res[1][i] = bits[k];
                            for(std::size_t j = 1; j < sizes[i] ; j++) {
                                res[0][i] = res[0][i] * 2 + bits[k + j];
                                res[1][i] = res[1][i] * 4 + bits[k + j];
                            }
                            k = k + sizes[i];
                        }
                    return res;
                    }

                    static std::array<std::array<std::size_t, 4>, 2> split_and_reversed_sparse(std::array<bool, 64> bits, std::array<std::size_t, 4> sizes) {
                        std::array<std::array<std::size_t, 4>, 2> res;
                        std::size_t k = 0;
                        for (std::size_t i = 3; i > - 1; i--) {
                            res[0][i] = bits[k];
                            res[1][i] = bits[k];
                            for(std::size_t j = 1; j < sizes[i]*2 ; j++) {
                                if (j % 2 != 1) {
                                    res[0][i] = res[0][i] * 2 + bits[k + j];
                                }
                                res[1][i] = res[1][i] * 2 + bits[k + j];
                            }
                            k = k + sizes[i]*2;
                        }
                    return res;
                    }

                public:

                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const public_params_type &init_params,
                        const std::size_t &component_start_row) {
                        std::size_t j = component_start_row;
                        generate_message_scheduling_gates(bp, public_assignment, j);
                    }

                    static void generate_copy_constraints(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const public_params_type &init_params,
                        const std::size_t &component_start_row) {

                    }

                    static void generate_assignments(
                        blueprint_private_assignment_table<ArithmetizationType>
                            &private_assignment,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const public_params_type &init_params,
                        const private_params_type &params,
                        const std::size_t &component_start_row) {
                        std::size_t row = component_start_row;
                        std::array<typename ArithmetizationType::field_type::value_type, 8> input_state = params.input_state;
                        std::array<typename ArithmetizationType::field_type::value_type, 64> message_scheduling_last_words; 
                        for (std::size_t i = 0; i< 16; i++) {
                            message_scheduling_last_words[i] = params.input_words[i];
                        }
                        for (std::size_t i = 0; i< 8; i++) {
                            private_assignment.witness(i)[row] = input_state[i];
                            private_assignment.witness(i)[row + 1] = message_scheduling_last_words[i];
                            private_assignment.witness(i)[row + 2] = message_scheduling_last_words[2*i];
                        }
                        row = row + 3;

                        for (std::size_t i = row; i < row + 240; i = i + 5) {
                            std::vector<bool> a(32);
                            typename CurveType::scalar_field_type::integral_type integral_a = typename CurveType::scalar_field_type::integral_type(message_scheduling_last_words[i/5 + 1].data);
                            private_assignment.witness(W0)[i]  = message_scheduling_last_words[i/5 + 1];
                            for (std::size_t i = 0; i < 32; i++) {
                                a[32 - i - 1] = multiprecision::bit_test(integral_a, i);
                            }
                            std::vector<std::size_t> a_sizes = {3, 4, 11, 14};
                            std::array<std::vector<std::size_t>, 2> a_chunks = split_and_sparse(a, a_sizes);
                            private_assignment.witness(W1)[i]  = a_chunks[0][0];
                            private_assignment.witness(W2)[i]  = a_chunks[0][1];
                            private_assignment.witness(W3)[i]  = a_chunks[0][2];
                            private_assignment.witness(W4)[i]  = a_chunks[0][3];
                            private_assignment.witness(W7)[i]  = a_chunks[1][0];
                            private_assignment.witness(W0)[i + 1]  = message_scheduling_last_words[i/5 + 9];
                            private_assignment.witness(W1)[i + 1]  = message_scheduling_last_words[i/5];
                            private_assignment.witness(W2)[i + 1]  = a_chunks[1][1];
                            private_assignment.witness(W3)[i + 1]  = a_chunks[1][2];
                            private_assignment.witness(W4)[i + 1]  = a_chunks[1][3];
                            typename ArithmetizationType::field_type::value_type sparse_sigma0 = a_chunks[1][1] * (1 + (1<<56) + (1<<54)) 
                            + a_chunks[1][2] * ((1<<8) + 1 + (1<<42)) 
                            + a_chunks[1][3]* ((1<<30) + (1<<22) + 1) + a_chunks[1][0]* ((1<<50) + (1<<28));
                            std::array<bool, 64> sparse_sigma0_b = {false};
                            typename CurveType::scalar_field_type::integral_type integral_sparse_sigma0 = typename CurveType::scalar_field_type::integral_type(sparse_sigma0.data);
                            for (std::size_t i = 0; i < 64; i++) {
                                sparse_sigma0_b[64 - i - 1] = multiprecision::bit_test(integral_sparse_sigma0, i);
                            }
                            std::array<std::size_t, 4> sigma0_sizes = {14, 14, 2, 2};
                            std::array<std::array<std::size_t, 4>, 2> sigma0_chunks = split_and_reversed_sparse(sparse_sigma0_b, sigma0_sizes);
                            private_assignment.witness(W5)[i + 1]  = sigma0_chunks[1][0];
                            private_assignment.witness(W6)[i + 1]  = sigma0_chunks[1][1];
                            private_assignment.witness(W7)[i + 1]  = sigma0_chunks[1][2];
                            private_assignment.witness(W8)[i + 1]  = sigma0_chunks[1][3];

                            private_assignment.witness(W1)[i + 2]  = sigma0_chunks[0][0];
                            private_assignment.witness(W2)[i + 2]  = sigma0_chunks[0][1];
                            private_assignment.witness(W3)[i + 2]  = sigma0_chunks[0][2];
                            private_assignment.witness(W4)[i + 2]  = sigma0_chunks[0][3];

                            std::vector<bool> b(32);
                            typename CurveType::scalar_field_type::integral_type integral_b = typename CurveType::scalar_field_type::integral_type(message_scheduling_last_words[i/5 + 14].data);
                            for (std::size_t i = 0; i < 32; i++) {
                                b[32 - i - 1] = multiprecision::bit_test(integral_b, i);
                            }
                            std::vector<std::size_t> b_sizes = {10, 7, 2, 13};
                            std::array<std::vector<std::size_t>, 2> b_chunks = split_and_sparse(b, b_sizes);
                            private_assignment.witness(W0)[i + 4]  = message_scheduling_last_words[i/5 + 14];
                            private_assignment.witness(W1)[i + 4]  = b_chunks[0][0];
                            private_assignment.witness(W2)[i + 4]  = b_chunks[0][1];
                            private_assignment.witness(W3)[i + 4]  = b_chunks[0][2];
                            private_assignment.witness(W4)[i + 4]  = b_chunks[0][3];

                            private_assignment.witness(W1)[i + 3]  = b_chunks[1][0];
                            private_assignment.witness(W2)[i + 3]  = b_chunks[1][1];
                            private_assignment.witness(W3)[i + 3]  = b_chunks[1][2];
                            private_assignment.witness(W4)[i + 3]  = b_chunks[1][3];

                            typename ArithmetizationType::field_type::value_type sparse_sigma1 = b_chunks[1][1] * (1 + (1<<50) + (1<<46)) 
                            + b_chunks[1][2] * ((1<<14) + 1 + (1<<60)) 
                            + b_chunks[1][3]* ((1<<18) + (1<<4) + 1) + b_chunks[1][0]* ((1<<30) + (1<<26));
                            std::array<bool, 64> sparse_sigma1_b = {false};
                            typename CurveType::scalar_field_type::integral_type integral_sparse_sigma1 = typename CurveType::scalar_field_type::integral_type(sparse_sigma0.data);
                            for (std::size_t i = 0; i < 64; i++) {
                                sparse_sigma1_b[64 - i - 1] = multiprecision::bit_test(integral_sparse_sigma1, i);
                            }
                            std::array<std::size_t, 4> sigma1_sizes = {14, 14, 2, 2};
                            std::array<std::array<std::size_t, 4>, 2> sigma1_chunks = split_and_reversed_sparse(sparse_sigma1_b, sigma1_sizes);
                            private_assignment.witness(W5)[i + 3]  = sigma1_chunks[1][0];
                            private_assignment.witness(W6)[i + 3]  = sigma1_chunks[1][1];
                            private_assignment.witness(W7)[i + 3]  = sigma1_chunks[1][2];
                            private_assignment.witness(W8)[i + 3]  = sigma1_chunks[1][3];

                            private_assignment.witness(W5)[i + 2]  = sigma1_chunks[0][0];
                            private_assignment.witness(W6)[i + 2]  = sigma1_chunks[0][1];
                            private_assignment.witness(W7)[i + 2]  = sigma1_chunks[0][2];
                            private_assignment.witness(W8)[i + 2]  = sigma1_chunks[0][3];
                            message_scheduling_last_words[i/5 + 16] = message_scheduling_last_words[i/5 + 14] 
                            + message_scheduling_last_words[i/5] + sigma1_chunks[0][0] + sigma0_chunks[0][0] + (1<<14) * (sigma1_chunks[0][1] 
                            + sigma0_chunks[0][1]) + (1<<28) * (sigma1_chunks[0][2] + sigma0_chunks[0][2]) + (1<<30) * (sigma1_chunks[0][3] + sigma0_chunks[0][3]);
                            private_assignment.witness(W0)[i + 2]  = message_scheduling_last_words[i/5 + 16];

                        }

                        // lookup table
                        for(typename CurveType::scalar_field_type::integral_type i = 0; i < typename CurveType::scalar_field_type::integral_type(16384); i++){
                            std::vector<bool> value(14);
                            for (std::size_t j = 0; j < 14; j++) {
                                value[14 - j - 1] = multiprecision::bit_test(i, j);
                            }
                            std::vector<std::size_t> value_sizes = {14};
                            std::array<std::vector<std::size_t>, 2> value_chunks = split_and_sparse(value, value_sizes);
                            public_assignment.constant(0)[component_start_row + std::size_t(i)] = value_chunks[0][0];
                            public_assignment.constant(1)[component_start_row + std::size_t(i)] = value_chunks[1][0];
                        }

                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_SHA256_HPP
