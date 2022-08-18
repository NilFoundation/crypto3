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
#include <nil/crypto3/zk/components/hashes/sha256/plonk/sha512_process.hpp>
//#include <nil/crypto3/zk/components/hashes/sha256/plonk/decomposition.hpp>

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

                    using sha512_process_component = 
                        sha512_process<ArithmetizationType, CurveType, W0, W1, W2, W3, W4, W5, W6, W7, W8>;
 //                   using decomposition_component = 
 //                       decomposition<ArithmetizationType, BlueprintFieldType, W0, W1, W2, W3, W4, W5, W6, W7, W8>;

                public: 
//                    constexpr static const std::size_t rows_RAM_and_input_words = 16;
//
                    constexpr static const std::size_t rows_amount =
                        2 + 3 + sha512_process_component::rows_amount * 2 + 2;

                    struct var_ec_point {
                        std::array<var, 4> x;    
                        std::array<var, 4> y;    
                    };

                    struct params_type {
                        var_ec_point R;
                        var_ec_point A;
                        std::array<var, 4> M;
                    };

                    struct result_type {
                        std::array<var, 8> output_state;

                        result_type(const std::size_t &start_row_index) { 
                            output_state = {var(W0, start_row_index + rows_amount - 3, false),
                                                               var(W1, start_row_index + rows_amount - 3, false),
                                                               var(W2, start_row_index + rows_amount - 3, false),
                                                               var(W3, start_row_index + rows_amount - 3, false),
                                                               var(W0, start_row_index + rows_amount - 1, false),
                                                               var(W1, start_row_index + rows_amount - 1, false),
                                                               var(W2, start_row_index + rows_amount - 1, false),
                                                               var(W3, start_row_index + rows_amount - 1, false)};
                        }
                    };
                    static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type & params,
                        const std::size_t start_row_index) {

                        generate_gates(bp, assignment, start_row_index);  
                        generate_copy_constraints(bp, assignment, params, start_row_index); 
                        return result_type(start_row_index);

                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;

                        std::array<typename ArithmetizationType::field_type::integral_type, 20> RAM = {
                            typename ArithmetizationType::field_type::integral_type(assignment.var_value(params.R.x[0]).data),
                            typename ArithmetizationType::field_type::integral_type(assignment.var_value(params.R.x[1]).data),
                            typename ArithmetizationType::field_type::integral_type(assignment.var_value(params.R.x[2]).data),
                            typename ArithmetizationType::field_type::integral_type(assignment.var_value(params.R.x[3]).data),
                            typename ArithmetizationType::field_type::integral_type(assignment.var_value(params.R.y[0]).data),
                            typename ArithmetizationType::field_type::integral_type(assignment.var_value(params.R.y[1]).data),
                            typename ArithmetizationType::field_type::integral_type(assignment.var_value(params.R.y[2]).data),
                            typename ArithmetizationType::field_type::integral_type(assignment.var_value(params.R.y[3]).data),
                            typename ArithmetizationType::field_type::integral_type(assignment.var_value(params.A.x[0]).data),
                            typename ArithmetizationType::field_type::integral_type(assignment.var_value(params.A.x[1]).data),
                            typename ArithmetizationType::field_type::integral_type(assignment.var_value(params.A.x[2]).data),
                            typename ArithmetizationType::field_type::integral_type(assignment.var_value(params.A.x[3]).data),
                            typename ArithmetizationType::field_type::integral_type(assignment.var_value(params.A.y[0]).data),
                            typename ArithmetizationType::field_type::integral_type(assignment.var_value(params.A.y[1]).data),
                            typename ArithmetizationType::field_type::integral_type(assignment.var_value(params.A.y[2]).data),
                            typename ArithmetizationType::field_type::integral_type(assignment.var_value(params.A.y[3]).data),
                            typename ArithmetizationType::field_type::integral_type(assignment.var_value(params.M[0]).data),
                            typename ArithmetizationType::field_type::integral_type(assignment.var_value(params.M[1]).data),
                            typename ArithmetizationType::field_type::integral_type(assignment.var_value(params.M[2]).data),
                            typename ArithmetizationType::field_type::integral_type(assignment.var_value(params.M[3]).data)
                            };

                        for (std::size_t i = 0; i < 4; i++) {
                            assignment.witness(i)[row] = RAM[i];
                            assignment.witness(i+4)[row] = RAM[i+4];
                            assignment.witness(i)[row+1] = RAM[i+8];
                            assignment.witness(i+4)[row+1] = RAM[i+12];
                            assignment.witness(i)[row+2] = RAM[i+16];
                        } 

                        std::array<typename ArithmetizationType::field_type::integral_type, 16> input_words_values;
                        typename ArithmetizationType::field_type::integral_type integral_one = 1;
                        typename ArithmetizationType::field_type::integral_type mask = ((integral_one<<64) - 1);
                        input_words_values[0] = (RAM[0]) & mask;
                        input_words_values[1] = ((RAM[0] >> 64) + (RAM[1] << 2)) & mask;
                        input_words_values[2] = ((RAM[1] >> 62) + (RAM[2] << 4)) & mask;
                        input_words_values[3] = ((RAM[2] >> 60) + (RAM[3] << 6) + (RAM[4] << 63)) & mask;
                        input_words_values[4] = ((RAM[4] >> 1)) & mask;
                        input_words_values[5] = ((RAM[4] >> 65) + (RAM[5] << 1)) & mask;
                        input_words_values[6] = ((RAM[5] >> 63) + (RAM[6] << 3)) & mask;
                        input_words_values[7] = ((RAM[6] >> 61) + (RAM[7] << 5) + (RAM[8] << 62)) & mask;
                        input_words_values[8] = ((RAM[8] >> 2)) & mask;
                        input_words_values[9] = ((RAM[9])) & mask;
                        input_words_values[10] = ((RAM[9] >> 64) + (RAM[10] << 2)) & mask;
                        input_words_values[11] = ((RAM[10] >> 62) + (RAM[11] << 4) + (RAM[12] << 61)) & mask;
                        input_words_values[12] = ((RAM[12] >> 3) + (RAM[13] << 63)) & mask;
                        input_words_values[13] = ((RAM[13] >> 1)) & mask;
                        input_words_values[14] = ((RAM[13] >> 65) + (RAM[14] << 1)) & mask;
                        input_words_values[15] = ((RAM[14] >> 63) + (RAM[15] << 3) + (RAM[16] << 60)) & mask;                    

                        row = row + 3;
                        std::array<var, 16> input_words_vars;

                        for (std::size_t i = 0; i < 8; i++) {
                            assignment.witness(i)[row] = input_words_values[i];
                            assignment.witness(i)[row+1] = input_words_values[i+8];
                            input_words_vars[i] = var(i, row, false);
                            input_words_vars[i+8] = var(i, row+1, false);
                        }

                        row = row + 2;

                        std::array<typename ArithmetizationType::field_type::value_type, 8> constants = {
                            0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                            0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};
                        for (int i = 0; i < 8; i++) {
                            assignment.constant(0)[component_start_row + i] = constants[i]; 
                        }

                        std::array<var, 8> constants_var = {var(0, component_start_row, false, var::column_type::constant), 
                                                            var(0, component_start_row + 1, false, var::column_type::constant),
                                                            var(0, component_start_row + 2, false, var::column_type::constant),
                                                            var(0, component_start_row + 3, false, var::column_type::constant),
                                                            var(0, component_start_row + 4, false, var::column_type::constant),
                                                            var(0, component_start_row + 5, false, var::column_type::constant),
                                                            var(0, component_start_row + 6, false, var::column_type::constant),
                                                            var(0, component_start_row + 7, false, var::column_type::constant)};
                        typename sha512_process_component::params_type sha_params = {constants_var, input_words_vars};
                        auto sha_output = sha512_process_component::generate_assignments(assignment, sha_params, row).output_state;
                        row += sha512_process_component::rows_amount;

                        input_words_values[0] = ((RAM[16] >> 4) + (RAM[17] << 62)) & mask;
                        input_words_values[1] = ((RAM[17] >> 2)) & mask;
                        input_words_values[2] = ((RAM[18])) & mask;
                        input_words_values[3] = ((RAM[18] >> 64) + (RAM[19] << 2) + (integral_one << 60)) << 3;


                        for (std::size_t i = 4; i < 15; ++i) {
                            input_words_values[i] = 0;
                        }
                        input_words_values[15] = 1024 + 252;

                        for (std::size_t i = 0; i < 8; i++) {
                            assignment.witness(i)[row] = input_words_values[i];
                            assignment.witness(i)[row+1] = input_words_values[i+8];
                            input_words_vars[i] = var(i, row, false);
                            input_words_vars[i+8] = var(i, row+1, false);
                        }

                        row = row + 2;
                        sha_params = {sha_output, input_words_vars};



/*                        std::array<typename ArithmetizationType::field_type::value_type, 16> input_words2 = {
                            1 << 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 9};
                        for (int i = 0; i < 16; i++) {
                            assignment.constant(0)[component_start_row + 8 + i] = input_words2[i];
                        }
                        std::vector<var> input_words2_var = {var(0, row + 8, false, var::column_type::constant),
                                                             var(0, row + 9, false, var::column_type::constant),
                                                             var(0, row + 10, false, var::column_type::constant),
                                                             var(0, row + 11, false, var::column_type::constant),
                                                             var(0, row + 12, false, var::column_type::constant),
                                                             var(0, row + 13, false, var::column_type::constant),
                                                             var(0, row + 14, false, var::column_type::constant),
                                                             var(0, row + 15, false, var::column_type::constant),
                                                             var(0, row + 16, false, var::column_type::constant),
                                                             var(0, row + 17, false, var::column_type::constant),
                                                             var(0, row + 18, false, var::column_type::constant),
                                                             var(0, row + 19, false, var::column_type::constant),
                                                             var(0, row + 20, false, var::column_type::constant),
                                                             var(0, row + 21, false, var::column_type::constant),
                                                             var(0, row + 22, false, var::column_type::constant),
                                                             var(0, row + 23, false, var::column_type::constant)};
                        typename sha512_process_component::params_type sha_params2 = {sha_output.output_state,
                                                                                      input_words2_var}; */
                                                            
                        sha512_process_component::generate_assignments(assignment, sha_params, row);
                        return result_type(component_start_row);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        
                    }

                    static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                          blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                          const params_type &params,
                                                          const std::size_t &component_start_row) {
                        std::size_t j = component_start_row;
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_SHA512_HPP