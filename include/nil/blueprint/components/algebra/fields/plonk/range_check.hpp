//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_FIELD_RANGE_CHECK_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_FIELD_RANGE_CHECK_HPP

#include <cmath>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // Constraint that x < 2**R
                // Input: x \in Fp
                // Output:
                template<typename ArithmetizationType, std::size_t R, std::size_t... WireIndexes>
                class range_check;

                // The idea is split x in ConstraintDegree-bit chunks.
                // Then, for each chunk x_i, we constraint that x_i < 2**ConstraintDegree.
                // Thus, we get R/ConstraintDegree chunks that is proved to be less than 2**ConstraintDegree.
                // We can aggreate them into one value < 2**R.
                // Layout:
                // W0  | W1   | ... | W14
                //  0  | ...  | ... | ...
                // sum | c_0  | ... | c_13
                // sum | c_14 | ... | c_27
                // ...
                // The last sum = x
                template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t R, std::size_t W0,
                         std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5, std::size_t W6,
                         std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10, std::size_t W11,
                         std::size_t W12, std::size_t W13, std::size_t W14>
                class range_check<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, R, W0, W1,
                                  W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t selector_seed = 0x0f0A;

                    constexpr static const std::size_t witness_amount = 15;
                    constexpr static const std::size_t chunk_size = 2;
                    constexpr static const std::size_t reserved_columns = 1;
                    constexpr static const std::size_t chunks_per_row = witness_amount - reserved_columns;
                    constexpr static const std::size_t bits_per_row = chunks_per_row * chunk_size;

                public:
                    constexpr static const std::size_t rows_amount =
                        1 + (R + bits_per_row - 1) / bits_per_row;    // ceil(R / bits_per_row)
                    constexpr static const std::size_t padded_chunks = (rows_amount - 1) * chunks_per_row;
                    constexpr static const std::size_t padding_size = padded_chunks - (R + chunk_size - 1) / chunk_size;
                    constexpr static const std::size_t gates_amount = 1;

                    struct params_type {
                        var x;
                    };

                    struct result_type {
                        var output;

                        result_type(std::size_t component_start_row) {
                            output = var(W0, component_start_row + rows_amount - 1, false);
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         std::size_t start_row_index) {

                        assert(R % chunk_size == 0);

                        auto selector_iterator = assignment.find_selector(selector_seed);
                        std::size_t first_selector_index;

                        if (selector_iterator == assignment.selectors_end()) {
                            first_selector_index = assignment.allocate_selector(selector_seed, gates_amount);
                            generate_gates(bp, assignment, params, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }

                        assignment.enable_selector(first_selector_index, start_row_index + 1,
                                                   start_row_index + rows_amount - 1);

                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        generate_assignments_constants(assignment, params, start_row_index);

                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        typename BlueprintFieldType::value_type x = assignment.var_value(params.x);

                        typename BlueprintFieldType::integral_type x_integral =
                            typename BlueprintFieldType::integral_type(x.data);

                        std::array<bool, padded_chunks * chunk_size> bits;
                        {
                            nil::marshalling::status_type status;
                            std::array<bool, 255> bytes_all =
                                nil::marshalling::pack<nil::marshalling::option::big_endian>(x_integral, status);
                            std::copy(bytes_all.end() - padded_chunks * chunk_size, bytes_all.end(), bits.begin());
                        }

                        BOOST_ASSERT(chunk_size <= 8);

                        std::array<std::uint8_t, padded_chunks> chunks;
                        for (std::size_t i = 0; i < padded_chunks; i++) {
                            std::uint8_t chunk_value = 0;
                            for (std::size_t j = 0; j < chunk_size; j++) {
                                chunk_value <<= 1;
                                chunk_value |= bits[i * chunk_size + j];
                            }
                            chunks[i] = chunk_value;
                        }

                        assignment.witness(W0)[row] = 0;
                        row++;

                        typename BlueprintFieldType::value_type shift = 2;
                        shift = shift.pow(chunk_size * chunks_per_row);

                        for (std::size_t i = 0; i < rows_amount - 1; i++) {
                            typename BlueprintFieldType::value_type sum = 0;
                            for (std::size_t j = 0; j < chunks_per_row; j++) {
                                assignment.witness(W0 + reserved_columns + j)[row] = chunks[i * chunks_per_row + j];
                                sum *= (1 << chunk_size);
                                sum += chunks[i * chunks_per_row + j];
                            }
                            assignment.witness(W0)[row] = sum + assignment.witness(W0)[row - 1] * shift;
                            row++;
                        }

                        typename BlueprintFieldType::value_type x_reconstructed = assignment.witness(W0)[row - 1];
                        BOOST_ASSERT(x_reconstructed == x);
                        BOOST_ASSERT(row == start_row_index + rows_amount);

                        return result_type(start_row_index);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               const std::size_t first_selector_index) {

                        typename ArithmetizationType::field_type::value_type base_two = 2;

                        std::vector<snark::plonk_constraint<BlueprintFieldType>> constraints;

                        // assert chunk size
                        for (std::size_t i = 0; i < chunks_per_row; i++) {
                            snark::plonk_constraint<BlueprintFieldType> chunk_range_constraint =
                                var(W0 + reserved_columns + i, 0, true);
                            for (std::size_t j = 1; j < (1 << chunk_size); j++) {
                                chunk_range_constraint =
                                    chunk_range_constraint * (var(W0 + reserved_columns + i, 0, true) - j);
                            }

                            constraints.push_back(bp.add_constraint(chunk_range_constraint));
                        }

                        // assert sum
                        snark::plonk_constraint<BlueprintFieldType> sum_constraint =
                            var(W0 + reserved_columns, 0, true);
                        for (std::size_t i = 1; i < chunks_per_row; i++) {
                            sum_constraint =
                                base_two.pow(chunk_size) * sum_constraint + var(W0 + reserved_columns + i, 0, true);
                        }
                        sum_constraint = sum_constraint +
                                         base_two.pow(chunk_size * chunks_per_row) * var(W0, -1, true) -
                                         var(W0, 0, true);
                        constraints.push_back(bp.add_constraint(sum_constraint));

                        snark::plonk_gate<BlueprintFieldType, snark::plonk_constraint<BlueprintFieldType>> gate(
                            first_selector_index, constraints);
                        bp.add_gate(gate);
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  std::size_t component_start_row) {

                        var zero(0, component_start_row, false, var::column_type::constant);
                        bp.add_copy_constraint({zero, var(W0, component_start_row, false)});

                        for (std::size_t i = 1; i <= padding_size; i++) {
                            bp.add_copy_constraint({zero, var(W0 + i, component_start_row + 1, false)});
                        }

                        bp.add_copy_constraint({params.x, var(W0, component_start_row + rows_amount - 1, false)});
                    }

                    static void generate_assignments_constants(
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        assignment.constant(0)[row] = 0;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_FIELD_RANGE_CHECK_HPP