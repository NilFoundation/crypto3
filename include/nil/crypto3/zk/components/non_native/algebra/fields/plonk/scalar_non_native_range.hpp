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
// @file Declaration of interfaces for auxiliary components for the RANGE component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_SCALAR_RANGE_EDWARD25519_HPP
#define CRYPTO3_ZK_BLUEPRINT_SCALAR_RANGE_EDWARD25519_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType,
                         typename CurveType,
                         typename Ed25519Type,
                         std::size_t... WireIndexes>
                class scalar_non_native_range;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         typename CurveType,
                         typename Ed25519Type,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4,
                         std::size_t W5,
                         std::size_t W6,
                         std::size_t W7,
                         std::size_t W8>
                class scalar_non_native_range<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                              CurveType,
                                              Ed25519Type,
                                              W0,
                                              W1,
                                              W2,
                                              W3,
                                              W4,
                                              W5,
                                              W6,
                                              W7,
                                              W8> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t selector_seed = 0xff50;

                public:
                    constexpr static const std::size_t rows_amount = 3;
                    constexpr static const std::size_t gates_amount = 1;

                    struct params_type {
                        var k;
                    };

                    struct result_type {
                        std::array<var, 12> output;
                        result_type(std::size_t component_start_row) {
                            output = {var(W1, component_start_row, false),     var(W2, component_start_row, false),
                                      var(W3, component_start_row, false),     var(W4, component_start_row, false),
                                      var(W5, component_start_row, false),     var(W6, component_start_row, false),
                                      var(W7, component_start_row, false),     var(W8, component_start_row, false),
                                      var(W0, component_start_row + 1, false), var(W1, component_start_row + 1, false),
                                      var(W2, component_start_row + 1, false), var(W3, component_start_row + 1, false)};
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         std::size_t start_row_index) {

                        auto selector_iterator = assignment.find_selector(selector_seed);
                        std::size_t first_selector_index;
                        if (selector_iterator == assignment.selectors_end()) {
                            first_selector_index = assignment.allocate_selector(selector_seed, gates_amount);
                            generate_gates(bp, assignment, params, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }
                        std::size_t j = start_row_index;
                        assignment.enable_selector(first_selector_index, j + 1);
                        generate_copy_constraints(bp, assignment, params, j);
                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        typename Ed25519Type::scalar_field_type::integral_type base = 1;
                        typename Ed25519Type::scalar_field_type::extended_integral_type extended_base = 1;
                        typename Ed25519Type::scalar_field_type::integral_type mask = (base << 22) - 1;
                        typename CurveType::base_field_type::integral_type pasta_k =
                            typename CurveType::base_field_type::integral_type(assignment.var_value(params.k).data);
                        typename Ed25519Type::scalar_field_type::integral_type k =
                            typename Ed25519Type::scalar_field_type::integral_type(pasta_k);
                        typename Ed25519Type::scalar_field_type::extended_integral_type q =
                            Ed25519Type::scalar_field_type::modulus;
                        typename Ed25519Type::scalar_field_type::extended_integral_type d = (extended_base << 253) - q;
                        typename Ed25519Type::scalar_field_type::integral_type dk =
                            k + typename Ed25519Type::scalar_field_type::integral_type(d);
                        std::array<typename Ed25519Type::scalar_field_type::integral_type, 12> k_chunks;
                        std::array<typename Ed25519Type::scalar_field_type::integral_type, 12> dk_chunks;
                        for (std::size_t i = 0; i < 12; i++) {
                            k_chunks[i] = (k >> i * 22) & mask;
                            dk_chunks[i] = (dk >> i * 22) & mask;
                        }
                        assignment.witness(W0)[row] = k;
                        assignment.witness(W1)[row] = k_chunks[0];
                        assignment.witness(W2)[row] = k_chunks[1];
                        assignment.witness(W3)[row] = k_chunks[2];
                        assignment.witness(W4)[row] = k_chunks[3];
                        assignment.witness(W5)[row] = k_chunks[4];
                        assignment.witness(W6)[row] = k_chunks[5];
                        assignment.witness(W7)[row] = k_chunks[6];
                        assignment.witness(W8)[row] = k_chunks[7];
                        row++;
                        assignment.witness(W0)[row] = k_chunks[8];
                        assignment.witness(W1)[row] = k_chunks[9];
                        assignment.witness(W2)[row] = k_chunks[10];
                        assignment.witness(W3)[row] = k_chunks[11];
                        assignment.witness(W4)[row] = dk;
                        assignment.witness(W5)[row] = dk_chunks[0];
                        assignment.witness(W6)[row] = dk_chunks[1];
                        assignment.witness(W7)[row] = dk_chunks[2];
                        assignment.witness(W8)[row] = dk_chunks[3];
                        row++;
                        assignment.witness(W0)[row] = dk_chunks[4];
                        assignment.witness(W1)[row] = dk_chunks[5];
                        assignment.witness(W2)[row] = dk_chunks[6];
                        assignment.witness(W3)[row] = dk_chunks[7];
                        assignment.witness(W4)[row] = dk_chunks[8];
                        assignment.witness(W5)[row] = dk_chunks[9];
                        assignment.witness(W6)[row] = dk_chunks[10];
                        assignment.witness(W7)[row] = dk_chunks[11];

                        return result_type(component_start_row);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               std::size_t first_selector_index) {
                        typename CurveType::base_field_type::integral_type base = 1;
                        typename Ed25519Type::scalar_field_type::extended_integral_type extended_base = 1;
                        typename Ed25519Type::scalar_field_type::extended_integral_type q =
                            Ed25519Type::scalar_field_type::modulus;
                        typename Ed25519Type::scalar_field_type::extended_integral_type d = (extended_base << 253) - q;
                        auto constraint_1 = bp.add_constraint(
                            var(W0, -1) -
                            (var(W1, -1) + var(W2, -1) * (base << 22) + var(W3, -1) * (base << 44) +
                             var(W4, -1) * (base << 66) + var(W5, -1) * (base << 88) + var(W6, -1) * (base << 110) +
                             var(W7, -1) * (base << 132) + var(W8, -1) * (base << 154) + var(W0, 0) * (base << 176) +
                             var(W1, 0) * (base << 198) + var(W2, 0) * (base << 220) + var(W3, 0) * (base << 242)));
                        auto constraint_2 = bp.add_constraint(var(W4, 0) - var(W0, -1) - d);
                        auto constraint_3 = bp.add_constraint(
                            var(W4, 0) -
                            (var(W5, 0) + var(W6, 0) * (base << 22) + var(W7, 0) * (base << 44) +
                             var(W8, 0) * (base << 66) + var(W0, +1) * (base << 88) + var(W1, +1) * (base << 110) +
                             var(W2, +1) * (base << 132) + var(W3, +1) * (base << 154) + var(W4, +1) * (base << 176) +
                             var(W5, +1) * (base << 198) + var(W6, +1) * (base << 220) + var(W7, +1) * (base << 242)));
                        bp.add_gate(first_selector_index, {constraint_1, constraint_2, constraint_3});
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        bp.add_copy_constraint({{W0, static_cast<int>(row), false}, params.k});
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_REDUCTION_HPP