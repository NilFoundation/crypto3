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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_DETAIL_LAGRANGE_DENOMINATORS_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_DETAIL_LAGRANGE_DENOMINATORS_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/proof.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                // result = [(zeta - omega^(i))^(-1)] concat. [(zeta_omega - omega^(i))^(-1)] for i in
                // (0..public_input_size)
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/verifier.rs#L231-L240
                // Input: eval_point_0, eval_point_1, [omega^0, omega^1, ..., omega^public_input_size]
                // Output: [(eval_point_0 - omega^(i))^(-1), (eval_point_1 - omega^(i))^(-1) for i in
                // (0..public_input_size)]
                template<typename ArithmetizationType, std::size_t PublicInputSize, std::size_t... WireIndexes>
                class lagrange_denominators;

                template<typename BlueprintFieldType, std::size_t PublicInputSize,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                         std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10,
                         std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class lagrange_denominators<snark::plonk_constraint_system<BlueprintFieldType>,
                                            PublicInputSize, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13,
                                            W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType>
                        ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;

                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;
                    using div_component = zk::components::division<ArithmetizationType, W0, W1, W2, W3>;

                    constexpr static const std::size_t selector_seed = 0x0f0d;

                public:
                    constexpr static const std::size_t rows_amount =
                        (sub_component::rows_amount + div_component::rows_amount) * PublicInputSize * 2;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        var zeta;
                        var zeta_omega;
                        std::array<var, PublicInputSize> omega_powers;
                        var one;
                    };

                    struct result_type {
                        std::array<var, PublicInputSize * 2> output;

                        result_type(std::size_t component_start_row) {
                            std::size_t row = component_start_row;
                            for (std::size_t i = 0; i < PublicInputSize; i++) {
                                row += sub_component::rows_amount;
                                var div_res = typename div_component::result_type(row).output;
                                row += div_component::rows_amount;
                                output[i] = div_res;
                            }

                            for (std::size_t i = 0; i < PublicInputSize; i++) {
                                row += sub_component::rows_amount;
                                var div_res = typename div_component::result_type(row).output;
                                row += div_component::rows_amount;
                                output[PublicInputSize + i] = div_res;
                            }
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        for (std::size_t i = 0; i < PublicInputSize; i++) {
                            var sub_res = zk::components::generate_circuit<sub_component>(
                                              bp, assignment, {params.zeta, params.omega_powers[i]}, row)
                                              .output;
                            row += sub_component::rows_amount;
                            var div_res = zk::components::generate_circuit<div_component>(bp, assignment,
                                                                                          {params.one, sub_res}, row)
                                              .output;
                            row += div_component::rows_amount;
                        }

                        for (std::size_t i = 0; i < PublicInputSize; i++) {
                            var sub_res = zk::components::generate_circuit<sub_component>(
                                              bp, assignment, {params.zeta_omega, params.omega_powers[i]}, row)
                                              .output;
                            row += sub_component::rows_amount;
                            var div_res = zk::components::generate_circuit<div_component>(bp, assignment,
                                                                                          {params.one, sub_res}, row)
                                              .output;
                            row += div_component::rows_amount;
                        }

                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        for (std::size_t i = 0; i < PublicInputSize; i++) {
                            var sub_res = sub_component::generate_assignments(
                                              assignment, {params.zeta, params.omega_powers[i]}, row)
                                              .output;
                            row += sub_component::rows_amount;
                            var div_res =
                                div_component::generate_assignments(assignment, {params.one, sub_res}, row).output;
                            row += div_component::rows_amount;
                        }

                        for (std::size_t i = 0; i < PublicInputSize; i++) {
                            var sub_res = sub_component::generate_assignments(
                                              assignment, {params.zeta_omega, params.omega_powers[i]}, row)
                                              .output;
                            row += sub_component::rows_amount;
                            var div_res =
                                div_component::generate_assignments(assignment, {params.one, sub_res}, row).output;
                            row += div_component::rows_amount;
                        }

                        return result_type(start_row_index);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               const std::size_t first_selector_index) {
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t start_row_index) {
                    }
                };
            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_DETAIL_LAGRANGE_DENOMINATORS_HPP