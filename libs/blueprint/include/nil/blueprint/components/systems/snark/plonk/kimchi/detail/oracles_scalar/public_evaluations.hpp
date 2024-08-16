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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_DETAIL_PUBLIC_EVALUATIONS_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_DETAIL_PUBLIC_EVALUATIONS_HPP

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

                // evaluate negated public polynomials at evaluation points
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/verifier.rs#L245-L269
                // Input: zeta^n, (zeta * omega)^n, lagrange_denominators, public_input, omega_powers
                // Output: r = {r_0, r_1}
                //         r_0 = (zeta_pow_n - 1) * domain.size_inv * SUM(-l * p * w)
                //              where l from lagrange_denominators, p from public_input, w from omega_powers for l from
                //              0 to PulicInputSize
                //         r_1 = (zeta_omega.pow(n) - 1) * index.domain.size_inv * SUM(-l * p * w)
                //              where l from lagrange_denominators, p from public_input, w from omega_powers for l from
                //              PulicInputSize to 2 * PulicInputSize
                template<typename ArithmetizationType, std::size_t PublicInputSize, std::size_t... WireIndexes>
                class public_evaluations;

                template<typename BlueprintFieldType, std::size_t PublicInputSize,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                         std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10,
                         std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class public_evaluations<snark::plonk_constraint_system<BlueprintFieldType>,
                                         PublicInputSize, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13,
                                         W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType>
                        ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;

                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;
                    using div_component = zk::components::division<ArithmetizationType, W0, W1, W2, W3>;
                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;
                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using mul_by_const_component = zk::components::mul_by_constant<ArithmetizationType, W0, W1>;

                    constexpr static const std::size_t selector_seed = 0x0f0e;

                public:
                    constexpr static const std::size_t rows_amount =
                        1 + ((mul_by_const_component::rows_amount + mul_component::rows_amount +
                              mul_component::rows_amount + add_component::rows_amount) *
                                 PublicInputSize +
                             sub_component::rows_amount + div_component::rows_amount + mul_component::rows_amount) *
                                2;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        var zeta_pow_n;
                        var zeta_omega_pow_n;
                        std::array<var, PublicInputSize> &public_input;
                        std::array<var, 2 * PublicInputSize> &lagrange_base;
                        std::array<var, PublicInputSize> &omega_powers;
                        var domain_size;
                        var one;
                        var zero;
                    };

                    struct result_type {
                        std::array<var, 2> output;

                        result_type(std::size_t component_start_row) {
                            std::size_t row = component_start_row;
                            row++;
                            for (std::size_t j = 0; j < 2; j++) {
                                for (std::size_t i = 0; i < PublicInputSize; i++) {
                                    row += mul_by_const_component::rows_amount;
                                    row += mul_component::rows_amount;
                                    row += mul_component::rows_amount;
                                    row += add_component::rows_amount;
                                }

                                row += sub_component::rows_amount;
                                row += div_component::rows_amount;
                                output[j] = typename mul_component::result_type(row).output;
                                row += mul_component::rows_amount;
                            }
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        std::array<var, 2> res = {var(W0, row, false), var(W1, row, false)};
                        row++;

                        for (std::size_t j = 0; j < 2; j++) {
                            for (std::size_t i = 0; i < PublicInputSize; i++) {
                                var term = zk::components::generate_circuit<mul_by_const_component>(
                                               bp, assignment, {params.lagrange_base[j * PublicInputSize + i], -1}, row)
                                               .output;
                                row += mul_by_const_component::rows_amount;
                                term = zk::components::generate_circuit<mul_component>(
                                           bp, assignment, {term, params.public_input[i]}, row)
                                           .output;
                                row += mul_component::rows_amount;
                                term = zk::components::generate_circuit<mul_component>(
                                           bp, assignment, {term, params.omega_powers[i]}, row)
                                           .output;
                                row += mul_component::rows_amount;
                                res[j] =
                                    zk::components::generate_circuit<add_component>(bp, assignment, {res[j], term}, row)
                                        .output;
                                row += add_component::rows_amount;
                            }

                            var tmp = j == 0 ? params.zeta_pow_n : params.zeta_omega_pow_n;
                            var res_multiplier =
                                zk::components::generate_circuit<sub_component>(bp, assignment, {tmp, params.one}, row)
                                    .output;
                            row += sub_component::rows_amount;
                            res_multiplier = zk::components::generate_circuit<div_component>(
                                                 bp, assignment, {res_multiplier, params.domain_size}, row)
                                                 .output;
                            row += div_component::rows_amount;
                            res[j] = zk::components::generate_circuit<mul_component>(bp, assignment,
                                                                                     {res[j], res_multiplier}, row)
                                         .output;
                            row += mul_component::rows_amount;
                        }

                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        // r[0] = (zeta_pow_n - 1) * domain.size_inv * SUM(-l * p * w)
                        // where l from lagrange, p from public, w from omega_powers for l from 0 to PulicInputSize
                        // r[2] = (zeta_omega.pow(n) - 1) * index.domain.size_inv * SUM(-l * p * w)
                        // where l from lagrange, p from public, w from omega_powers for l from PulicInputSize to 2 *
                        // PulicInputSize
                        assignment.witness(W0)[row] = 0;
                        assignment.witness(W1)[row] = 0;
                        std::array<var, 2> res = {var(W0, row, false), var(W1, row, false)};
                        row++;

                        for (std::size_t j = 0; j < 2; j++) {
                            for (std::size_t i = 0; i < PublicInputSize; i++) {
                                var term = mul_by_const_component::generate_assignments(
                                               assignment, {params.lagrange_base[j * PublicInputSize + i], -1}, row)
                                               .output;
                                row += mul_by_const_component::rows_amount;
                                term =
                                    mul_component::generate_assignments(assignment, {term, params.public_input[i]}, row)
                                        .output;
                                row += mul_component::rows_amount;
                                term =
                                    mul_component::generate_assignments(assignment, {term, params.omega_powers[i]}, row)
                                        .output;
                                row += mul_component::rows_amount;
                                res[j] = add_component::generate_assignments(assignment, {res[j], term}, row).output;
                                row += add_component::rows_amount;
                            }

                            var tmp = j == 0 ? params.zeta_pow_n : params.zeta_omega_pow_n;
                            var res_multiplier =
                                sub_component::generate_assignments(assignment, {tmp, params.one}, row).output;
                            row += sub_component::rows_amount;
                            res_multiplier = div_component::generate_assignments(
                                                 assignment, {res_multiplier, params.domain_size}, row)
                                                 .output;
                            row += div_component::rows_amount;
                            res[j] =
                                mul_component::generate_assignments(assignment, {res[j], res_multiplier}, row).output;
                            row += mul_component::rows_amount;
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
                        bp.add_copy_constraint({var(W0, start_row_index, false), params.zero});
                        bp.add_copy_constraint({var(W1, start_row_index, false), params.zero});
                    }
                };
            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_DETAIL_PUBLIC_EVALUATIONS_HPP