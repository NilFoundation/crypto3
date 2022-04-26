//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_ORACLES_DETAIL_COMPONENT_15_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_ORACLES_DETAIL_COMPONENT_15_WIRES_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/endo_scalar.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                ///////////////// From Limbs ////////////////////////////////
                template<typename ArithmetizationType,
                         typename CurveType,
                         std::size_t... WireIndexes>
                class from_limbs;

                template<typename ArithmetizationParams,
                         typename CurveType,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2>
                class from_limbs<
                    snark::plonk_constraint_system<typename CurveType::scalar_field_type, ArithmetizationParams>,
                    CurveType,
                    W0, W1, W2> {

                    using BlueprintFieldType = typename CurveType::scalar_field_type;

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                public:
                    constexpr static const std::size_t rows_amount = 1;

                    struct params_type {
                        std::array<var, 2> scalar_limbs_var;
                    };

                    struct result_type
                    {
                        var result = var(0, 0);

                        result_type(const std::size_t &component_start_row) {
                            result = var(W2, static_cast<int>(component_start_row), false, var::column_type::witness);
                        }
                    };

                    struct allocated_data_type {
                        allocated_data_type() {
                            previously_allocated = false;
                        }

                        // TODO access modifiers
                        bool previously_allocated;
                        std::size_t selector_1;
                    };
                    

                    static std::size_t allocate_rows (blueprint<ArithmetizationType> &in_bp){
                        return in_bp.allocate_rows(rows_amount);
                    }

                    static result_type generate_circuit(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        allocated_data_type &allocated_data,
                        const std::size_t &component_start_row) {

                        generate_gates(bp, assignment, params, allocated_data, component_start_row);
                        generate_copy_constraints(bp, assignment, params, component_start_row);

                        return result_type(component_start_row);
                    }

                    static result_type generate_assignments(
                            blueprint_assignment_table<ArithmetizationType> &assignment,
                                        const params_type &params,
                                        const std::size_t &component_start_row) {

                        std::size_t row = component_start_row;
                        typename BlueprintFieldType::value_type first_limb = assignment.var_value(params.scalar_limbs_var[0]);
                        typename BlueprintFieldType::value_type second_limb = assignment.var_value(params.scalar_limbs_var[1]);
                        assignment.witness(W0)[row] = first_limb;
                        assignment.witness(W1)[row] = second_limb;
                        typename BlueprintFieldType::value_type scalar = 2;
                        scalar = scalar.pow(64) * second_limb + first_limb;
                        std::cout<<scalar.data<<std::endl;
                        assignment.witness(W2)[row] = scalar;

                        return result_type(component_start_row);
                    }

                    private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                        blueprint_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        allocated_data_type &allocated_data,
                        const std::size_t &component_start_row) {

                        const std::size_t &row = component_start_row;

                        std::size_t selector_index_1;
                        if (!allocated_data.previously_allocated) {
                            selector_index_1 = assignment.add_selector(row, row + rows_amount - 1);
                            allocated_data.previously_allocated = true;
                            allocated_data.selector_1 = selector_index_1;
                        } else {
                            selector_index_1 = allocated_data.selector_1;
                            assignment.enable_selector(selector_index_1, row, row + rows_amount - 1);
                        }

                        // TODO constraints

                        bp.add_gate(selector_index_1, 
                            {});
                    }
                    
                    static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                            blueprint_assignment_table<ArithmetizationType> &assignment,
                            const params_type &params,
                            const std::size_t &component_start_row = 0){

                        bp.add_copy_constraint({{W0, static_cast<int>(component_start_row), false}, 
                        {params.scalar_limbs_var[0].index, params.scalar_limbs_var[0].rotation, false, params.scalar_limbs_var[0].type}});
                        bp.add_copy_constraint({{W1, static_cast<int>(component_start_row), false}, 
                            {params.scalar_limbs_var[1].index, params.scalar_limbs_var[1].rotation, false, params.scalar_limbs_var[1].type}});
                    }
                };

                
                ///////////////// From Limbs ////////////////////////////////
                template<typename ArithmetizationType,
                         typename CurveType,
                         std::size_t... WireIndexes>
                class kimchi_oracles_lagrange;

                template<typename ArithmetizationParams,
                         typename CurveType,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4,
                         std::size_t W5,
                         std::size_t W6,
                         std::size_t W7,
                         std::size_t W8,
                         std::size_t W9,
                         std::size_t W10,
                         std::size_t W11,
                         std::size_t W12,
                         std::size_t W13,
                         std::size_t W14>
                class kimchi_oracles_lagrange<
                    snark::plonk_constraint_system<typename CurveType::scalar_field_type, ArithmetizationParams>,
                    CurveType,
                    W0, W1, W2, W3,
                    W4, W5, W6, W7,
                    W8, W9, W10, W11,
                    W12, W13, W14> {

                    using BlueprintFieldType = typename CurveType::scalar_field_type;

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t selector_seed = 0x0f0a;

                public:
                    constexpr static const std::size_t rows_amount = 1;
                    constexpr static const std::size_t gates_amount = 2;

                    struct params_type {
                        var zeta_var;
                        var zeta_omega_var;
                        std::vector<var> omega_powers;
                    };

                    struct result_type
                    {
                        std::vector<var> lagrange_base;

                        result_type(const params_type &params, const std::size_t &component_start_row) {
                            lagrange_base = std::vector<var>(0);
                        }
                    };

                    static result_type generate_circuit(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        allocated_data_type &allocated_data,
                        const std::size_t &component_start_row) {

                        auto selector_iterator = assignment.find_selector(selector_seed);
                        std::size_t first_selector_index;

                        if (selector_iterator == assignment.selectors_end()){
                            first_selector_index = assignment.allocate_selector(selector_seed,
                                gates_amount);
                            generate_gates(bp, assignment, params, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }

                        std::size_t j = start_row_index;
                        assignment.enable_selector(first_selector_index, j, j + rows_amount - 1);
                        assignment.enable_selector(first_selector_index+1, j + rows_amount - 1);

                        generate_copy_constraints(bp, assignment, params, component_start_row);

                        return result_type(component_start_row);
                    }

                    static result_type generate_assignments(
                            blueprint_assignment_table<ArithmetizationType> &assignment,
                                        const params_type &params,
                                        const std::size_t &component_start_row) {

                        // TODO: the naive method for batch inversion is not the optimal one, we can use
                        // Montgomery’s Trick and Fast Implementation of Masked AES
                        // Genelle, Prouff and Quisquater, Section 3.2
                        // result = [(zeta - omega^(i))^(-1)] concat. [(zeta_omega - omega^(i))^(-1)] for i in (0..public_input_size)
                        // * omega = w in the table
                        // W0     | W1                | W2  | W3  | W4  | W5  | W6  | W7           | W8         | W9  | W10 | W11 | W12 | W13          | W14 | W15 |
                        // zeta   | w^0               | w^1 | w^2 | w^3 | w^4 | w^5 | zeta - w^0   | zeta - w^1 | ... | ... | ... | ... | zeta - w^5   |     |     |
                        // zeta_w | (zeta - w^0)^(-1) | ... | ... | ... | ... | ... | zeta_w = w^0 | ...        | ... | ... | ... | ... | zeta_w - w^5 |     |     |
                        //        | (zeta_w - w^0)^(-1) | ..| ... | ... | ... | ... | ...
                        // ....
                        std::vector<var> res(omega_powers.size() * 2);
                        std::size_t omega_idx = 0;
                        std::size_t component_instances = omega_powers.size() / 6;
                        if (omega_powers.size() % 6 > 0) {
                            component_instances += 1;
                        }

                        typename BlueprintFieldType::value_type zeta = assignment.var_value(zeta_var);
                        typename BlueprintFieldType::value_type zeta_omega = assignment.var_value(zeta_omega_var);
                        std::vector<BlueprintFieldType::value_type> omegas(omega_powers.size());
                        for (std::size_t i = 0; i < omega_powers.size(); i++) {
                            omegas[i] = assignment.var_value(omega_powers[i]);
                        }

                        for (std::size_t i = 0; i < component_instances; i++) {
                            assignment.witness(W0)[row] = zeta;
                            std::size_t row_limit = omega_idx + 6 >= omega_powers.size() ? 
                                omega_powers.size() - omega_idx :
                                6;

                            for (std::size_t j = 0; j < row_limit; j++) {
                                assignment.witness(W1 + j)[row] = omegas[omega_idx];
                                assignment.witness(W7 + j)[row] = zeta - omegas[omega_idx];
                                assignment.witness(W7 + j)[row + 1] = zeta_omega - omegas[omega_idx];
                                omega_idx++;
                            }
                            row++;

                            assignment.witness(W0)[row] = zeta_omega;
                            for (std::size_t j = 0; j < row_limit; j++) {
                                assignment.witness(W1 + j)[row] = (assignment.witness(W7 + j)[row - 1]).inversed();
                                res[i + j] = var(W1 + j, row, false);
                                assignment.witness(W1 + j)[row + 1] = (assignment.witness(W7 + j)[row]).inversed();
                                res[omega_powers.size() + i + j] = var(W1 + j, row, false);
                            }
                            row++;
                        }


                        return result_type { res } ;
                    }

                    private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                        blueprint_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t &component_start_row) {

                        const std::size_t &row = component_start_row;

                        // TODO constraints

                        bp.add_gate(selector_index_1, 
                            {});
                    }
                    
                    static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                            blueprint_assignment_table<ArithmetizationType> &assignment,
                            const params_type &params,
                            const std::size_t &component_start_row = 0){

                    }
                };
                
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_ORACLES_DETAIL_COMPONENT_15_WIRES_HPP