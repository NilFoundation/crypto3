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

                    static typename BlueprintFieldType::value_type var_value(blueprint_assignment_table<ArithmetizationType> &assignment,
                            const var &a) {

                        typename BlueprintFieldType::value_type result;
                        if (a.type == var::column_type::witness) {
                            result = assignment.witness(a.index)[a.rotation];
                        } else if (a.type == var::column_type::public_input) {
                            result = assignment.public_input(a.index)[a.rotation];
                        } else {
                            result = assignment.constant(a.index)[a.rotation];
                        }

                        return result;
                    }

                public:
                    constexpr static const std::size_t required_rows_amount = 1;

                    struct params_type {
                        std::array<var, 2> scalar_limbs_var;
                    };

                    struct result_type
                    {
                        var result;
                    };

                    struct allocated_data_type {
                        std::vector<std::size_t> start_rows;
                    };
                    

                    static std::size_t allocate_rows (blueprint<ArithmetizationType> &in_bp){
                        return in_bp.allocate_rows(required_rows_amount);
                    }

                    static void allocate(blueprint<ArithmetizationType> &bp,
                            blueprint_assignment_table<ArithmetizationType> &assignment,
                            const params_type &scalar_limbs_var,
                            allocated_data_type &allocated_data,
                            const std::size_t &component_start_row = 0) {
                                allocated_data.start_rows.push_back(component_start_row);

                        bp.add_copy_constraint({{W0, static_cast<int>(component_start_row), false}, 
                        {scalar_limbs_var[0].index, scalar_limbs_var[0].rotation, false, scalar_limbs_var[0].type}});
                        bp.add_copy_constraint({{W1, static_cast<int>(component_start_row), false}, 
                            {scalar_limbs_var[1].index, scalar_limbs_var[1].rotation, false, scalar_limbs_var[1].type}});
                    }

                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                            blueprint_assignment_table<ArithmetizationType> &assignment,
                            allocated_data_type &allocated_data,
                        const std::size_t &component_start_row = 0) {

                        const std::size_t &row = component_start_row;

                        std::vector<std::size_t> selector_rows(allocated_data.start_rows * required_rows_amount);
                        for (std::size_t i = 0; i < allocated_data.start_rows; i++) {
                            for (std::size_t j = 0; j < required_rows_amount; j++) {
                                selector_rows[i * required_rows_amount + j] = allocated_data.start_rows[i] + j;
                            }
                        }

                        std::size_t selector_index_1 = assignment.add_selector(selector_rows);

                        // TODO constraints

                        bp.add_gate(selector_index_1, 
                            {});
                    }

                    static result_type generate_assignments(
                            blueprint_assignment_table<ArithmetizationType> &assignment,
                                        const params_type &private_params,
                                        const std::size_t &component_start_row) {

                        std::size_t row = component_start_row;
                        typename BlueprintFieldType::value_type first_limb = var_value(assignment, private_params.scalar_limbs_var[0]);
                        typename BlueprintFieldType::value_type second_limb = var_value(assignment, private_params.scalar_limbs_var[1]);
                        assignment.witness(W0)[row] = first_limb;
                        assignment.witness(W1)[row] = second_limb;
                        typename BlueprintFieldType::value_type scalar = 2;
                        scalar = scalar.pow(64) * second_limb + first_limb;
                        std::cout<<scalar.data<<std::endl;
                        assignment.witness(W2)[row] = scalar;
                        var res(W2, row, false);

                        return result_type {res};
                    }
                };
                
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_ORACLES_DETAIL_COMPONENT_15_WIRES_HPP