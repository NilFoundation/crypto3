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
// @file Declaration of interfaces for auxiliary components for the SHA256 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_MULTI_SCALAR_MUL_COMPONENT_15_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_MULTI_SCALAR_MUL_COMPONENT_15_WIRES_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/unified_addition.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/variable_base_scalar_mul_15_wires.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType,
                         typename CurveType,
                         std::size_t PointsAmount,
                         std::size_t... WireIndexes>
                class element_g1_multi_scalar_mul;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         typename CurveType,
                         std::size_t PointsAmount,
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
                class element_g1_multi_scalar_mul<
                    snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams>,
                    CurveType, PointsAmount,
                    W0, W1, W2, W3, W4,
                    W5, W6, W7, W8, W9,
                    W10, W11, W12, W13, W14>{

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    using scalar_mul_component = zk::components::curve_element_variable_base_scalar_mul<ArithmetizationType, CurveType,
                                                            W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    using add_component = zk::components::curve_element_unified_addition<ArithmetizationType, CurveType,
                                                            W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10>;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                public:
                    constexpr static const std::size_t selector_seed = 0x0f07;
                    constexpr static const std::size_t rows_amount = PointsAmount * (scalar_mul_component::rows_amount + add_component::rows_amount);
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        struct var_ec_point {
                            var X;
                            var Y;
                        };

                        std::vector<var> scalars; 
                        std::vector<var_ec_point> bases;
                    };

                    struct result_type {
                        struct var_ec_point {
                            var X;
                            var Y;
                        };
                        
                        var_ec_point sum;

                        result_type(const params_type &params, const std::size_t &start_row_index) {
                        }
                    };

                    static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type params,
                        const std::size_t start_row_index){

                        std::size_t row = start_row_index;
                        std::array<var, 2> res;
                        for (std::size_t i = 0; i < PointsAmount; i++) {
                            auto multiplied = scalar_mul_component::generate_circuit(bp,
                                assignment, {{params.bases[i].X, params.bases[i].Y}, params.scalars[i]},
                                row);
                            row += scalar_mul_component::rows_amount;
                            if (i == 0) {
                                res[0] = multiplied.X;
                                res[1] = multiplied.Y;
                            } else {
                                components::generate_circuit<add_component>(bp,
                                    assignment, {{res[0], res[1]}, {multiplied.X, multiplied.Y}},
                                    row);
                                typename add_component::result_type added({{res[0], res[1]}, {multiplied.X, multiplied.Y}}, row);
                                res[0] = added.X;
                                res[1] = added.Y;
                                row += add_component::rows_amount;
                            }
                        }
                        
                        auto result = result_type(params, start_row_index);
                        result.sum.X = res[0];
                        result.sum.Y = res[1];
                        return result;
                    }

                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const params_type &params,
                        const std::size_t &component_start_row) {

                    }

                    static void generate_copy_constraints(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const params_type &params,
                        const std::size_t &component_start_row) {
                        
                    }

                    static result_type generate_assignments(
                        blueprint_assignment_table<ArithmetizationType>
                            &assignment,
                        const params_type params,
                        const std::size_t start_row_index) {
                        
                        std::size_t row = start_row_index;
                        std::array<var, 2> res;
                        for (std::size_t i = 0; i < PointsAmount; i++) {
                            auto multiplied = scalar_mul_component::generate_assignments(
                                assignment, {{params.bases[i].X, params.bases[i].Y}, params.scalars[i]},
                                row);
                            row += scalar_mul_component::rows_amount;
                            if (i == 0) {
                                res[0] = multiplied.X;
                                res[1] = multiplied.Y;
                            } else {
                                auto added = add_component::generate_assignments(
                                    assignment, {{res[0], res[1]}, {multiplied.X, multiplied.Y}},
                                    row);
                                res[0] = added.X;
                                res[1] = added.Y;
                                row += add_component::rows_amount;
                            }
                        }
                        std::cout<<"X: "<<assignment.var_value(res[0]).data<<" Y: "<<assignment.var_value(res[1]).data<<std::endl;
                        
                        auto result = result_type(params, start_row_index);
                        result.sum.X = res[0];
                        result.sum.Y = res[1];
                        return result;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_MULTI_SCALAR_MUL_COMPONENT_15_WIRES_HPP
