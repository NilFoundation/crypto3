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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_PREV_CHALLENGES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_PREV_CHALLENGES_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/proof.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                
                template<typename ArithmetizationType,
                         typename CurveType,
                         std::size_t... WireIndexes>
                class prev_challenges_scalar;

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
                class prev_challenges_scalar<
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

                public:
                    constexpr static const std::size_t required_rows_amount = 1;

                    struct params_type {
                        
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
                        return in_bp.allocate_rows(required_rows_amount);
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
                        
                        /*
                        let polys: Vec<(PolyComm<G>, _)> = self
                            .prev_challenges
                            .iter()
                            .zip(self.prev_chal_evals(index, &ep, &powers_of_eval_points_for_chunks))
                            .map(|(c, e)| (c.1.clone(), e))
                            .collect();
                        */

                       /*
                        pub fn prev_chal_evals(
                            &self,
                            index: &VerifierIndex<G>,
                            evaluation_points: &[Fr<G>],
                            powers_of_eval_points_for_chunks: &[Fr<G>],
                        ) -> Vec<Vec<Vec<Fr<G>>>> {
                            self.prev_challenges
                                .iter()
                                .map(|(chals, _poly)| {
                                    // No need to check the correctness of poly explicitly. Its correctness is assured by the
                                    // checking of the inner product argument.
                                    let b_len = 1 << chals.len();
                                    let mut b: Option<Vec<Fr<G>>> = None;

                                    (0..2)
                                        .map(|i| {
                                            let full = b_poly(chals, evaluation_points[i]);
                                            if index.max_poly_size == b_len {
                                                return vec![full];
                                            }
                                            let mut betaacc = Fr::<G>::one();
                                            let diff = (index.max_poly_size..b_len)
                                                .map(|j| {
                                                    let b_j = match &b {
                                                        None => {
                                                            let t = b_poly_coefficients(chals);
                                                            let res = t[j];
                                                            b = Some(t);
                                                            res
                                                        }
                                                        Some(b) => b[j],
                                                    };

                                                    let ret = betaacc * b_j;
                                                    betaacc *= &evaluation_points[i];
                                                    ret
                                                })
                                                .fold(Fr::<G>::zero(), |x, y| x + y);
                                            vec![full - (diff * powers_of_eval_points_for_chunks[i]), diff]
                                        })
                                        .collect()
                                })
                                .collect()
                        }
                       */

                        return result_type(params, component_start_row);
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
                            selector_index_1 = assignment.add_selector(row, row + required_rows_amount - 1);
                            allocated_data.previously_allocated = true;
                            allocated_data.selector_1 = selector_index_1;
                        } else {
                            selector_index_1 = allocated_data.selector_1;
                            assignment.enable_selector(selector_index_1, row, row + required_rows_amount - 1);
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
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_PREV_CHALLENGES_HPP