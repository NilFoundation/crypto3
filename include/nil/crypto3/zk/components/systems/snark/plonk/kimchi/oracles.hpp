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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_ORACLES_COMPONENT_15_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_ORACLES_COMPONENT_15_WIRES_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/entities/verifier_index.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/endo_scalar.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType,
                         typename CurveType,
                         std::size_t... WireIndexes>
                class oracles_scalar;

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
                class oracles_scalar<
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
                    using endo_scalar_component = zk::components::endo_scalar<ArithmetizationType, CurveType,
                                                            W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    static typename BlueprintFieldType::value_type var_value(blueprint_private_assignment_table<ArithmetizationType> &private_assignment,
                            blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                            const var &a) {

                        typename BlueprintFieldType::value_type result;
                        if (a.type == var::column_type::witness) {
                            result = private_assignment.witness(a.index)[a.rotation];
                        } else if (a.type == var::column_type::public_input) {
                            result = public_assignment.public_input(a.index)[a.rotation];
                        } else {
                            result = public_assignment.constant(a.index)[a.rotation];
                        }

                        return result;
                    }

                    static var assignments_from_limbs(blueprint_private_assignment_table<ArithmetizationType> &private_assignment,
                            blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                            std::array<var, 2> scalar_limbs_var,
                            std::size_t &component_start_row) {

                        constexpr const std::size_t from_limbs_rows = 1;

                        std::size_t row = component_start_row;
                        typename BlueprintFieldType::value_type first_limb = var_value(private_assignment, public_assignment, scalar_limbs_var[0]);
                        typename BlueprintFieldType::value_type second_limb = var_value(private_assignment, public_assignment, scalar_limbs_var[1]);
                        private_assignment.witness(W0)[row] = first_limb;
                        private_assignment.witness(W1)[row] = second_limb;
                        std::cout<<"first limb: "<<first_limb.data<<std::endl;
                        typename BlueprintFieldType::value_type scalar = 2;
                        scalar = scalar.pow(64) * second_limb + first_limb;
                        std::cout<<scalar.data<<std::endl;
                        private_assignment.witness(W2)[row] = scalar;
                        var res(W2, row, false);

                        component_start_row += from_limbs_rows;
                        return res;
                    }

                    static void copy_constraints_from_limbs(blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                            std::array<var, 2> scalar_limbs_var,
                            const std::size_t &component_start_row = 0) {

                        bp.add_copy_constraint({{W0, static_cast<int>(component_start_row), false}, 
                            {scalar_limbs_var[0].index, scalar_limbs_var[0].rotation, false, scalar_limbs_var[0].type}});
                        bp.add_copy_constraint({{W1, static_cast<int>(component_start_row), false}, 
                            {scalar_limbs_var[1].index, scalar_limbs_var[1].rotation, false, scalar_limbs_var[1].type}});
                    }

                    static var assignments_endo_scalar(blueprint_private_assignment_table<ArithmetizationType> &private_assignment,
                            blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                            var scalar,
                            std::size_t &component_start_row) {
                        
                        typename BlueprintFieldType::value_type endo_factor = 0x12CCCA834ACDBA712CAAD5DC57AAB1B01D1F8BD237AD31491DAD5EBDFDFE4AB9_cppui255;
                        std::size_t num_bits = 128;
                        //TODO endo_scalar component has to get variable as scalar param
                        typename BlueprintFieldType::value_type scalar_value = var_value(private_assignment, public_assignment, scalar);
                        
                        typename endo_scalar_component::private_params_type private_params = {scalar_value};
                        typename endo_scalar_component::public_params_type public_params = {endo_factor, num_bits};
                        typename endo_scalar_component::result_type endo_scalar_res = endo_scalar_component::generate_assignments(private_assignment,
                            public_assignment, public_params, private_params, component_start_row);
                        component_start_row += endo_scalar_component::required_rows_amount;
                        return endo_scalar_res.endo_scalar;
                    }

                public:
                    constexpr static const std::size_t required_rows_amount = 32;

                    struct public_params_type {
                        //kimchi_scalar_limbs joint_combiner;
                        //kimchi_scalar_limbs beta;
                        //kimchi_scalar_limbs gamma;
                        kimchi_scalar_limbs alpha;
                        kimchi_scalar_limbs zeta;
                        typename BlueprintFieldType::value_type fq_digest; // TODO overflow check
                    };

                    struct private_params_type {
                        kimchi_verifier_index_scalar<CurveType> verifier_index;
                    };

                    static std::size_t allocate_rows (blueprint<ArithmetizationType> &in_bp){
                        return in_bp.allocate_rows(required_rows_amount);
                    }

                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                            const public_params_type &public_params,
                        const std::size_t &component_start_row = 0) {

                        const std::size_t &j = component_start_row;
                        using F = typename BlueprintFieldType::value_type;

                        std::size_t selector_index_1 = public_assignment.add_selector(j, j + required_rows_amount - 1);

                        bp.add_gate(selector_index_1, 
                            {});
                    }

                    static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                            const public_params_type &public_params,
                            const std::size_t &component_start_row = 0){

                        std::size_t row = component_start_row;

                        std::array<var, 2> alpha_pub_limbs = {var(0, row, false, var::column_type::public_input), 
                                var(0, row + 1, false, var::column_type::public_input)};
                        std::array<var, 2> zeta_pub_limbs = {var(0, row + 2, false, var::column_type::public_input), 
                                var(0, row + 3, false, var::column_type::public_input)};

                        row += 4;
                        
                        copy_constraints_from_limbs(bp, public_assignment, alpha_pub_limbs, row);
                        row++;
                        // copy endo-scalar
                        row += endo_scalar_component::required_rows_amount;
                        
                        copy_constraints_from_limbs(bp, public_assignment, zeta_pub_limbs, row);
                        row++;
                        // copy endo-scalar
                        row += endo_scalar_component::required_rows_amount;
                            
                    }

                    static void generate_assignments(
                            blueprint_private_assignment_table<ArithmetizationType> &private_assignment,
                            blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                                        const public_params_type &public_params,
                                        const private_params_type &private_params,
                                        const std::size_t &component_start_row) {
                            
                        std::size_t row = component_start_row;

                        // copy public input
                        public_assignment.public_input(0)[row] = public_params.alpha[0];
                        public_assignment.public_input(0)[row + 1] = public_params.alpha[1];
                        public_assignment.public_input(0)[row + 2] = public_params.zeta[0];
                        public_assignment.public_input(0)[row + 3] = public_params.zeta[1];

                        std::array<var, 2> alpha_pub_limbs = {var(0, row, false, var::column_type::public_input), 
                                var(0, row + 1, false, var::column_type::public_input)};
                        std::array<var, 2> zeta_pub_limbs = {var(0, row + 2, false, var::column_type::public_input), 
                                var(0, row + 3, false, var::column_type::public_input)};

                        row += 4;

                        var alpha = assignments_from_limbs(private_assignment, public_assignment,
                            alpha_pub_limbs, row);
                        var alpha_endo = assignments_endo_scalar(private_assignment, public_assignment,
                            alpha, row);
                        
                        var zeta = assignments_from_limbs(private_assignment, public_assignment,
                            zeta_pub_limbs, row);
                        var zeta_endo = assignments_endo_scalar(private_assignment, public_assignment,
                            zeta, row);
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_ORACLES_COMPONENT_15_WIRES_HPP
