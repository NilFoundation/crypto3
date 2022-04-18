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
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/verifier_index.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/sponge.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/transcript.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/endo_scalar.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/exponentiation.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>

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
                    using from_limbs = zk::components::from_limbs<ArithmetizationType, CurveType, W0, W1, W2>;
                    using exponentiation_component = zk::components::exponentiation<ArithmetizationType,
                                                            W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    using multiplication_component = zk::components::multiplication<ArithmetizationType,
                                                            W0, W1, W2>;

                    constexpr static const permute_size = 7;

                    static var assignments_from_limbs(blueprint_assignment_table<ArithmetizationType> &assignment,
                            std::array<var, 2> scalar_limbs_var,
                            std::size_t &component_start_row) {

                        typename from_limbs::result_type res = from_limbs::generate_assignments(assignment, 
                            typename from_limbs::params_type {scalar_limbs_var}, component_start_row);

                        component_start_row += from_limbs::required_rows_amount;
                        return res.result;
                    }

                    static void copy_constraints_from_limbs(blueprint<ArithmetizationType> &bp,
                            blueprint_assignment_table<ArithmetizationType> &assignment,
                            std::array<var, 2> scalar_limbs_var,
                            const std::size_t &component_start_row = 0) {

                        bp.add_copy_constraint({{W0, static_cast<int>(component_start_row), false}, 
                            {scalar_limbs_var[0].index, scalar_limbs_var[0].rotation, false, scalar_limbs_var[0].type}});
                        bp.add_copy_constraint({{W1, static_cast<int>(component_start_row), false}, 
                            {scalar_limbs_var[1].index, scalar_limbs_var[1].rotation, false, scalar_limbs_var[1].type}});
                    }

                    static var assignments_endo_scalar(blueprint_assignment_table<ArithmetizationType> &assignment,
                            var scalar,
                            std::size_t &component_start_row) {
                        
                        typename BlueprintFieldType::value_type endo_factor = 0x12CCCA834ACDBA712CAAD5DC57AAB1B01D1F8BD237AD31491DAD5EBDFDFE4AB9_cppui255;
                        std::size_t num_bits = 128;
                        //TODO endo_scalar component has to get variable as scalar param
                        
                        typename endo_scalar_component::params_type params = {scalar, endo_factor, num_bits};
                        typename endo_scalar_component::result_type endo_scalar_res = endo_scalar_component::generate_assignments(assignment,
                            params, component_start_row);
                        component_start_row += endo_scalar_component::required_rows_amount;
                        return endo_scalar_res.endo_scalar;
                    }

                    static var assignment_exponentiation(blueprint_assignment_table<ArithmetizationType> &assignment,
                            var base,
                            var power,
                            std::size_t &component_start_row) {
                        typename exponentiation_component::params_type params = {base, power};
                        typename exponentiation_component::result_type res = 
                            exponentiation_component::generate_assignments(assignment, params, component_start_row);
                        component_start_row += exponentiation_component::required_rows_amount;
                        return res.result;
                    }

                    static var assigment_multiplication(blueprint_assignment_table<ArithmetizationType> &assignment,
                            var x,
                            var y,
                            std::size_t &component_start_row) {
                        typename multiplication_component::params_type params = {x, y};
                        typename multiplication_component::result_type res = 
                            multiplication_component::generate_assignments(assignment, params, component_start_row);
                        component_start_row += multiplication_component::required_rows_amount;
                        return res.result;
                    }

                    static std::vector<var> assigment_element_powers(blueprint_assignment_table<ArithmetizationType> &assignment,
                                var x,
                                std::size_t n,
                                std::size_t &component_start_row) {
                            std::size_t column_index = W0;
                            for (std::size_t i = 0; i < n; i++) {
                                
                            }
                        }

                public:
                    constexpr static const std::size_t required_rows_amount = 32;

                    struct params_type {
                        kimchi_verifier_index_scalar<CurveType> verifier_index;
                        //kimchi_scalar_limbs joint_combiner;
                        //kimchi_scalar_limbs beta;
                        //kimchi_scalar_limbs gamma;
                        kimchi_scalar_limbs alpha;
                        kimchi_scalar_limbs zeta;
                        typename BlueprintFieldType::value_type fq_digest; // TODO overflow check
                    };

                    struct result_type {
                        result_type(const params_type &params,
                            const std::size_t &component_start_row) {

                        }
                    };

                    struct allocated_data_type {
                        allocated_data_type() {
                            previously_allocated = false;
                        }

                        // TODO access modifiers
                        bool previously_allocated;
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

                        return result_type(params, component_start_row);
                    }

                    static result_type generate_assignments(
                            blueprint_assignment_table<ArithmetizationType> &assignment,
                            const params_type &params,
                            const std::size_t &component_start_row) {
                            
                        std::size_t row = component_start_row;
                        const std::size_t public_input_size = 5; 

                        // copy public input
                        var alpha_limb_1 = assignment.allocate_public_input(params.alpha[0]);
                        var alpha_limb_2 = assignment.allocate_public_input(params.alpha[1]);
                        var zeta_limb_1 = assignment.allocate_public_input(params.zeta[0]);
                        var zeta_limb_2 = assignment.allocate_public_input(params.zeta[1]);
                        var fq_digest = assignment.allocate_public_input(params.fq_digest);
                        var omega = assignment.allocate_public_input(params.omega);

                        std::array<var, 2> alpha_pub_limbs = {alpha_limb_1, alpha_limb_2};
                        std::array<var, 2> zeta_pub_limbs = {zeta_limb_1, zeta_limb_2};

                        //row += public_input_size;

                        var alpha = assignments_from_limbs(assignment,
                            alpha_pub_limbs, row);
                        var alpha_endo = assignments_endo_scalar(assignment,
                            alpha, row);
                        
                        var zeta = assignments_from_limbs(assignment,
                            zeta_pub_limbs, row);
                        var zeta_endo = assignments_endo_scalar(assignment,
                            zeta, row);

                        kimchi_transcript<ArithmetizationType, CurveType,
                            W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> transcript;
                        transcript.init_assignment(assignment, row);
                        transcript.absorb_assignment(assignment,
                            fq_digest, row);

                        var n = assignment.allocate_public_input(params.verifier_index.n);
                        var zeta_pow_n = assignment_exponentiation(assignment, zeta, n, row);

                        var zeta_omega = assigment_multiplication(assignment, zeta, omega, row);
                        
                        return result_type(params, component_start_row);
                    }

                    private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                            blueprint_assignment_table<ArithmetizationType> &assignment,
                            const params_type &params,
                            allocated_data_type &allocated_data,
                        const std::size_t &component_start_row = 0) {

                        const std::size_t &j = component_start_row;
                        using F = typename BlueprintFieldType::value_type;

                        std::size_t selector_index_1 = assignment.add_selector(j, j + required_rows_amount - 1);

                        bp.add_gate(selector_index_1, 
                            {});
                    }

                    static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                            blueprint_assignment_table<ArithmetizationType> &assignment,
                            const params_type &params,
                            const std::size_t &component_start_row = 0){

                        std::size_t row = component_start_row;

                        std::array<var, 2> alpha_pub_limbs = {var(0, row, false, var::column_type::public_input), 
                                var(0, row + 1, false, var::column_type::public_input)};
                        std::array<var, 2> zeta_pub_limbs = {var(0, row + 2, false, var::column_type::public_input), 
                                var(0, row + 3, false, var::column_type::public_input)};

                        row += 4;
                        
                        copy_constraints_from_limbs(bp, assignment, alpha_pub_limbs, row);
                        row++;
                        // copy endo-scalar
                        row += endo_scalar_component::required_rows_amount;
                        
                        copy_constraints_from_limbs(bp, assignment, zeta_pub_limbs, row);
                        row++;
                        // copy endo-scalar
                        row += endo_scalar_component::required_rows_amount;
                            
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_ORACLES_COMPONENT_15_WIRES_HPP
