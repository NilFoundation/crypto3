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

#include <nil/crypto3/zk/snark/systems/plonk/pickles/constants.hpp>

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
                    
                    struct field_op_component {
                        using mul = zk::components::multiplication<ArithmetizationType,
                                                            W0, W1, W2>;
                        // TODO: change to add / sub
                        using add = zk::components::multiplication<ArithmetizationType,
                                                            W0, W1, W2>;
                        using sub = zk::components::multiplication<ArithmetizationType,
                                                            W0, W1, W2>;
                    };

                    constexpr static const std::size_t permute_size = 7;

                    static var assignments_from_limbs(blueprint_assignment_table<ArithmetizationType> &assignment,
                            std::array<var, 2> scalar_limbs_var,
                            std::size_t &component_start_row) {

                        typename from_limbs::result_type res = from_limbs::generate_assignments(assignment, 
                            typename from_limbs::params_type {scalar_limbs_var}, component_start_row);

                        component_start_row += from_limbs::rows_amount;
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
                        component_start_row += endo_scalar_component::rows_amount;
                        return endo_scalar_res.endo_scalar;
                    }

                    static var assignment_exponentiation(blueprint_assignment_table<ArithmetizationType> &assignment,
                            var base,
                            var power,
                            std::size_t &component_start_row) {
                        typename exponentiation_component::params_type params = {base, power};
                        typename exponentiation_component::result_type res = 
                            exponentiation_component::generate_assignments(assignment, params, component_start_row);
                        component_start_row += exponentiation_component::rows_amount;
                        return res.result;
                    }

                    static var assigment_multiplication(blueprint_assignment_table<ArithmetizationType> &assignment,
                            var x,
                            var y,
                            std::size_t &component_start_row) {
                        typename field_op_component::mul::params_type params = {x, y};
                        typename field_op_component::mul::result_type res = 
                            field_op_component::mul::generate_assignments(assignment, params, component_start_row);
                        component_start_row += field_op_component::mul::rows_amount;
                        return res.result;
                    }

                    static std::vector<var> assigment_element_powers(blueprint_assignment_table<ArithmetizationType> &assignment,
                            var x,
                            std::size_t n,
                            std::size_t &row) {

                        std::vector<var> res(n);
                        if (n < 2) {
                            res.resize(2);
                        }
                        assignment.witness(W0)[row] = 1;
                        res[0] = var(0, row, false);
                        typename BlueprintFieldType::value_type base_value =
                            assignment.var_value(x);
                        assignment.witness(W0 + 1)[row] = base_value;
                        res[1] = var(W0 + 1, row, false);
                        typename BlueprintFieldType::value_type prev_value =
                            base_value;
                        std::size_t column_idx = 2;

                        for (std::size_t i = 2; i < n; i++) {
                            // we need to copy any power of the element
                            // so we place them only on copy-constrainted columns
                            if (column_idx >= zk::snark::kimchi_constant::PERMUTES) {
                                column_idx = 0;
                                row++;
                            }
                            typename BlueprintFieldType::value_type new_value =
                                prev_value * base_value;
                            assignment.witness(W0 + column_idx)[row] = new_value;
                            res[i] = var(W0 + i, row, false);
                            prev_value = new_value;
                        }

                        return res;
                    }

                    static std::vector<var> assignment_lagrange(blueprint_assignment_table<ArithmetizationType> &assignment,
                            var zeta,
                            var zeta_omega,
                            std::vector<var> omega_powers,
                            std::size_t &row) {
                        using lagrange_base_component = zk::components::kimchi_oracles_lagrange<ArithmetizationType, CurveType,
                                                            W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                        auto res = lagrange_base_component::generate_assignments(assignment, {zeta, zeta_omega, omega_powers} , row);
                        row += lagrange_base_component::rows_amount;
                        return res.lagrange_base;
                    }

                    static std::array<var, 2> assignment_puiblic_eval(blueprint_assignment_table<ArithmetizationType> &assignment,
                            const std::vector<var> &public_input,
                            var zeta_pow_n,
                            var zeta_omega_pow_n,
                            std::vector<var> &lagrange_base,
                            std::vector<var> &omega_powers,
                            typename BlueprintFieldType::value_type domain_size_inv,
                            std::size_t &row) {
                        using public_eval_component = zk::components::kimchi_oracles_public_eval<ArithmetizationType, CurveType,
                                                            W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                        auto res = public_eval_component::generate_assignments(assignment, {zeta_pow_n, zeta_omega_pow_n, 
                                public_input, lagrange_base, omega_powers} , row);
                        row += public_eval_component::rows_amount;
                        return res.public_evaluations;
                    }

                    static std::vector<var> assignment_prev_chal_evals(blueprint_assignment_table<ArithmetizationType> &assignment,
                                var max_poly_size,
                                std::array<var, 2> eval_points,
                                std::array<var, 2> powers_of_eval_points_for_chunks,
                                std::size_t &component_start_row) {
                        return std::vector<var>(0);
                    }

                    static kimchi_proof_evaluations<CurveType> assignment_combine_evaluations(blueprint_assignment_table<ArithmetizationType> &assignment,
                        const kimchi_proof_evaluations<CurveType> &proof_eval,
                        const var &proof_eval_for_chunk,
                        std::size_t &row) {
                        
                        return kimchi_proof_evaluations<CurveType>();
                    }

                    // let init = (evals[0].w[PERMUTS - 1] + gamma) * evals[1].z * alpha0 * zkp;
                    static var ft_eval_1(blueprint_assignment_table<ArithmetizationType> &assignment,
                                var eval_w,
                                var gamma,
                                var eval_z,
                                var alpha_0,
                                var zkp,
                                std::size_t &component_start_row) {

                    }
                    
                    static var ft_eval_at_zeta(blueprint_assignment_table<ArithmetizationType> &assignment,
                        std::size_t &row) {
                        
                        /*var zkpm_at_zeta = assignment_evaluate_polynomial(
                            assignment, zkpm, zeta, row);
                        var zeta1m1 = assignment_add(assignment, zeta_pow_n, -1, row);

                        // (evals[0].w[PERMUTS - 1] + gamma) * evals[1].z * alphas[0] * zkpm_at_zeta;
                        var init = ft_eval_1(evals[0].w[zk::snark::kimchi_constant::PERMUTES - 1],
                            gamma,
                            evals[1].z,
                            alpha_powers[0],
                            zkpm_at_zeta);
                        var ft_eval0 = permutation_fold(

                        );
                        var nominator;
                        var denominator;
                        ft_eval0 = assignment_add(assignment,
                            ft_eval0,
                            assignment_mul(assignment, nominator, denominator, row),
                            row);
                        var tmp = ft_eval_2(

                        );
                        ft_eval0 = assignment_sub(
                            assignment,
                            ft_eval0,
                            tmp,
                            row);*/
                        return var(0, row, false);
                    }

                public:
                    constexpr static const std::size_t selector_seed = 0x0f08;
                    constexpr static const std::size_t rows_amount = 50;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        kimchi_verifier_index_scalar<CurveType> verifier_index;
                        kimchi_proof_scalar<CurveType> proof;
                        typename BlueprintFieldType::value_type joint_combiner;
                        typename BlueprintFieldType::value_type beta; // beta and gamma can be combined from limbs in the base circuit
                        typename BlueprintFieldType::value_type gamma;
                        typename BlueprintFieldType::value_type alpha;
                        typename BlueprintFieldType::value_type zeta;
                        typename BlueprintFieldType::value_type fq_digest; // TODO overflow check
                    };

                    struct result_type {
                        struct random_oracles {
                            var joint_combiner;
                            var beta;
                            var gamma;
                            var alpha_chal;
                            var alpha;
                            var zeta;
                            var v;
                            var u;
                            var zeta_chal;
                            var v_chal;
                            var u_chal;
                        };

                        var digest;
                        random_oracles oracles;
                        std::vector<var> alpha_powers;
                        std::vector<std::vector<var>> p_eval;
                        std::array<var, 2> zeta_powers;
                        //??? polys;
                        var zeta1;
                        var ft_eval0;


                        result_type(const params_type &params,
                            const std::size_t &component_start_row) {
                        }
                    };
                    
                    static result_type generate_circuit(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t &component_start_row) {

                        generate_gates(bp, assignment, params, component_start_row);
                        generate_copy_constraints(bp, assignment, params, component_start_row);

                        return result_type(params, component_start_row);
                    }

                    static result_type generate_assignments(
                            blueprint_assignment_table<ArithmetizationType> &assignment,
                            const params_type &params,
                            const std::size_t &component_start_row) {
                            
                        std::size_t row = component_start_row;

                        // copy public input
                        var alpha = assignment.allocate_public_input(params.alpha);
                        var zeta = assignment.allocate_public_input(params.zeta);
                        var fq_digest = assignment.allocate_public_input(params.fq_digest);
                        var omega = assignment.allocate_public_input(params.verifier_index.omega);
                        var beta = assignment.allocate_public_input(params.beta);
                        var gamma = assignment.allocate_public_input(params.gamma);
                        var joint_combiner = assignment.allocate_public_input(params.joint_combiner);
                        var max_poly_size = assignment.allocate_public_input(params.verifier_index.max_poly_size);

                        std::vector<var> zkpm(params.verifier_index.zkpm.size());
                        for (std::size_t i = 0; i < zkpm.size(); i++) {
                            zkpm[i] = assignment.allocate_public_input(
                                params.verifier_index.zkpm[i]);
                        }

                        var alpha_endo = assignments_endo_scalar(assignment,
                            alpha, row);
                        
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
                        var zeta_omega_pow_n = assignment_exponentiation(assignment, zeta_omega, n, row);

                        std::vector<var> alpha_powers = assigment_element_powers(assignment, alpha, params.verifier_index.alpha_powers, row);
                        std::vector<var> omega_powers = assigment_element_powers(assignment, alpha, params.verifier_index.public_input_size, row);
                        std::vector<var> lagrange_base = assignment_lagrange(assignment, zeta, zeta_omega, omega_powers, row);

                        // TODO: check on empty public_input
                        std::array<var, 2> public_eval = assignment_puiblic_eval(assignment, params.proof.public_input, zeta_pow_n, 
                            zeta_omega_pow_n, lagrange_base, omega_powers, params.verifier_index.domain_size_inv, row);
                        transcript.absorb_evaluations_assignment(
                            assignment,
                            public_eval[0],
                            params.proof.proof_evals[0],
                            row
                        );
                        transcript.absorb_evaluations_assignment(
                            assignment,
                            public_eval[1],
                            params.proof.proof_evals[1],
                            row
                        );

                        transcript.absorb_assignment(assignment, params.proof.ft_eval, row);

                        var v_challenge = transcript.challenge_assignment(
                            assignment, row);
                        var v = assignments_endo_scalar(assignment,
                            v_challenge, row);

                        var u_challenge = transcript.challenge_assignment(
                            assignment, row);
                        var u = assignments_endo_scalar(assignment,
                            u_challenge, row);

                        std::array<var, 2> powers_of_eval_points_for_chunks = {
                            assignment_exponentiation(assignment, zeta, max_poly_size, row),
                            assignment_exponentiation(assignment, zeta_omega, max_poly_size, row),
                        };

                        std::vector<var> prev_challenges_evals = assignment_prev_chal_evals(assignment,
                            max_poly_size,
                            std::array<var, 2> {zeta, zeta_omega},
                            powers_of_eval_points_for_chunks,
                            row);

                        std::array<kimchi_proof_evaluations<CurveType>, 2> evals = {
                            assignment_combine_evaluations(assignment, params.proof.proof_evals[0],
                                powers_of_eval_points_for_chunks[0], row),
                            assignment_combine_evaluations(assignment, params.proof.proof_evals[1],
                                powers_of_eval_points_for_chunks[1], row),
                        };

                        // ft(zeta)
                        var ft_at_zeta = ft_eval_at_zeta(assignment, row);
                        
                        return result_type(params, component_start_row);
                    }

                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment, 
                            const params_type &params,
                        const std::size_t &component_start_row = 0) {
                    }

                    static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment, 
                            const params_type &params,
                            const std::size_t &component_start_row = 0){

                        std::size_t row = component_start_row;

                        /*std::array<var, 2> alpha_pub_limbs = {var(0, row, false, var::column_type::public_input), 
                                var(0, row + 1, false, var::column_type::public_input)};
                        std::array<var, 2> zeta_pub_limbs = {var(0, row + 2, false, var::column_type::public_input), 
                                var(0, row + 3, false, var::column_type::public_input)};

                        row += 4;
                        
                        copy_constraints_from_limbs(bp, assignment, alpha_pub_limbs, row);
                        row++;
                        // copy endo-scalar
                        row += endo_scalar_component::rows_amount;
                        
                        copy_constraints_from_limbs(bp, assignment, zeta_pub_limbs, row);
                        row++;
                        // copy endo-scalar
                        row += endo_scalar_component::rows_amount;*/
                        
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_ORACLES_COMPONENT_15_WIRES_HPP
