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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_ORACLES_SCALAR_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_ORACLES_SCALAR_COMPONENT_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/element_powers.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/lagrange_denominators.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/public_evaluations.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/prev_chal_evals.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/combine_proof_evals.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/verifier_index.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/transcript_fr.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/endo_scalar.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/exponentiation.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/pickles/constants.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, typename KimchiParamsType, 
                    typename KimchiCommitmentParamsType, std::size_t... WireIndexes>
                class oracles_scalar;

                template<typename ArithmetizationParams, typename CurveType, typename KimchiParamsType,  
                         typename KimchiCommitmentParamsType, std::size_t W0, std::size_t W1,
                         std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7,
                         std::size_t W8, std::size_t W9, std::size_t W10, std::size_t W11, std::size_t W12,
                         std::size_t W13, std::size_t W14>
                class oracles_scalar<
                    snark::plonk_constraint_system<typename CurveType::scalar_field_type, ArithmetizationParams>,
                    CurveType, KimchiParamsType, KimchiCommitmentParamsType, 
                    W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    using BlueprintFieldType = typename CurveType::scalar_field_type;

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t selector_seed = 0x0f08;

                    using endo_scalar_component =
                        zk::components::endo_scalar<ArithmetizationType, CurveType, W0, W1, W2, W3, W4, W5, W6, W7, W8,
                                                    W9, W10, W11, W12, W13, W14>;
                    using from_limbs = zk::components::from_limbs<ArithmetizationType, CurveType, W0, W1, W2>;

                    using exponentiation_component =
                        zk::components::exponentiation<ArithmetizationType, 60, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9,
                                                       W10, W11, W12, W13, W14>;
                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    
                    using alpha_powers_component = zk::components::element_powers<ArithmetizationType, KimchiParamsType::alpha_powers_n, 0, 1, 2, 3,
                                                                          4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

                    using pi_powers_component = zk::components::element_powers<ArithmetizationType, KimchiParamsType::public_input_size, 0, 1, 2, 3,
                                                                          4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

                    using lagrange_denominators_component =
                            zk::components::lagrange_denominators<ArithmetizationType, KimchiParamsType::public_input_size, W0, W1, W2, W3, W4,
                                                                    W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using public_eval_component =
                            zk::components::public_evaluations<ArithmetizationType, 
                                                        KimchiParamsType::public_input_size, W0, W1, W2, W3,
                                                        W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using prev_chal_evals_component =
                            zk::components::prev_chal_evals<ArithmetizationType, 
                                                        KimchiCommitmentParamsType, W0, W1, W2, W3,
                                                        W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                                        
                    using combined_proof_evals_component =
                            zk::components::combine_proof_evals<ArithmetizationType, 
                                                        KimchiParamsType, W0, W1, W2, W3,
                                                        W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    constexpr static const std::size_t eval_points_amount = 2;

                    struct field_op_component {
                        // TODO: change to add / sub
                        using add = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                        using sub = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    };

                    static var assignments_endo_scalar(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                       var scalar,
                                                       std::size_t &component_start_row) {

                        typename BlueprintFieldType::value_type endo_factor =
                            0x12CCCA834ACDBA712CAAD5DC57AAB1B01D1F8BD237AD31491DAD5EBDFDFE4AB9_cppui255;
                        std::size_t num_bits = 128;
                        // TODO endo_scalar component has to get variable as scalar param

                        typename endo_scalar_component::params_type params = {scalar, endo_factor, num_bits};
                        typename endo_scalar_component::result_type endo_scalar_res =
                            endo_scalar_component::generate_assignments(assignment, params, component_start_row);
                        component_start_row += endo_scalar_component::rows_amount;
                        return endo_scalar_res.output;
                    }

                    static var assignment_exponentiation(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                         var base,
                                                         var power,
                                                         var zero,
                                                         var one,
                                                         std::size_t &component_start_row) {
                        typename exponentiation_component::params_type params = {base, power, zero, one};
                        typename exponentiation_component::result_type res =
                            exponentiation_component::generate_assignments(assignment, params, component_start_row);
                        component_start_row += exponentiation_component::rows_amount;
                        return res.result;
                    }

                    static var assigment_multiplication(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                        var x,
                                                        var y,
                                                        std::size_t &component_start_row) {
                        typename mul_component::params_type params = {x, y};
                        typename mul_component::result_type res =
                            mul_component::generate_assignments(assignment, params, component_start_row);
                        component_start_row += mul_component::rows_amount;
                        return res.output;
                    }

                    static std::vector<var>
                        assignment_prev_chal_evals(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                   var max_poly_size,
                                                   std::array<var, eval_points_amount>
                                                       eval_points,
                                                   std::array<var, eval_points_amount>
                                                       powers_of_eval_points_for_chunks,
                                                   std::size_t &component_start_row) {
                        return std::vector<var>(0);
                    }

                public:
                    constexpr static const std::size_t rows_amount = 200;
                    constexpr static const std::size_t gates_amount = 1;

                    struct params_type {
                        struct fq_sponge_output {
                            var joint_combiner;
                            var beta;    // beta and gamma can be combined from limbs in the base circuit
                            var gamma;
                            var alpha;
                            var zeta;
                            var fq_digest;    // TODO overflow check

                            static fq_sponge_output
                                allocate_fq_output(blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                   typename BlueprintFieldType::value_type joint_combiner,
                                                   typename BlueprintFieldType::value_type beta,
                                                   typename BlueprintFieldType::value_type gamma,
                                                   typename BlueprintFieldType::value_type alpha,
                                                   typename BlueprintFieldType::value_type zeta,
                                                   typename BlueprintFieldType::value_type fq_digest) {

                                return fq_sponge_output {
                                    assignment.allocate_public_input(joint_combiner),
                                    assignment.allocate_public_input(beta),
                                    assignment.allocate_public_input(gamma),
                                    assignment.allocate_public_input(alpha),
                                    assignment.allocate_public_input(zeta),
                                    assignment.allocate_public_input(fq_digest),
                                };
                            }
                        };

                        kimchi_verifier_index_scalar<CurveType> verifier_index;
                        kimchi_proof_scalar<CurveType, KimchiParamsType,
                            KimchiCommitmentParamsType::eval_rounds> proof;
                        fq_sponge_output fq_output;
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
                        std::array<var, eval_points_amount> zeta_powers;
                        //??? polys;
                        var zeta1;
                        var ft_eval0;

                        result_type(const params_type &params, std::size_t component_start_row) {
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {
                        auto selector_iterator = assignment.find_selector(selector_seed);
                        std::size_t first_selector_index;

                        if (selector_iterator == assignment.selectors_end()) {
                            first_selector_index = assignment.allocate_selector(selector_seed, gates_amount);
                            generate_gates(bp, assignment, params, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }

                        std::size_t row = start_row_index;

                        typename BlueprintFieldType::value_type endo_factor =
                            0x12CCCA834ACDBA712CAAD5DC57AAB1B01D1F8BD237AD31491DAD5EBDFDFE4AB9_cppui255;
                        std::size_t endo_num_bits = 128;
                        // alpha = phi(alpha_challenge)
                        var alpha = endo_scalar_component::generate_circuit(
                            bp, assignment, {params.fq_output.alpha, endo_factor, endo_num_bits}, row).output;
                        row += endo_scalar_component::rows_amount;
                        // zeta = phi(zeta_challenge)
                        var zeta = endo_scalar_component::generate_circuit(
                            bp, assignment, {params.fq_output.zeta, endo_factor, endo_num_bits}, row).output;
                        row += endo_scalar_component::rows_amount;

                        // fr_transcript.absorb(fq_digest)
                        var zero = var(0, 0, false, var::column_type::constant);
                        var one = var(0, 1, false, var::column_type::constant);
                        kimchi_transcript<ArithmetizationType, CurveType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10,
                                          W11, W12, W13, W14>
                            transcript;
                        transcript.init_circuit(bp, assignment, zero, row);
                        transcript.absorb_circuit(bp, assignment, params.fq_output.fq_digest, row);

                        // zeta_pow_n = zeta**n
                        var zeta_pow_n = exponentiation_component::generate_circuit(
                                             bp, assignment,
                                             {zeta, params.verifier_index.domain_size, zero, one}, row)
                                             .result;
                        row += exponentiation_component::rows_amount;

                        var zeta_omega = zk::components::generate_circuit<mul_component>(bp, assignment,
                           {zeta, params.verifier_index.omega}, row).output;
                        row += mul_component::rows_amount;

                        var zeta_omega_pow_n = 
                            exponentiation_component::generate_circuit(bp, assignment, 
                            {zeta_omega, params.verifier_index.domain_size, zero, one}, row).result;
                        row += exponentiation_component::rows_amount;

                        std::array<var, KimchiParamsType::alpha_powers_n> alpha_powers =
                            alpha_powers_component::generate_circuit(bp, assignment, 
                            {alpha, one}, row).output;
                        row += alpha_powers_component::rows_amount;

                        std::array<var, KimchiParamsType::public_input_size> omega_powers =
                            pi_powers_component::generate_circuit(bp, assignment, 
                            {params.verifier_index.omega, one}, row).output;
                        row += pi_powers_component::rows_amount;

                        std::array<var, eval_points_amount * KimchiParamsType::public_input_size> lagrange_denominators =
                                            lagrange_denominators_component::generate_circuit(bp, assignment,
                                                {zeta, zeta_omega, omega_powers, one}, row).output;
                        row += lagrange_denominators_component::rows_amount;

                        // TODO: check on empty public_input
                        std::array<var, KimchiParamsType::public_input_size> pi = params.proof.public_input;
                        std::array<var, eval_points_amount> public_eval = public_eval_component::generate_circuit(bp,
                            assignment, {zeta_pow_n, zeta_omega_pow_n, 
                                        pi,
                                        lagrange_denominators, 
                                        omega_powers,
                                        params.verifier_index.domain_size, one, zero}, row).output;
                        row += public_eval_component::rows_amount;

                        // transcript.absorb_evaluations_circuit(
                        //     bp, assignment, public_eval[0], params.proof.proof_evals[0], row);
                        // transcript.absorb_evaluations_circuit(
                        //     bp, assignment, public_eval[1], params.proof.proof_evals[1], row);

                        //transcript.absorb_circuit(assignment, params.proof.ft_eval, row);

                        // var v_challenge = transcript.challenge_circuit(bp, assignment, row);
                        // var v = endo_scalar_component::generate_circuit(
                        //     bp, assignment, {v_challenge, endo_factor, endo_num_bits}, row).output;
                        // row += endo_scalar_component::rows_amount;

                        // var u_challenge = transcript.challenge_circuit(bp, assignment, row);
                        // var u = endo_scalar_component::generate_circuit(
                        //     bp, assignment, {u_challenge, endo_factor, endo_num_bits}, row).output;
                        // row += endo_scalar_component::rows_amount;


                        std::array<var, eval_points_amount> powers_of_eval_points_for_chunks;
                        powers_of_eval_points_for_chunks[0] = exponentiation_component::generate_circuit(
                                             bp, assignment,
                                             {zeta, params.verifier_index.max_poly_size, zero, one}, row)
                                             .result;
                        row += exponentiation_component::rows_amount;
                        powers_of_eval_points_for_chunks[1] = exponentiation_component::generate_circuit(
                                             bp, assignment,
                                             {zeta_omega, params.verifier_index.max_poly_size, zero, one}, row)
                                             .result;
                        row += exponentiation_component::rows_amount;

                        std::array<var, KimchiCommitmentParamsType::eval_rounds> prev_challenges =
                            params.proof.prev_challenges;
                        std::array<std::array<var, KimchiCommitmentParamsType::res_size>, eval_points_amount> 
                            prev_challenges_evals = 
                            prev_chal_evals_component::generate_circuit(bp, assignment,
                                {prev_challenges, 
                                {{zeta, zeta_omega}},
                                powers_of_eval_points_for_chunks, 
                                one, zero}, row).output;
                        row += prev_chal_evals_component::rows_amount;

                        std::array<kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>,
                            eval_points_amount> combined_evals;
                        for (std::size_t i = 0; i < eval_points_amount; i++) {
                            combined_evals[i] = combined_proof_evals_component::generate_circuit(
                                bp, assignment, {params.proof.proof_evals[i], 
                                powers_of_eval_points_for_chunks[i]}, row).output;
                            row += combined_proof_evals_component::rows_amount;
                        }

                        std::cout<<"row:"<<row<<std::endl;

                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        return result_type(params, start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t component_start_row) {

                        std::size_t row = component_start_row;

                        // copy public input
                        std::vector<var> zkpm(params.verifier_index.zkpm.size());
                        for (std::size_t i = 0; i < zkpm.size(); i++) {
                            zkpm[i] = assignment.allocate_public_input(params.verifier_index.zkpm[i]);
                        }

                        var fq_digest = params.fq_output.fq_digest;
                        var beta = params.fq_output.beta;
                        var gamma = params.fq_output.gamma;
                        var joint_combiner = params.fq_output.joint_combiner;

                        var alpha = assignments_endo_scalar(assignment, params.fq_output.alpha, row);
                        std::cout << "alpha: " << assignment.var_value(alpha).data << std::endl;
                        var zeta = assignments_endo_scalar(assignment, params.fq_output.zeta, row);
                        std::cout << "zeta: " << assignment.var_value(zeta).data << std::endl;
                        std::cout << "params.fq_output.zeta: " << assignment.var_value(params.fq_output.zeta).data << std::endl;

                        var zero = var(0, 0, false, var::column_type::constant);
                        var one = var(0, 1, false, var::column_type::constant);
                        assignment.constant(0)[0] = 0;    // set zero constant
                        assignment.constant(0)[1] = 1;    // set one constant

                        kimchi_transcript<ArithmetizationType, CurveType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10,
                                          W11, W12, W13, W14>
                            transcript;
                        transcript.init_assignment(assignment, row);
                        transcript.absorb_assignment(assignment, fq_digest, row);

                        var n = params.verifier_index.domain_size;
                        var zeta_pow_n = assignment_exponentiation(assignment, zeta, n, zero, one, row);

                        var zeta_omega = assigment_multiplication(assignment, zeta, params.verifier_index.omega, row);
                        var zeta_omega_pow_n = assignment_exponentiation(assignment, zeta_omega, n, zero, one, row);

                        std::array<var, KimchiParamsType::alpha_powers_n> alpha_powers = alpha_powers_component::generate_assignments(
                            assignment, {alpha, one}, row).output;
                        row += alpha_powers_component::rows_amount;

                        std::array<var, KimchiParamsType::public_input_size> omega_powers =
                            pi_powers_component::generate_assignments(assignment, 
                            {params.verifier_index.omega, one}, row).output;
                        row += pi_powers_component::rows_amount;

                        std::array<var, eval_points_amount * KimchiParamsType::public_input_size> lagrange_denominators = 
                                    lagrange_denominators_component::generate_assignments(assignment,
                                    {zeta, zeta_omega, omega_powers, one}, row).output;
                        row += lagrange_denominators_component::rows_amount;

                        // TODO: check on empty public_input
                        std::array<var, KimchiParamsType::public_input_size> pi = params.proof.public_input;
                        std::array<var, eval_points_amount> public_eval = public_eval_component::generate_assignments(
                            assignment, {zeta_pow_n, zeta_omega_pow_n, 
                                        pi,
                                        lagrange_denominators, 
                                        omega_powers,
                                        n, one, zero}, row).output;
                        row += public_eval_component::rows_amount;
                        
                        // transcript.absorb_evaluations_assignment(
                        //     assignment, public_eval[0], params.proof.proof_evals[0], row);
                        // transcript.absorb_evaluations_assignment(
                        //     assignment, public_eval[1], params.proof.proof_evals[1], row);

                        // transcript.absorb_assignment(assignment, params.proof.ft_eval, row);

                        // var v_challenge = transcript.challenge_assignment(assignment, row);
                        // var v = assignments_endo_scalar(assignment, v_challenge, row);

                        // var u_challenge = transcript.challenge_assignment(assignment, row);
                        // var u = assignments_endo_scalar(assignment, u_challenge, row);

                        std::array<var, eval_points_amount> powers_of_eval_points_for_chunks = {
                            assignment_exponentiation(assignment, zeta, params.verifier_index.max_poly_size, zero, one, row),
                            assignment_exponentiation(assignment, zeta_omega, params.verifier_index.max_poly_size, zero, one, row),
                        };

                        std::array<var, KimchiCommitmentParamsType::eval_rounds> prev_challenges =
                            params.proof.prev_challenges;
                        std::array<std::array<var, KimchiCommitmentParamsType::res_size>, eval_points_amount> 
                            prev_challenges_evals = 
                            prev_chal_evals_component::generate_assignments(assignment,
                                {prev_challenges, 
                                {{zeta, zeta_omega}},
                                powers_of_eval_points_for_chunks, 
                                one, zero}, row).output;
                        row += prev_chal_evals_component::rows_amount;

                        std::array<kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>,
                            eval_points_amount> combined_evals;
                        for (std::size_t i = 0; i < eval_points_amount; i++) {
                            combined_evals[i] = combined_proof_evals_component::generate_assignments(
                                assignment, {params.proof.proof_evals[i], 
                                powers_of_eval_points_for_chunks[i]}, row).output;
                            row += combined_proof_evals_component::rows_amount;
                        }

                        std::cout<<"assignment row: "<<row<<std::endl;

                        // let polys: Vec<(PolyComm<G>, _)> = self
                        //     .prev_challenges
                        //     .iter()
                        //     .zip(self.prev_chal_evals(index, &ep, &powers_of_eval_points_for_chunks))
                        //     .map(|(c, e)| (c.1.clone(), e))
                        //     .collect();
                        //self.prev_challenges
                        //         .iter()

                        // std::vector<var> prev_challenges_evals =
                        //     assignment_prev_chal_evals(assignment,
                        //                                max_poly_size,
                        //                                std::array<var, eval_points_amount> {zeta, zeta_omega},
                        //                                powers_of_eval_points_for_chunks,
                        //                                row);

                        // std::array<kimchi_proof_evaluations<CurveType>, eval_points_amount> evals = {
                        //     assignment_combine_evaluations(assignment, params.proof.proof_evals[0],
                        //                                    powers_of_eval_points_for_chunks[0], row),
                        //     assignment_combine_evaluations(assignment, params.proof.proof_evals[1],
                        //                                    powers_of_eval_points_for_chunks[1], row),
                        // };

                        // // ft(zeta)
                        // var ft_at_zeta = ft_eval_at_zeta(assignment, row);

                        return result_type(params, component_start_row);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               std::size_t component_start_row = 0) {
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  std::size_t component_start_row = 0) {

                        std::size_t row = component_start_row;
                        
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_ORACLES_SCALAR_COMPONENT_HPP
