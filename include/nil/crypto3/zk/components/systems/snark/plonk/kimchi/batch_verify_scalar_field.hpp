//---------------------------------------------------------------------------//
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the BATCH_VERIFY_SCALAR_FIELD component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_BATCH_VERIFY_SCALAR_FIELD_HPP
#define CRYPTO3_ZK_BLUEPRINT_BATCH_VERIFY_SCALAR_FIELD_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>

#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/combined_inner_product.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/proof.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/batch_scalar/random.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/batch_scalar/prepare_scalars.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles_scalar/b_poly.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles_scalar/b_poly_coefficients.hpp>

#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/endo_scalar.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // batched polynomial commitment verification (scalar field)
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/poly-commitment/src/commitment.rs#L610
                // Input: list of batch evaluation proofs
                //      https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/verifier.rs#L881-L888
                // Output: list of scalars for MSM in batch verify base
                template<typename ArithmetizationType, 
                         typename CurveType,
                         typename KimchiParamsType,
                         typename KimchiCommitmentParamsType,
                         std::size_t BatchSize,
                         std::size_t... WireIndexes>
                class batch_verify_scalar_field;

                template<typename BlueprintFieldType,
                         typename CurveType,
                         typename ArithmetizationParams,
                         typename KimchiParamsType,
                         typename KimchiCommitmentParamsType,
                         std::size_t BatchSize,
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
                class batch_verify_scalar_field<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                                       CurveType,
                                                       KimchiParamsType,
                                                       KimchiCommitmentParamsType,
                                                       BatchSize,
                                                       W0,
                                                       W1,
                                                       W2,
                                                       W3,
                                                       W4,
                                                       W5,
                                                       W6,
                                                       W7,
                                                       W8,
                                                       W9,
                                                       W10,
                                                       W11,
                                                       W12,
                                                       W13,
                                                       W14 > {

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;
                    

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;
                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;

                    using random_component = zk::components::random<ArithmetizationType, 
                        W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using endo_scalar_component =
                        zk::components::endo_scalar<ArithmetizationType, CurveType, 
                            KimchiParamsType::scalar_challenge_size, 
                                W0, W1, W2, W3, W4, W5, W6, W7, W8,
                                W9, W10, W11, W12, W13, W14>;

                    using b_poly_component = zk::components::b_poly<ArithmetizationType, 
                        KimchiCommitmentParamsType::eval_rounds, W0, W1, W2, W3, W4, W5,
                        W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    using b_poly_coeff_component = zk::components::b_poly_coefficients<ArithmetizationType, 
                        KimchiCommitmentParamsType::eval_rounds, W0, W1, W2, W3, W4, W5,
                        W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    constexpr static std::size_t scalars_len() {
                        return 10;
                    }
                    
                    using prepare_scalars_component =
                        zk::components::prepare_scalars<ArithmetizationType, scalars_len(), W0, W1, W2, W3, W4, W5, W6, W7, W8,
                                                    W9, W10, W11, W12, W13, W14>;

                    using batch_proof = batch_evaluation_proof_scalar<BlueprintFieldType, 
                        ArithmetizationType, KimchiParamsType, KimchiCommitmentParamsType>;

                    constexpr static const std::size_t selector_seed = 0x0f28;

                    constexpr static const std::size_t srs_len = KimchiCommitmentParamsType::srs_len;
                    constexpr static const std::size_t eval_rounds = KimchiCommitmentParamsType::eval_rounds;

                public:
                    constexpr static const std::size_t rows_amount = 240;

                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::array<batch_proof, BatchSize> batches;
                    };

                    struct result_type {
                        std::array<var, scalars_len()> output;

                        result_type(std::size_t start_row_index) {
                        }
                    };

                    static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t start_row_index){

                        generate_assignments_constant(bp, assignment, params, start_row_index);

                        std::size_t row = start_row_index;

                        var zero = var(0, start_row_index, false, var::column_type::constant);
                        var one = var(0, start_row_index + 1, false, var::column_type::constant);

                        std::array<var, scalars_len()> scalars;
                        
                        var rand_base = random_component::generate_circuit(
                            bp, assignment, {one}, row).output;
                        row += random_component::rows_amount;
                        var sg_rand_base = random_component::generate_circuit(
                            bp, assignment, {one}, row).output;
                        row += random_component::rows_amount;

                        var rand_base_i = one;
                        var sg_rand_base_i = one;

                        for (std::size_t batch_id = 0; batch_id < params.batches.size(); batch_id++) {
                            var cip = params.batches[batch_id].cip;

                            std::array<std::array<var, eval_rounds>, 2> challenges;
                            for (std::size_t j = 0; j < eval_rounds; j++) {
                                challenges[0][j] = endo_scalar_component::generate_circuit(
                                    bp, assignment, 
                                    {params.batches[batch_id].fq_output.challenges[j]},
                                    row).output;
                                row += endo_scalar_component::rows_amount;

                                challenges[1][j] = zk::components::generate_circuit<sub_component>(
                                    bp, assignment, {zero, challenges[0][j]}, row).output;
                                row += sub_component::rows_amount;
                            }

                            var c = endo_scalar_component::generate_circuit(
                                    bp, assignment, 
                                    {params.batches[batch_id].fq_output.c},
                                    row).output;
                            row += endo_scalar_component::rows_amount;

                            var b0_scale = one;
                            var b0 = zero;

                            for (std::size_t i = 0; i < KimchiParamsType::eval_points_amount; i++) {
                                var term = b_poly_component::generate_circuit(
                                    bp, assignment, 
                                    {challenges[0], params.batches[batch_id].eval_points[i],
                                    one}, row).output;
                                row += b_poly_component::rows_amount;
                                
                                var tmp = zk::components::generate_circuit<mul_component>(
                                    bp, assignment, {b0_scale, term}, row).output;
                                row += mul_component::rows_amount;

                                b0 = zk::components::generate_circuit<add_component>(
                                    bp, assignment, {b0, tmp}, row).output;
                                row += add_component::rows_amount;

                                b0_scale = zk::components::generate_circuit<mul_component>(
                                    bp, assignment, {b0_scale, params.batches[batch_id].r}, row).output;
                                row += mul_component::rows_amount;
                            }

                            rand_base_i = zk::components::generate_circuit<mul_component>(
                                bp, assignment,
                                {rand_base_i, rand_base}, row).output;
                            row += mul_component::rows_amount;

                            sg_rand_base_i = zk::components::generate_circuit<mul_component>(
                                bp, assignment,
                                {sg_rand_base_i, sg_rand_base}, row).output;
                            row += mul_component::rows_amount;
                        }

                        scalars = prepare_scalars_component::generate_circuit(bp, assignment,
                            {scalars}, row).output;
                        row += prepare_scalars_component::rows_amount;

                        std::cout<<"circuit row: "<<row<<std::endl;

                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t start_row_index) {
                        std::size_t row = start_row_index;

                        typename BlueprintFieldType::value_type endo_factor =
                            0x12CCCA834ACDBA712CAAD5DC57AAB1B01D1F8BD237AD31491DAD5EBDFDFE4AB9_cppui255;
                        std::size_t endo_num_bits = 128;

                        var zero = var(0, start_row_index, false, var::column_type::constant);
                        var one = var(0, start_row_index + 1, false, var::column_type::constant);

                        std::array<var, scalars_len()> scalars;
                        var rand_base = random_component::generate_assignments(
                            assignment, {one}, row).output;
                        row += random_component::rows_amount;
                        var sg_rand_base = random_component::generate_assignments(
                            assignment, {one}, row).output;
                        row += random_component::rows_amount;

                        var rand_base_i = one;
                        var sg_rand_base_i = one;

                        for (std::size_t batch_id = 0; batch_id < params.batches.size(); batch_id++) {
                            var cip = params.batches[batch_id].cip;

                            std::array<std::array<var, eval_rounds>, 2> challenges;
                            for (std::size_t j = 0; j < eval_rounds; j++) {
                                challenges[0][j] = endo_scalar_component::generate_assignments(
                                    assignment, 
                                    {params.batches[batch_id].fq_output.challenges[j]},
                                    row).output;
                                row += endo_scalar_component::rows_amount;

                                challenges[1][j] = sub_component::generate_assignments(
                                    assignment, {zero, challenges[0][j]}, row).output;
                                row += sub_component::rows_amount;
                            }

                            var c = endo_scalar_component::generate_assignments(
                                    assignment, 
                                    {params.batches[batch_id].fq_output.c},
                                    row).output;
                            row += endo_scalar_component::rows_amount;

                            var b0_scale = one;
                            var b0 = zero;

                            for (std::size_t i = 0; i < KimchiParamsType::eval_points_amount; i++) {
                                var term = b_poly_component::generate_assignments(
                                    assignment, 
                                    {challenges[0], params.batches[batch_id].eval_points[i],
                                    one}, row).output;
                                row += b_poly_component::rows_amount;
                                
                                var tmp = mul_component::generate_assignments(
                                    assignment, {b0_scale, term}, row).output;
                                row += mul_component::rows_amount;

                                b0 = add_component::generate_assignments(
                                    assignment, {b0, tmp}, row).output;
                                row += add_component::rows_amount;

                                b0_scale = mul_component::generate_assignments(
                                    assignment, {b0_scale, params.batches[batch_id].r}, row).output;
                                row += mul_component::rows_amount;
                            }

                            rand_base_i = mul_component::generate_assignments(assignment,
                                {rand_base_i, rand_base}, row).output;
                            row += mul_component::rows_amount;

                            sg_rand_base_i = mul_component::generate_assignments(assignment,
                                {sg_rand_base_i, sg_rand_base}, row).output;
                            row += mul_component::rows_amount;
                        }

                    //     // Verifier checks for all i,
                    //     // c_i Q_i + delta_i = z1_i (G_i + b_i U_i) + z2_i H
                    //     //
                    //     // if we sample r at random, it suffices to check
                    //     //
                    //     // 0 == sum_i r^i (c_i Q_i + delta_i - ( z1_i (G_i + b_i U_i) + z2_i H ))
                    //     //
                    //     // and because each G_i is a multiexp on the same array self.g, we
                    //     // can batch the multiexp across proofs.
                    //     //
                    //     // So for each proof in the batch, we add onto our big multiexp the following terms
                    //     // r^i c_i Q_i
                    //     // r^i delta_i
                    //     // - (r^i z1_i) G_i
                    //     // - (r^i z2_i) H
                    //     // - (r^i z1_i b_i) U_i

                    //     // We also check that the sg component of the proof is equal to the polynomial commitment
                    //     // to the "s" array

                    //     let nonzero_length = self.g.len();

                    //     let max_rounds = math::ceil_log2(nonzero_length);

                    //     let padded_length = 1 << max_rounds;

                    //     // TODO: This will need adjusting
                    //     let padding = padded_length - nonzero_length;

                    //     let mut scalars = vec![ScalarField::<G>::zero(); padded_length + 1];

                    //     for BatchEvaluationProof {
                    //         sponge,
                    //         evaluation_points,
                    //         xi,
                    //         r,
                    //         evaluations,
                    //         opening,
                    //     } in batch.iter_mut()
                    //     {

                    //         let s = b_poly_coefficients(&chal);

                    //         let neg_rand_base_i = -rand_base_i;

                    //         // TERM
                    //         // - rand_base_i z1 G
                    //         //
                    //         // we also add -sg_rand_base_i * G to check correctness of sg.
                    //         points.push(opening.sg);
                    //         scalars.push(neg_rand_base_i * opening.z1 - sg_rand_base_i);

                    //         // Here we add
                    //         // sg_rand_base_i * ( < s, self.g > )
                    //         // =
                    //         // < sg_rand_base_i s, self.g >
                    //         //
                    //         // to check correctness of the sg component.
                    //         {
                    //             let terms: Vec<_> = s.par_iter().map(|s| sg_rand_base_i * s).collect();

                    //             for (i, term) in terms.iter().enumerate() {
                    //                 scalars[i + 1] += term;
                    //             }
                    //         }

                    //         // TERM
                    //         // - rand_base_i * z2 * H
                    //         scalars[0] -= &(rand_base_i * opening.z2);

                    //         // TERM
                    //         // -rand_base_i * (z1 * b0 * U)
                    //         scalars.push(neg_rand_base_i * (opening.z1 * b0));
                    //         points.push(u);

                    //         // TERM
                    //         // rand_base_i c_i Q_i
                    //         // = rand_base_i c_i
                    //         //   (sum_j (chal_invs[j] L_j + chals[j] R_j) + P_prime)
                    //         // where P_prime = combined commitment + combined_inner_product * U
                    //         let rand_base_i_c_i = c * rand_base_i;
                    //         for ((l, r), (u_inv, u)) in opening.lr.iter().zip(chal_inv.iter().zip(chal.iter())) {
                    //             points.push(*l);
                    //             scalars.push(rand_base_i_c_i * u_inv);

                    //             points.push(*r);
                    //             scalars.push(rand_base_i_c_i * u);
                    //         }

                    //         // TERM
                    //         // sum_j r^j (sum_i xi^i f_i) (elm_j)
                    //         // == sum_j sum_i r^j xi^i f_i(elm_j)
                    //         // == sum_i xi^i sum_j r^j f_i(elm_j)
                    //         {
                    //             let mut xi_i = ScalarField::<G>::one();

                    //             for Evaluation {
                    //                 commitment,
                    //                 degree_bound,
                    //                 ..
                    //             } in evaluations
                    //                 .iter()
                    //                 .filter(|x| !x.commitment.unshifted.is_empty())
                    //             {
                    //                 // iterating over the polynomial segments
                    //                 for comm_ch in commitment.unshifted.iter() {
                    //                     scalars.push(rand_base_i_c_i * xi_i);
                    //                     points.push(*comm_ch);

                    //                     xi_i *= *xi;
                    //                 }

                    //                 if let Some(_m) = degree_bound {
                    //                     if let Some(comm_ch) = commitment.shifted {
                    //                         if !comm_ch.is_zero() {
                    //                             // xi^i sum_j r^j elm_j^{N - m} f(elm_j)
                    //                             scalars.push(rand_base_i_c_i * xi_i);
                    //                             points.push(comm_ch);

                    //                             xi_i *= *xi;
                    //                         }
                    //                     }
                    //                 }
                    //             }
                    //         };

                    //         scalars.push(rand_base_i_c_i * combined_inner_product0);
                    //         points.push(u);

                    //         scalars.push(rand_base_i);
                    //         points.push(opening.delta);
                    //     }

                        scalars = prepare_scalars_component::generate_assignments(assignment,
                            {scalars}, row).output;
                        row += prepare_scalars_component::rows_amount;

                        std::cout<<"assignment row: "<<row<<std::endl;

                        return result_type(start_row_index);
                    }

                private:

                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const params_type &params,
                        const std::size_t first_selector_index) {
                        
                    }

                    static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t start_row_index) {
                        std::size_t row = start_row_index;

                    }

                    static void
                        generate_assignments_constant(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  std::size_t component_start_row) {
                            std::size_t row = component_start_row;
                            assignment.constant(0)[row] = 0;
                            row++;
                            assignment.constant(0)[row] = 1;
                            row++;
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_BATCH_VERIFY_SCALAR_FIELD_HPP