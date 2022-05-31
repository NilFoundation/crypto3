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

#ifndef CRYPTO3_ZK_BLUEPRINT_BATCH_VERIFY_BASE_FIELD_HPP
#define CRYPTO3_ZK_BLUEPRINT_BATCH_VERIFY_BASE_FIELD_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType, 
                         typename KimchiCommitmentParamsType,
                         std::size_t BatchSize,
                         std::size_t... WireIndexes>
                class batch_verify_scalar_field;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
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
                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;

                    constexpr static const std::size_t selector_seed = 0x0f28;

                    constexpr static std::size_t scalars_len() {
                        return 10;
                    }

                public:
                    constexpr static const std::size_t rows_amount = 1;

                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        
                    };

                    struct result_type {
                        var output;

                        result_type(std::size_t component_start_row) {
                        }
                    };

                    static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t start_row_index){

                        std::size_t row = start_row_index;

                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;

                        std::array<var, scalars_len()> scalars;
                        var rand_base; //todo random
                        var sg_rand_base;

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
                    //     let mut points = vec![self.h];
                    //     points.extend(self.g.clone());
                    //     points.extend(vec![G::zero(); padding]);

                    //     let mut scalars = vec![ScalarField::<G>::zero(); padded_length + 1];
                    //     assert_eq!(scalars.len(), points.len());

                    //     // sample randomiser to scale the proofs with
                    //     let rand_base = ScalarField::<G>::rand(rng);
                    //     let sg_rand_base = ScalarField::<G>::rand(rng);

                    //     let mut rand_base_i = ScalarField::<G>::one();
                    //     let mut sg_rand_base_i = ScalarField::<G>::one();

                    //     for BatchEvaluationProof {
                    //         sponge,
                    //         evaluation_points,
                    //         xi,
                    //         r,
                    //         evaluations,
                    //         opening,
                    //     } in batch.iter_mut()
                    //     {
                    //         // TODO: This computation is repeated in ProverProof::oracles
                    //         let combined_inner_product0 = {
                    //             let es: Vec<_> = evaluations
                    //                 .iter()
                    //                 .map(
                    //                     |Evaluation {
                    //                         commitment,
                    //                         evaluations,
                    //                         degree_bound,
                    //                     }| {
                    //                         let bound: Option<usize> = (|| {
                    //                             let b = (*degree_bound)?;
                    //                             let x = commitment.shifted?;
                    //                             if x.is_zero() {
                    //                                 None
                    //                             } else {
                    //                                 Some(b)
                    //                             }
                    //                         })();
                    //                         (evaluations.clone(), bound)
                    //                     },
                    //                 )
                    //                 .collect();
                    //             combined_inner_product::<G>(evaluation_points, xi, r, &es, self.g.len())
                    //         };

                    //         sponge.absorb_fr(&[shift_scalar::<G>(combined_inner_product0)]);

                    //         let t = sponge.challenge_fq();
                    //         let u: G = to_group(group_map, t);

                    //         let Challenges { chal, chal_inv } =
                    //             opening.challenges::<EFqSponge>(&self.endo_r, sponge);

                    //         sponge.absorb_g(&[opening.delta]);
                    //         let c = ScalarChallenge(sponge.challenge()).to_field(&self.endo_r);

                    //         // < s, sum_i r^i pows(evaluation_point[i]) >
                    //         // ==
                    //         // sum_i r^i < s, pows(evaluation_point[i]) >
                    //         let b0 = {
                    //             let mut scale = ScalarField::<G>::one();
                    //             let mut res = ScalarField::<G>::zero();
                    //             for &e in evaluation_points.iter() {
                    //                 let term = b_poly(&chal, e);
                    //                 res += &(scale * term);
                    //                 scale *= *r;
                    //             }
                    //             res
                    //         };

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

                    //         rand_base_i *= &rand_base;
                    //         sg_rand_base_i *= &sg_rand_base;
                    //     }

                    //     // verify the equation
                    //     let scalars: Vec<_> = scalars.iter().map(|x| x.into_repr()).collect();
                    //     VariableBaseMSM::multi_scalar_mul(&points, &scalars) == G::Projective::zero()
                    // }

                        return result_type(component_start_row);
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

#endif    // CRYPTO3_ZK_BLUEPRINT_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP