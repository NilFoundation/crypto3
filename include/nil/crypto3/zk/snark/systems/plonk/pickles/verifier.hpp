//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_BATCHED_PICKLES_VERIFIER_HPP
#define CRYPTO3_ZK_PLONK_BATCHED_PICKLES_VERIFIER_HPP

#include <nil/crypto3/zk/snark/commitments/kzg.hpp>
#include <nil/crypto3/zk/snark/arithmetization/constraint_satisfaction_problems/r1cs.hpp>
#include <nil/crypto3/zk/snark/commitments/polynmomial/pedersen.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template <typename CurveType, std::size_t WiresAmount>
                BatchEvaluationProof to_batch(VerifierIndex<CurveType> index, pedersen_commitment_scheme<CurveType> proof) {
                    typedef pedersen_commitment_scheme<CurveType> commitment_scheme;
                    using Fr = typename CurveType::scalar_field_type;
                    using Fq = typename CurveType::base_field_type;
                    //~
                    //~ #### Partial verification
                    //~
                    //~ For every proof we want to verify, we defer the proof opening to the very end.
                    //~ This allows us to potentially batch verify a number of partially verified proofs.
                    //~ Essentially, this steps verifies that $f(\zeta) = t(\zeta) * Z_H(\zeta)$.
                    //~

                    //~ 1. Commit to the negated public input polynomial.
                    std::vector<CurveType> lgr_comm = index.srs.lagrange_bases; // calculate lgr_comm
                    BOOST_ASSERT(lgr_comm.size() == 512); // ??
                    std::vector<commitment_scheme> com;
                    for (size_t i = 0; i < proof.public_p.size(); ++i) {
                        com.push_back(commitment_scheme(lgr_comm[i], 0));
                    }
                    std::vector<commitment_scheme> *com_ref = &com;
                    std::vector<CurveType> elm;
                    for (auto i: &proof.public_p) {
                        elm.push_back(-i);
                    }

                    commitment_scheme p_comm = typename commitment_scheme::multi_scalar_mul(&com_ref, &elm);


                    //~ 2. Run the [Fiat-Shamir argument](#fiat-shamir-argument).
                    OraclesResult<CurveType, EFqSponge, WiresAmount> oracles_res = oracles(proof, index, p_comm);
//                        fq_sponge,
//                        oracles,
//                        all_alphas,
//                        p_eval,
//                        powers_of_eval_points_for_chunks,
//                        polys,
//                        zeta1 : zeta_to_domain_size,
//                        ft_eval0,
//                        ..> = proof.oracles::<EFqSponge, EFrSponge>(index, &p_comm);

                    //~ 3. Combine the chunked polynomials' evaluations
                    //~    (TODO: most likely only the quotient polynomial is chunked)
                    //~    with the right powers of $\zeta^n$ and $(\zeta * \omega)^n$.

                    // Calculate polynoms in pointers powers_of_eval_points_for_chunks[0] and powers_of_eval_points_for_chunks[1]
//                    let evals = vec ![
//                        proof.evals[0].combine(powers_of_eval_points_for_chunks[0]),
//                        proof.evals[1].combine(powers_of_eval_points_for_chunks[1]),
//                    ];
                    // begin
                    nil::crypto3::math::polynomial<G> w_zeta_polynomial(proof.w_zeta);
                    auto w_zeta_eval = w_zeta_polunomial.evaluate(powers_of_eval_points_for_chunks[0]);
                    nil::crypto3::math::polynomial<G> w_zeta_omega_polynomial(proof.w_zeta);
                    auto w_zeta_omega_eval = w_zeta_polunomial.evaluate(powers_of_eval_points_for_chunks[1]);

                    nil::crypto3::math::polynomial<G> z_zeta_polynomial(proof.w_zeta);
                    auto z_zeta_eval = z_zeta_polunomial.evaluate(powers_of_eval_points_for_chunks[0]);
                    nil::crypto3::math::polynomial<G> z_zeta_omega_polynomial(proof.w_zeta);
                    auto z_zeta_omega_eval = z_zeta_polunomial.evaluate(powers_of_eval_points_for_chunks[1]);

                    nil::crypto3::math::polynomial<G> S_zeta_polynomial(proof.w_zeta);
                    auto S_zeta_eval = S_zeta_polunomial.evaluate(powers_of_eval_points_for_chunks[0]);
                    nil::crypto3::math::polynomial<G> S_zeta_omega_polynomial(proof.w_zeta);
                    auto S_zeta_omega_eval = S_zeta_polunomial.evaluate(powers_of_eval_points_for_chunks[1]);
                    // end this step

                    //~ 4. Compute the commitment to the linearized polynomial $f$.
                   let f_comm = {
                    // permutation
                    Fr zkp = index.zkpm.evaluate(oracles_res.oracles.zeta);

                    let alphas = all_alphas.get_alphas(permutation::CONSTRAINTS);

                    let mut commitments = vec![&index.sigma_comm[PERMUTS - 1]];
                    let mut scalars = vec![ConstraintSystem::perm_scalars(
                        &evals,
                        oracles.beta,
                        oracles.gamma,
                        alphas,
                        zkp,
                    )];

                    // generic
                    {
                        let alphas =
                            all_alphas.get_alphas(generic::CONSTRAINTS);

                        let generic_scalars =
                            &ConstraintSystem::gnrc_scalars(alphas, &evals[0].w, evals[0].generic_selector);

                        let generic_com = index.coefficients_comm.iter().take(generic_scalars.len());

                        assert_eq!(generic_scalars.len(), generic_com.len());

                        scalars.extend(generic_scalars);
                        commitments.extend(generic_com);
                    }

                    // other gates are implemented using the expression framework
                    {
                        // TODO: Reuse constants from oracles function
                        Constants constants = {
                            alpha = oracles_res.oracles.alpha,
                            beta = oracles_res.oracles.beta,
                            gamma = oracles_res.oracles.gamma,
                            joint_combiner = oracles_res.oracles.joint_combiner.1,
                            endo_coefficient = index.endo,
                            mds = index.fr_sponge_params.mds,
                        };

                        for (col, tokens) in &index.linearization.index_terms {
                            let scalar =
                                PolishToken::evaluate(tokens, index.domain, oracles.zeta, &evals, &constants)
                                    .expect("should evaluate");
                            let l = proof.commitments.lookup.as_ref();
                            use Column::*;
                            match col {
                                Witness(i) => {
                                    scalars.push(scalar);
                                    commitments.push(&proof.commitments.w_comm[*i])
                                }
                                Coefficient(i) => {
                                    scalars.push(scalar);
                                    commitments.push(&index.coefficients_comm[*i])
                                }
                                Z => {
                                    scalars.push(scalar);
                                    commitments.push(&proof.commitments.z_comm);
                                }
                                LookupSorted(i) => {
                                    scalars.push(scalar);
                                    commitments.push(&l.unwrap().sorted[*i])
                                }
                                LookupAggreg => {
                                    scalars.push(scalar);
                                    commitments.push(&l.unwrap().aggreg)
                                }
                                LookupKindIndex(i) => match index.lookup_index.as_ref() {
                                    None => {
                                        panic!("Attempted to use {:?}, but no lookup index was given", col)
                                    }
                                    Some(lindex) => {
                                        scalars.push(scalar);
                                        commitments.push(&lindex.lookup_selectors[*i]);
                                    }
                                },
                                LookupTable => match index.lookup_index.as_ref() {
                                    None => {
                                        panic!("Attempted to use {:?}, but no lookup index was given", col)
                                    }
                                    Some(lindex) => {
                                        let mut j = Fr::<G>::one();
                                        scalars.push(scalar);
                                        commitments.push(&lindex.lookup_table[0]);
                                        for t in lindex.lookup_table.iter().skip(1) {
                                            j *= constants.joint_combiner;
                                            scalars.push(scalar * j);
                                            commitments.push(t);
                                        }
                                    }
                                },
                                Index(t) => {
                                    use GateType::*;
                                    let c = match t {
                                        Zero | Generic => panic!("Selector for {:?} not defined", t),
                                        CompleteAdd => &index.complete_add_comm,
                                        VarBaseMul => &index.mul_comm,
                                        EndoMul => &index.emul_comm,
                                        EndoMulScalar => &index.endomul_scalar_comm,
                                        Poseidon => &index.psm_comm,
                                        ChaCha0 => &index.chacha_comm.as_ref().unwrap()[0],
                                        ChaCha1 => &index.chacha_comm.as_ref().unwrap()[1],
                                        ChaCha2 => &index.chacha_comm.as_ref().unwrap()[2],
                                        ChaChaFinal => &index.chacha_comm.as_ref().unwrap()[3],
                                    };
                                    scalars.push(scalar);
                                    commitments.push(c);
                                }
                            }
                        }
                    }

                    // MSM
                    PolyComm::multi_scalar_mul(&commitments, &scalars)
                };

                //~ 5. Compute the (chuncked) commitment of $ft$
                //~    (see [Maller's optimization](../crypto/plonk/maller_15.html)).
                let ft_comm = {
                    let zeta_to_srs_len = oracles.zeta.pow(&[index.max_poly_size as u64]);
                    let chunked_f_comm = f_comm.chunk_commitment(zeta_to_srs_len);
                    let chunked_t_comm = &proof.commitments.t_comm.chunk_commitment(zeta_to_srs_len);
                    &chunked_f_comm - &chunked_t_comm.scale(zeta_to_domain_size - Fr::<G>::one())
                };

                //~ 6. List the polynomial commitments, and their associated evaluations,
                //~    that are associated to the aggregated evaluation proof in the proof:
                let mut evaluations = vec![];

                //~     - recursion
                evaluations.extend(polys.into_iter().map(|(c, e)| Evaluation {
                    commitment: c,
                    evaluations: e,
                    degree_bound: None,
                }));

                //~     - public input commitment
                evaluations.push(Evaluation {
                    commitment: p_comm,
                    evaluations: p_eval,
                    degree_bound: None,
                });

                //~     - ft commitment (chunks of it)
                evaluations.push(Evaluation {
                    commitment: ft_comm,
                    evaluations: vec![vec![ft_eval0], vec![proof.ft_eval1]],
                    degree_bound: None,
                });

                //~     - permutation commitment
                evaluations.push(Evaluation {
                    commitment: proof.commitments.z_comm.clone(),
                    evaluations: proof.evals.iter().map(|e| e.z.clone()).collect(),
                    degree_bound: None,
                });

                //~     - index commitments that use the coefficients
                evaluations.push(Evaluation {
                    commitment: index.generic_comm.clone(),
                    evaluations: proof
                        .evals
                        .iter()
                        .map(|e| e.generic_selector.clone())
                        .collect(),
                    degree_bound: None,
                });
                evaluations.push(Evaluation {
                    commitment: index.psm_comm.clone(),
                    evaluations: proof
                        .evals
                        .iter()
                        .map(|e| e.poseidon_selector.clone())
                        .collect(),
                    degree_bound: None,
                });

                //~     - witness commitments
                evaluations.extend(
                    proof
                        .commitments
                        .w_comm
                        .iter()
                        .zip(
                            (0..COLUMNS)
                                .map(|i| {
                                    proof
                                        .evals
                                        .iter()
                                        .map(|e| e.w[i].clone())
                                        .collect::<Vec<_>>()
                                })
                                .collect::<Vec<_>>(),
                        )
                        .map(|(c, e)| Evaluation {
                            commitment: c.clone(),
                            evaluations: e,
                            degree_bound: None,
                        }),
                );

                //~     - sigma commitments
                evaluations.extend(
                    index
                        .sigma_comm
                        .iter()
                        .zip(
                            (0..PERMUTS - 1)
                                .map(|i| {
                                    proof
                                        .evals
                                        .iter()
                                        .map(|e| e.s[i].clone())
                                        .collect::<Vec<_>>()
                                })
                                .collect::<Vec<_>>(),
                        )
                        .map(|(c, e)| Evaluation {
                            commitment: c.clone(),
                            evaluations: e,
                            degree_bound: None,
                        }),
                );

                // prepare for the opening proof verification
                let evaluation_points = vec![oracles.zeta, oracles.zeta * index.domain.group_gen];
                Ok(BatchEvaluationProof {
                    sponge: fq_sponge,
                    evaluations,
                    evaluation_points,
                    xi: oracles.v,
                    r: oracles.u,
                    opening: &proof.proof,
                })
            }
}    // namespace snark
}    // namespace zk
}    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_BATCHED_PICKLES_VERIFIER_HPP
