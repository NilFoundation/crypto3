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

#include <nil/crypto3/zk/snark/systems/plonk/pickles/detail.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/alphas.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/verifier_index.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kimchi_pedersen.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType, std::size_t WiresAmount>
                batch_evaluation_proof<CurveType>
                to_batch(verifier_index<CurveType> index, commitments::kimchi_pedersen<CurveType> proof) {
                    typedef commitments::kimchi_pedersen<CurveType> commitment_scheme;
                    typedef typename commitments::kimchi_pedersen<CurveType>::commitment_type commitment_type;
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
                    std::vector<CurveType> lgr_comm = index.srs.lagrange_bases;    // calculate lgr_comm
                    BOOST_ASSERT(lgr_comm.size() == 512);                          // ??
                    std::vector<commitment_scheme> com;
                    for (size_t i = 0; i < proof.public_p.size(); ++i) {
                        com.push_back(commitment_scheme(lgr_comm[i], 0));
                    }
                    std::vector<commitment_scheme> *com_ref = &com;
                    std::vector<CurveType> elm;
                    for (auto i : &proof.public_p) {
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

                    // Calculate polynoms in pointers powers_of_eval_points_for_chunks[0] and
                    // powers_of_eval_points_for_chunks[1]
                    std::array<typename commitment_scheme::proof_type, 2> evals = {
                        combine<CurveType>(proof.evals[0], oracles_res.powers_of_eval_points_for_chunks[0]),
                        combine<CurveType>(proof.evals[1], oracles_res.powers_of_eval_points_for_chunks[1])};

                    //~ 4. Compute the commitment to the linearized polynomial $f$.
                    // permutation
                    Fr zkp = index.zkpm.evaluate(oracles_res.oracles.zeta);

                    std::vector<Fr> alphas = oracles_res.all_alphas.get_alphas(CONSTRAINTS);

                    std::vector<commitment_type> commitments = index.sigma_comm[PERMUTS - 1];
                    std::vector<Fr> scalars = ConstraintSystem::perm_scalars(evals, oracles_res.oracles.beta,
                                                                             oracles_res.oracles.gamma, alphas, zkp);

                    // generic
                    {
                        std::vector<Fr> generic_scalars =
                            ConstraintSystem::gnrc_scalars(alphas, evals[0].w, evals[0].generic_selector);

                        std::vector<commitment_type> generic_com(
                            index.coefficients_comm.begin(), index.coefficients_comm.begin() + generic_scalars.size());

                        BOOST_ASSERT(generic_scalars.size() == generic_com.size());

                        scalars.insert(scalars.end(), generic_scalars.begin(), generic_scalars.end());
                        commitments.commitments(commitments.end(), generic_com.begin(), generic_com.end());
                    }

                    // other gates are implemented using the expression framework
                    {
                        // TODO: Reuse constants from oracles function
                        Constants constants = {oracles_res.oracles.alpha,
                                               oracles_res.oracles.beta,
                                               oracles_res.oracles.gamma,
                                               oracles_res.oracles.joint_combiner,
                                               index.endo,
                                               index.fr_sponge_params.mds};

                        for (auto i : index.linearization.index_terms) {
                            auto col = i[0];
                            auto tokens = i[1];

                            auto scalar =
                                PolishToken::evaluate(tokens, index.domain, oracles_res.oracles.zeta, evals, constants);
                            auto l = proof.commitments.lookup;
                            if (col == Column::Witness) {
                                scalars.push(scalar);
                                commitments.push(&proof.commitments.w_comm[*i]);
                            }
                            if (col == Column::Coefficient) {
                                scalars.push(scalar);
                                commitments.push(&index.coefficients_comm[*i]);
                            }
                            if (col == Column::Z) {
                                scalars.push(scalar);
                                commitments.push(&proof.commitments.z_comm);
                            }
                            if (col == Column::LookupSorted) {
                                scalars.push(scalar);
                                commitments.push(&l.unwrap().sorted[*i]);
                            }
                            if (col == Column::LookupAggreg) {
                                scalars.push(scalar);
                                commitments.push(&l.unwrap().aggreg);
                            }
                            if (col == Column::LookupKindIndex) {
                                if (index.lookup_index == 0) {
                                    assert("Attempted to use, but no lookup index was given");
                                } else {
                                    scalars.push(scalar);
                                    commitments.push(index.lookup_index.lookup_selectors[*i]);
                                }
                            }
                            if (col == Column::LookupTable) {
                                if (index.lookup_index == 0) {
                                    assert("Attempted to use, but no lookup index was given");
                                } else {
                                    Fr j = Fr::one();
                                    scalars.push(scalar);
                                    commitments.push(index.lookup_index.lookup_table[0]);
                                    for (size_t k = 1; k < index.lookup_index.lookup_table.size(); ++k) {
                                        k *= constants.joint_combiner;
                                        scalars.push_back(scalar * k);
                                        commitments.push(index.lookup_index.lookup_table[k]);
                                    }
                                }
                            }
                            if (col == Column::Index) {
                                let c = match t {
                                    Zero | Generic = > panic !("Selector for {:?} not defined", t),
                                    CompleteAdd = > &index.complete_add_comm,
                                    VarBaseMul = > &index.mul_comm,
                                    EndoMul = > &index.emul_comm,
                                    EndoMulScalar = > &index.endomul_scalar_comm,
                                    Poseidon = > &index.psm_comm,
                                    ChaCha0 = > &index.chacha_comm.as_ref().unwrap()[0],
                                    ChaCha1 = > &index.chacha_comm.as_ref().unwrap()[1],
                                    ChaCha2 = > &index.chacha_comm.as_ref().unwrap()[2],
                                    ChaChaFinal = > &index.chacha_comm.as_ref().unwrap()[3],
                                };
                                scalars.push(scalar);
                                commitments.push(c);
                            }
                        }
                    }

                    // MSM
                    commitment_type f_comm = PolyComm::multi_scalar_mul(&commitments, &scalars);

                        //~ 5. Compute the (chuncked) commitment of $ft$
                        //~    (see [Maller's optimization](../crypto/plonk/maller_15.html)).
                    Fr zeta_to_srs_len = oracles_res.oracles.zeta.pow(index.max_poly_size);
                    commitment_type chunked_f_comm = f_comm.chunk_commitment(zeta_to_srs_len);
                    commitment_type chunked_t_comm = proof.commitments.t_comm.chunk_commitment(zeta_to_srs_len);
                    commitment_type ft_comm = chunked_f_comm - chunked_t_comm.scale(oracles_res.zeta1 - Fr::one());

                    //~ 6. List the polynomial commitments, and their associated evaluations,
                    //~    that are associated to the aggregated evaluation proof in the proof:
                    std::vector<Evaluation<CurveType>> evaluations;

                    //~     - recursion
                    for (auto i : oracles_res.polys) {
                        evaluations.push_back({i[0], i[1], 0});
                    }

                    //~     - public input commitment
                    evaluations.push_back({p_comm, oracles_res.p_eval, 0});

                    //~     - ft commitment (chunks of it)
                evaluations.push_back({ft_comm, {{oracles_res.ft_eval0]}, {proof.ft_eval1}}, 0});

                //~     - permutation commitment
                std::vector<std::vector<Fr>> tmp_evals;
                for (auto i : proof.evals) {
                    tmp_evals.push_back(i.z);
                }
                evaluations.push_back({proof.commitments.z_comm, tmp_evals, 0});

                //~     - index commitments that use the coefficients
                tmp_evals.clear();
                for (auto i : proof.evals) {
                    tmp_evals.push_back(i.generic_selector);
                }
                evaluations.push_back({index.generic_comm, tmp_evals, 0});

                tmp_evals.clear();
                for (auto i : proof.evals) {
                    tmp_evals.push_back(i.poseidon_selector);
                }
                evaluations.push_back({index.psm_comm, tmp_evals, 0});

                //~     - witness commitments
                for (size_t i = 0; i < COLUMNS; ++i) {
                    evaluations.push_back({proof.commitments.w_comm[i], {proof.evals[0].w[i], proof.evals[1].w[i]}, 0});
                }

                //~     - sigma commitments
                for (size_t i = 0; i < PERMUTS - 1; ++i) {
                    evaluations.push_back({index.sigma_comm[i], {proof.evals[0].s[i], proof.evals[1].s[i]}, 0});
                }

                // prepare for the opening proof verification
                std::vector<Fr> evaluation_points = {oracles_res.oracles.zeta,
                                                     oracles_res.oracles.zeta * index.domain.group_gen};
                return batch_evaluation_proof {oracles_res.fq_sponge, evaluations,           evaluation_points,
                                             oracles_res.oracles.v, oracles_res.oracles.u, proof.proof};
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_BATCHED_PICKLES_VERIFIER_HPP
