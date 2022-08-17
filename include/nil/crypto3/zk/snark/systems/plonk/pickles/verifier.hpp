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
#include <nil/crypto3/zk/snark/systems/plonk/pickles/proof.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/constants.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/constraints.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kimchi_pedersen.hpp>
#include <nil/crypto3/zk/transcript/kimchi_transcript.hpp>


#include <nil/crypto3/math/polynomial/polynomial.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename CurveType, std::size_t WiresAmount>
                struct verifier{
                    typedef commitments::kimchi_pedersen<CurveType> commitment_scheme;
                    typedef typename commitment_scheme::commitment_type commitment_type;
                    typedef typename commitment_scheme::evaluation_type evaluation_type;
                    typedef typename CurveType::scalar_field_type scalar_field_type; // Fr;
                    typedef typename CurveType::base_field_type base_field_type; // Fq;
                    typedef typename commitment_scheme::batchproof_type batchproof_type;

                    typedef typename commitment_scheme::sponge_type EFqSponge;
                    typedef transcript::DefaultFrSponge<CurveType> EFrSponge;

                    constexpr static const COLUMNS = kimchi_constant::COLUMNS;
                    constexpr static const PERMUTS = kimchi_constant::PERMUTS;

                    batchproof_type<CurveType>
                    to_batch(verifier_index<CurveType> index, prover_proof<CurveType> proof) {
                        //~
                        //~ #### Partial verification
                        //~
                        //~ For every proof we want to verify, we defer the proof opening to the very end.
                        //~ This allows us to potentially batch verify a number of partially verified proofs.
                        //~ Essentially, this steps verifies that $f(\zeta) = t(\zeta) * Z_H(\zeta)$.
                        //~

                        //~ 1. Commit to the negated public input polynomial.
                        BOOST_ASSERT_MSG(index.srs.lagrange_bases.contains(index.domain.size(), "pre-computed committed lagrange bases not found"));
                        std::vector<typename scalar_field_type::value_type> lgr_comm = index.srs.lagrange_bases[index.domain.size()];    // calculate lgr_comm
                        // BOOST_ASSERT(lgr_comm.size() == 512);                          // ??
                        std::vector<commitment_type> com;

                        for (size_t i = 0; i < proof.public_input.size(); ++i) {
                            com.push_back(commitment_type(lgr_comm[i], 0));
                        }
                        // std::vector<commitment_scheme> *com_ref = &com;
                        std::vector<typename scalar_field_type::value_type> elm;
                        for (auto i : &proof.public_input) {
                            elm.push_back(-i);
                        }

                        commitment_type p_comm = commitment_type::multi_scalar_mul(com, elm);

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
                            proof.evals[0].combine(oracles_res.powers_of_eval_points_for_chunks[0]),
                            proof.evals[1].combine(oracles_res.powers_of_eval_points_for_chunks[1])
                        };

                        //~ 4. Compute the commitment to the linearized polynomial $f$.
                        // permutation
                        typename scalar_field_type::value_type zkp = index.zkpm.evaluate(oracles_res.oracles.zeta);

                        std::vector<typename scalar_field_type::value_type> alphas = oracles_res.all_alphas.get_alphas(kimchi_constants::CONSTRAINTS);

                        std::vector<commitment_type> commitments = {index.sigma_comm[PERMUTS - 1]};
                        std::vector<typename scalar_field_type::value_type> scalars = {ConstraintSystem::perm_scalars(evals, oracles_res.oracles.beta,
                                                                                oracles_res.oracles.gamma, alphas, zkp)};

                        // generic
                    
                        std::vector<typename scalar_field_type::value_type> generic_scalars =
                            ConstraintSystem::gnrc_scalars(alphas, evals[0].w, evals[0].generic_selector);

                        std::vector<commitment_type> generic_com(
                            index.coefficients_comm.begin(), index.coefficients_comm.begin() + generic_scalars.size());

                        BOOST_ASSERT(generic_scalars.size() == generic_com.size());

                        scalars.insert(scalars.end(), generic_scalars.begin(), generic_scalars.end());
                        commitments.insert(commitments.end(), generic_com.begin(), generic_com.end());
                    

                        // other gates are implemented using the expression framework
                        {
                            // TODO: Reuse constants from oracles function
                            Constants<typename scalar_field_type::value_type constants = {
                                                oracles_res.oracles.alpha,
                                                oracles_res.oracles.beta,
                                                oracles_res.oracles.gamma,
                                                oracles_res.oracles.joint_combiner,
                                                index.endo,
                                                index.fr_sponge_params.mds
                                            };

                            for (auto i : index.linearization.index_terms) {
                                auto col = i[0];
                                auto tokens = i[1];

                                auto scalar =
                                    PolishToken::evaluate(tokens, index.domain, oracles_res.oracles.zeta, evals, constants);
                                auto l = proof.commitments.lookup;
                                if (col.column == Column::Witness) {
                                    scalars.push(scalar);
                                    commitments.push(&proof.commitments.w_comm[col.witness_value]);
                                }
                                else if (col.column == Column::Coefficient) {
                                    scalars.push(scalar);
                                    commitments.push(&index.coefficients_comm[col.coefficient_value]);
                                }
                                else if (col.column == Column::Z) {
                                    scalars.push(scalar);
                                    commitments.push(&proof.commitments.z_comm);
                                }
                                else if (col.column == Column::LookupSorted) {
                                    scalars.push(scalar);
                                    commitments.push(l.sorted[col.lookup_sorted_value]);
                                }
                                else if (col.column == Column::LookupAggreg) {
                                    scalars.push(scalar);
                                    commitments.push(l.aggreg);
                                }
                                else if (col.column == Column::LookupKindIndex) {
                                    if (index.lookup_index_is_used) {
                                        // assert("Attempted to use, but no lookup index was given");
                                    } else {
                                        scalars.push(scalar);
                                        commitments.push(index.lookup_index.lookup_selectors[col.lookup_kind_index_value]);
                                    }
                                }
                                else if (col.column == Column::LookupTable) {
                                    if (index.lookup_index_is_used) {
                                        // assert("Attempted to use, but no lookup index was given");
                                    } else {
                                        scalar_field_type::value_type j = scalar_field_type::value_type::one();
                                        scalars.push(scalar);
                                        commitments.push(index.lookup_index.lookup_table[0]);
                                        for (size_t k = 1; k < index.lookup_index.lookup_table.size(); ++k) {
                                            k *= constants.joint_combiner;
                                            scalars.push_back(scalar * k);
                                            commitments.push(index.lookup_index.lookup_table[k]);
                                        }
                                    }
                                }
                                else if (col.column == Column::Index) {
                                    commitment_type c;
                                    if(col.index_value == gate_type::Zero || col.index_value == gate_type::Generic || col.index_value == gate_type::Lookup){
                                        std::cout << "Selector for {:?} not defined\n";
                                    }
                                    else if(col.index_value == gate_type::CompleteAdd){
                                        c = index.complete_add_comm;
                                    }
                                    else if(col.index_value == gate_type::VarBaseMul){
                                        c = index.mul_comm;
                                    }
                                    else if(col.index_value == gate_type::EndoMul){
                                        c = index.emul_comm;
                                    }
                                    else if(col.index_value == gate_type::EndoMulScalar){
                                        c = index.endomul_scalar_comm;
                                    }
                                    else if(col.index_value == gate_type::Poseidon){
                                        c = index.psm_comm;
                                    }
                                    else if(col.index_value == gate_type::ChaCha0){
                                        c = index.chacha_comm[0];
                                    }
                                    else if(col.index_value == gate_type::ChaCha1){
                                        c = index.chacha_comm[1];
                                    }
                                    else if(col.index_value == gate_type::ChaCha2){
                                        c = index.chacha_comm[2];
                                    }
                                    else if(col.index_value == gate_type::ChaChaFinal){
                                        c = index.chacha_comm[3];
                                    }
                                    else if(col.index_value == gate_type::RangeCheck0){
                                        c = index.range_check_comm;
                                    }
                                    else if(col.index_value == gate_type::RangeCheck1){
                                        c = index.range_check_comm;
                                    }
                                    

                                    scalars.push(scalar);
                                    commitments.push(c);
                                }
                            }
                        }

                        // MSM
                        commitment_type f_comm = PolyComm::multi_scalar_mul(commitments, scalars);

                            //~ 5. Compute the (chuncked) commitment of $ft$
                            //~    (see [Maller's optimization](../crypto/plonk/maller_15.html)).
                        scalar_field_type::value_type zeta_to_srs_len = oracles_res.oracles.zeta.pow(index.max_poly_size);
                        commitment_type chunked_f_comm = f_comm.chunk_commitment(zeta_to_srs_len);
                        commitment_type chunked_t_comm = proof.commitments.t_comm.chunk_commitment(zeta_to_srs_len);
                        commitment_type ft_comm = chunked_f_comm - chunked_t_comm.scale(oracles_res.zeta1 - scalar_field_type::value_type::one());

                        //~ 6. List the polynomial commitments, and their associated evaluations,
                        //~    that are associated to the aggregated evaluation proof in the proof:
                        std::vector<typename evaluation_type> evaluations;

                        //~     - recursion
                        for (auto i : oracles_res.polys) {
                            evaluations.emplace_back(i[0], i[1], -1);
                        }

                        //~     - public input commitment
                        evaluations.emplace_back(p_comm, oracles_res.p_eval, -1);

                        //~     - ft commitment (chunks of it)
                        evaluations.emplace_back(ft_comm, {{oracles_res.ft_eval0}, {proof.ft_eval1}}, -1);

                        //~     - permutation commitment
                        std::vector<std::vector<scalar_field_type::value_type>> tmp_evals;
                        for (auto i : proof.evals) {
                            tmp_evals.push_back(i.z);
                        }
                        evaluations.emplace_back(proof.commitments.z_comm, tmp_evals, -1);

                        //~     - index commitments that use the coefficients
                        tmp_evals.clear();
                        for (auto i : proof.evals) {
                            tmp_evals.push_back(i.generic_selector);
                        }
                        evaluations.emplace_back(index.generic_comm, tmp_evals, -1);

                        tmp_evals.clear();
                        for (auto i : proof.evals) {
                            tmp_evals.push_back(i.poseidon_selector);
                        }
                        evaluations.emplace_back(index.psm_comm, tmp_evals, -1);

                        //~     - witness commitments
                        for (size_t i = 0; i < COLUMNS; ++i) {
                            evaluations.emplace_back(proof.commitments.w_comm[i], {proof.evals[0].w[i], proof.evals[1].w[i]}, -1);
                        }

                        //~     - sigma commitments
                        for (size_t i = 0; i < PERMUTS - 1; ++i) {
                            evaluations.emplace_back(index.sigma_comm[i], {proof.evals[0].s[i], proof.evals[1].s[i]}, -1);
                        }

                        if(index.lookup_index_is_used){
                            std::size_t lookup_len = std::min({
                                proof.commitments.lookup.size(),
                                proof.evals[0].lookup.size(),
                                proof.evals[1].lookup.size(),
                            });

                            for(int i = 0; i < lookup_len; ++i){
                                evaluations.emplace_back(
                                    proof.commitments.lookup.sorted[i],
                                    {proof.evals[0].lookup.sorted[i], proof.evals[1].lookup.sorted[i]},
                                    -1,
                                );
                            }

                            evaluations.emplace_back(
                                proof.commitments.lookup.aggreg,
                                {proof.evals[0].lookup.aggreg, proof.evals[1].lookup.aggreg},
                                -1,
                            );

                            typename commitment_type table_comm = lookup_verifier_index::combine_table(
                                        index.lookup_index.lookup_table,
                                        oracles.joint_combiner.value(),
                                        oracles.joint_combiner.value().pow(index.lookup_index.max_joint_size),
                                        index.lookup_index.table_ids,
                                        proof.commitments.lookup.runtime
                            );

                            evaluations.emplace_back(
                                table_comm,
                                {proof.evals[0].lookup.table, proof.evals[1].lookup.table},
                                -1
                            );

                            if(index.lookup_index.runtime_tables_selector_is_used){
                                evaluations.emplace_back(
                                    index.lookup_index.runtime,
                                    {proof.evals[0].lookup.runtime, proof.evals[1].lookup.runtime},
                                    -1
                                );
                            }
                        }

                        // prepare for the opening proof verification
                        std::vector<scalar_field_type::value_type> evaluation_points = {oracles_res.oracles.zeta,
                                                            oracles_res.oracles.zeta * index.domain.omega};
                        return batchproof_type = {
                            oracles_res.fq_sponge, 
                            evaluations, 
                            evaluation_points,
                            oracles_res.oracles.v, 
                            oracles_res.oracles.u, 
                            proof.proof
                        };
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_BATCHED_PICKLES_VERIFIER_HPP
