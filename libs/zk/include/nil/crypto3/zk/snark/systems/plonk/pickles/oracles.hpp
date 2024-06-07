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

#ifndef CRYPTO3_ZK_PLONK_BATCHED_PICKLES_ORACLES_HPP
#define CRYPTO3_ZK_PLONK_BATCHED_PICKLES_ORACLES_HPP

#include <nil/crypto3/zk/snark/systems/plonk/pickles/detail.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/verifier_index.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/proof.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/expr.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/constants.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kimchi_pedersen.hpp>

#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>

#include <map>
#include <algorithm>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType>
                struct RandomOracles {
                    std::tuple<ScalarChallenge<FieldType>, typename FieldType::value_type> joint_combiner;
                    typename FieldType::value_type beta;
                    typename FieldType::value_type gamma;
                    ScalarChallenge<FieldType> alpha_chal;
                    typename FieldType::value_type alpha;
                    typename FieldType::value_type zeta;
                    typename FieldType::value_type v;
                    typename FieldType::value_type u;
                    ScalarChallenge<FieldType> zeta_chal;
                    ScalarChallenge<FieldType> v_chal;
                    ScalarChallenge<FieldType> u_chal;
                };

                template<typename CurveType, typename EFqSponge>
                struct OraclesResult {
                    typedef commitments::kimchi_pedersen<CurveType> commitment_scheme;
                    typedef typename commitments::kimchi_pedersen<CurveType>::commitment_type commitment_type;
                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    typedef typename CurveType::base_field_type base_field_type;
                    /// A sponge that acts on the base field of a curve
                    EFqSponge fq_sponge;
                    /// the last evaluation of the Fq-Sponge in this protocol
                    typename scalar_field_type::value_type digest;
                    /// the challenges produced in the protocol
                    RandomOracles<scalar_field_type> oracles;
                    /// the computed powers of alpha
                    Alphas<scalar_field_type> all_alphas;
                    /// public polynomial evaluations
                    std::vector<std::vector<typename scalar_field_type::value_type>> p_eval;
                    /// zeta^n and (zeta * omega)^n
                    std::array<typename scalar_field_type::value_type, 2> powers_of_eval_points_for_chunks;
                    /// ?
                    std::vector<std::tuple<commitment_type, std::vector<std::vector<typename scalar_field_type::value_type>>>> polys;
                    /// pre-computed zeta^n
                    typename scalar_field_type::value_type zeta1;
                    /// The evaluation f(zeta) - t(zeta) * Z_H(zeta)
                    typename scalar_field_type::value_type ft_eval0;
                    typename scalar_field_type::value_type combined_inner_product;
                };

                template<typename CurveType, typename VerifierIndexType = verifier_index<CurveType>>
                std::vector<std::vector<std::vector<typename CurveType::scalar_field_type::value_type>>>
                prev_chal_evals(
                        proof_type<CurveType> proof,
                        VerifierIndexType index,
                        std::vector<typename CurveType::scalar_field_type::value_type> evaluation_points,
                        std::array<typename CurveType::scalar_field_type::value_type, 2> powers_of_eval_points_for_chunks) {
                    typedef commitments::kimchi_pedersen<CurveType> commitment_scheme;
                    typedef typename CurveType::scalar_field_type scalar_field_type; // Fr
                    typedef typename CurveType::base_field_type base_field_type; // Fq

                    std::vector<std::vector<std::vector<typename scalar_field_type::value_type>>> prev_chal_evals;

                    for (auto &[chals, comm]: proof.prev_challenges) {
                        std::size_t b_len = 1 << chals.size();
                        std::vector<typename scalar_field_type::value_type> b;
                        prev_chal_evals.push_back(std::vector<std::vector<typename scalar_field_type::value_type>>());

                        for (int i = 0; i < evaluation_points.size(); ++i) {
                            // prev_chal_evals.back().push_back(std::vector<typename scalar_field_type::value_type>());
                            typename scalar_field_type::value_type full = commitment_scheme::b_poly(chals,
                                                                                                    evaluation_points[i]);
                            if (index.max_poly_size == b_len) {
                                std::vector<typename scalar_field_type::value_type> vec_full = {full};
                                prev_chal_evals.back().emplace_back(vec_full);
                            } else {
                                typename scalar_field_type::value_type betaacc = scalar_field_type::value_type::one();
                                typename scalar_field_type::value_type diff;

                                for (std::size_t j = index.max_poly_size; j < b_len; ++j) {
                                    typename scalar_field_type::value_type b_j;
                                    if (b.empty()) {
                                        b = commitment_scheme::b_poly_coefficents(chals);
                                    }
                                    b_j = b[j];

                                    diff += betaacc * b[j];
                                    betaacc *= evaluation_points[i];
                                }
                                std::vector<typename scalar_field_type::value_type> tmp_vec = {
                                        full - (diff * powers_of_eval_points_for_chunks[i]), diff,
                                };

                                prev_chal_evals.back().emplace_back(tmp_vec);
                            }
                        }
                    }

                    return prev_chal_evals;
                }

                /// This function runs the random oracle argument
                template<typename CurveType, typename EFqSponge, typename EFrSponge, typename VerifierIndexType = verifier_index<CurveType>>
                OraclesResult<CurveType, EFqSponge> oracles(proof_type<CurveType> proof,
                                                            VerifierIndexType index,
                                                            typename commitments::kimchi_pedersen<CurveType>::commitment_type p_comm) {
                    typedef commitments::kimchi_pedersen<CurveType> commitment_scheme;
                    typedef typename commitment_scheme::commitment_type commitment_type;
                    typedef typename commitment_scheme::evaluation_type evaluation_type;
                    typedef typename CurveType::scalar_field_type scalar_field_type; // Fr
                    typedef typename CurveType::base_field_type base_field_type; // Fq
                    //~
                    //~ #### Fiat-Shamir argument
                    //~
                    //~ We run the following algorithm:
                    //~
                    size_t n = index.domain.size();

                    //~typename CurveType::scalar_field_type; 1. Setup the Fq-Sponge.
                    EFqSponge fq_sponge;

                    //~ 2. Absorb the commitment of the public input polynomial with the Fq-Sponge.
                    fq_sponge.absorb_g(p_comm.unshifted);

                    //~ 3. Absorb the commitments to the registers / witness columns with the Fq-Sponge.
                    for (auto &commit: proof.commitments.w_comm) {
                        fq_sponge.absorb_g(commit.unshifted);
                    }

                    std::tuple<ScalarChallenge<typename CurveType::scalar_field_type>,
                            typename CurveType::scalar_field_type::value_type>
                            joint_combiner;
                    if (index.lookup_index_is_used) {
                        BOOST_ASSERT_MSG(proof.commitments.lookup_is_used, "lookup should be in proof commitments");

                        if (index.lookup_index.runtime_tables_selector_is_used) {
                            BOOST_ASSERT_MSG(proof.commitments.lookup.runtime_is_used,
                                             "lookup runtime should be in proof commitments");
                            fq_sponge.absorb_g(proof.commitments.lookup.runtime.unshifted);
                        }

                        ScalarChallenge<typename CurveType::scalar_field_type> s;

                        if (index.lookup_index.lookup_used == lookup_verifier_index<CurveType>::lookups_used::Single) {
                            s = ScalarChallenge<typename CurveType::scalar_field_type>(
                                    CurveType::scalar_field_type::value_type::zero());
                        } else if (index.lookup_index.lookup_used ==
                                   lookup_verifier_index<CurveType>::lookups_used::Joint) {
                            s = ScalarChallenge<typename CurveType::scalar_field_type>(fq_sponge.challenge());
                        }

                        joint_combiner = std::make_tuple(s, s.to_field(index.srs.endo_r));

                        for (auto &commit: proof.commitments.lookup.sorted) {
                            fq_sponge.absorb_g(commit.unshifted);
                        }
                    }
                    //~ 4. TODO: lookup (joint combiner challenge)

                    //~ 5. TODO: lookup (absorb)

                    // for (size_t i = 0; i < proof.commitments.lookup.size(); ++i) {
                    //     proof.commitments.lookup[i] = fq_sponge.absorb_g(proof.commitments.lookup[i].unshifted);
                    // }

                    //~ 6. Sample $\beta$ with the Fq-Sponge.
                    typename scalar_field_type::value_type beta = fq_sponge.challenge();

                    //~ 7. Sample $\gamma$ with the Fq-Sponge.
                    typename scalar_field_type::value_type gamma = fq_sponge.challenge();

                    //~ 8. TODO: lookup
                    // for (size_t i = 0; i < proof.commitments.lookup.size(); ++i) {
                    //     proof.commitments.lookup[i] = fq_sponge.absorb_g(proof.commitments.lookup[i].aggreg.unshifted);
                    // }

                    if (proof.commitments.lookup_is_used) {
                        fq_sponge.absorb_g(proof.commitments.lookup.aggreg.unshifted);
                    }


                    //~ 9. Absorb the commitment to the permutation trace with the Fq-Sponge.
                    fq_sponge.absorb_g(proof.commitments.z_comm.unshifted);

                    //~ 10. Sample $\alpha'$ with the Fq-Sponge.
                    ScalarChallenge<scalar_field_type> alpha_chal = ScalarChallenge<scalar_field_type>(
                            fq_sponge.challenge());

                    //~ 11. Derive $\alpha$ from $\alpha'$ using the endomorphism (TODO: details).
                    typename scalar_field_type::value_type alpha = alpha_chal.to_field(index.srs.endo_r);
                    //~ 12. Enforce that the length of the $t$ commitment is of size `PERMUTS`.
                    BOOST_ASSERT_MSG(proof.commitments.t_comm.unshifted.size() == kimchi_constant::PERMUTES,
                                     "IncorrectCommitmentLength(t)");

                    //~ 13. Absorb the commitment to the quotient polynomial $t$ into the argument.
                    fq_sponge.absorb_g(proof.commitments.t_comm.unshifted);

                    //~ 14. Sample $\zeta'$ with the Fq-Sponge.
                    ScalarChallenge<scalar_field_type> zeta_chal = ScalarChallenge<scalar_field_type>(
                            fq_sponge.challenge());

                    //~ 15. Derive $\zeta$ from $\zeta'$ using the endomorphism (TODO: specify).
                    typename scalar_field_type::value_type zeta = zeta_chal.to_field(index.srs.endo_r);

                    //~ 16. Setup the Fr-Sponge.
                    EFqSponge fq_sponge_cloned = fq_sponge;
                    typename scalar_field_type::value_type digest = fq_sponge_cloned.digest();
                    EFrSponge fr_sponge = EFrSponge();

                    //~ 17. Squeeze the Fq-sponge and absorb the result with the Fr-Sponge.
                    fr_sponge.absorb(digest);

                    // prepare some often used values
                    typename scalar_field_type::value_type zeta1 = zeta.pow(n);
                    typename scalar_field_type::value_type zetaw = zeta * index.domain.omega;

                    // retrieve ranges for the powers of alphas

                    std::vector<typename scalar_field_type::value_type> w;
                    w.reserve(proof.public_input.size());
                    if (proof.public_input.size() > 0) {
                        w.push_back(scalar_field_type::value_type::one());
                    }

                    Alphas<scalar_field_type> all_alphas = index.powers_of_alpha;

                    all_alphas.instantiate(alpha);

                    for (int i = 0; i < proof.public_input.size(); ++i) {
                        w.push_back(w.back() * index.domain.omega);
                    }

                    // compute Lagrange base evaluation denominators
                    std::vector<typename scalar_field_type::value_type> zeta_minus_x;
                    for (auto &i: w) {
                        zeta_minus_x.push_back(zeta - i);
                    }

                    for (size_t i = 0; i < proof.public_input.size(); ++i) {
                        zeta_minus_x.push_back(zetaw - w[i]);
                    }

                    // Given a vector of field elements {v_i}, compute the vector {coeff * v_i^(-1)}, where coeff =
                    // F::one()
                    //                    ark_ff::fields::batch_inversion::<Fr<G>>(&mut zeta_minus_x);
                    // zeta_minus_x = zeta_minus_x.inverse() * Fr::one();

                    std::transform(zeta_minus_x.begin(), zeta_minus_x.end(), zeta_minus_x.begin(), [](auto &element) {
                        return element.inversed();
                    });
                    //~ 18. Evaluate the negated public polynomial (if present) at $\zeta$ and $\zeta\omega$.
                    //~     NOTE: this works only in the case when the poly segment size is not smaller than that of the
                    // domain.
                    std::vector<std::vector<typename scalar_field_type::value_type>> p_eval;
                    if (!proof.public_input.empty()) {
                        typename scalar_field_type::value_type tmp;
                        std::size_t iter_size = std::min({proof.public_input.size(), zeta_minus_x.size(), w.size()});

                        for (int i = 0; i < iter_size; ++i) {
                            tmp -= proof.public_input[i] * zeta_minus_x[i] * w[i];
                        }

                        typename scalar_field_type::value_type size_inv = typename scalar_field_type::value_type(
                                index.domain.size()).inversed();

                        p_eval[0].push_back(tmp * (zeta1 - scalar_field_type::value_type::one()) * size_inv);
                        p_eval[1].push_back(tmp * (zetaw.pow(n) - scalar_field_type::value_type::one()) * size_inv);
                    } else {
                        p_eval.resize(2);
                    }

                    //~ 19. Absorb all the polynomial evaluations in $\zeta$ and $\zeta\omega$:
                    //~     - the public polynomial
                    //~     - z
                    //~     - generic selector
                    //~     - poseidon selector
                    //~     - the 15 register/witness
                    //~     - 6 sigmas evaluations (the last one is not evaluated)
                    for (size_t i = 0; i < p_eval.size(); ++i) {
                        fr_sponge.absorb_evaluations(p_eval[i], proof.evals[i]);
                    }

                    //~ 20. Absorb the unique evaluation of ft: $ft(\zeta\omega)$.
                    fr_sponge.absorb(proof.ft_eval1);

                    //~ 21. Sample $v'$ with the Fr-Sponge.
                    ScalarChallenge<scalar_field_type> v_chal = fr_sponge.challenge();

                    //~ 22. Derive $v$ from $v'$ using the endomorphism (TODO: specify).
                    typename scalar_field_type::value_type v = v_chal.to_field(index.srs.endo_r);

                    //~ 23. Sample $u'$ with the Fr-Sponge.
                    ScalarChallenge<scalar_field_type> u_chal = fr_sponge.challenge();

                    //~ 24. Derive $u$ from $u'$ using the endomorphism (TODO: specify).
                    typename scalar_field_type::value_type u = u_chal.to_field(index.srs.endo_r);

                    //~ 25. Create a list of all polynomials that have an evaluation proof.
                    std::vector<typename scalar_field_type::value_type> evaluation_points = {zeta, zetaw};
                    std::array<typename scalar_field_type::value_type, 2> powers_of_eval_points_for_chunks = {
                            zeta.pow(index.max_poly_size),
                            zetaw.pow(index.max_poly_size)
                    };

                    // let polys : Vec<(PolyComm<G>, _)> =
                    //                 self.prev_challenges.iter()
                    //                     .zip(self.prev_chal_evals(index, &evaluation_points,
                    //                                             &powers_of_eval_points_for_chunks))
                    //                     .map(| (c, e) | (c.1.clone(), e))
                    //                     .collect();

                    std::vector<std::tuple<commitment_type, std::vector<std::vector<typename scalar_field_type::value_type>>>> polys;
                    std::vector<std::vector<std::vector<typename scalar_field_type::value_type>>> prev_chal_evals_vec = prev_chal_evals(
                            proof, index, evaluation_points, powers_of_eval_points_for_chunks
                    );

                    for (int i = 0; i < proof.prev_challenges.size(); ++i) {
                        polys.emplace_back(std::get<1>(proof.prev_challenges[i]), prev_chal_evals_vec[i]);
                    }


                    std::vector<proof_evaluation_type<typename scalar_field_type::value_type>> evals = {
                            proof.evals[0].combine(powers_of_eval_points_for_chunks[0]),
                            proof.evals[1].combine(powers_of_eval_points_for_chunks[1])
                    };

                    //~ 26. Compute the evaluation of $ft(\zeta)$.
                    typename scalar_field_type::value_type zkp = index.zkpm.evaluate(zeta);
                    typename scalar_field_type::value_type zeta1m1 = zeta1 - scalar_field_type::value_type::one();

                    std::vector<typename scalar_field_type::value_type> alpha_powers = all_alphas.get_alphas(
                            argument_type::Permutation, kimchi_constant::CONSTRAINTS);
                    typename scalar_field_type::value_type alpha0 = alpha_powers[0];
                    typename scalar_field_type::value_type alpha1 = alpha_powers[1];
                    typename scalar_field_type::value_type alpha2 = alpha_powers[2];

                    typename scalar_field_type::value_type ft_eval0 =
                            (evals[0].w[kimchi_constant::PERMUTES - 1] + gamma) * evals[1].z * alpha0 * zkp;
                    for (size_t i = 0; i < evals[0].s.size(); ++i) {
                        ft_eval0 *= (beta * evals[0].s[i]) + evals[0].w[i] + gamma;
                    }

                    if (!p_eval.empty() && !p_eval[0].empty()) {
                        ft_eval0 -= p_eval[0][0];
                    } else { // ??????????????
                        ft_eval0 -= scalar_field_type::value_type::zero();
                    }

                    typename scalar_field_type::value_type tmp = alpha0 * zkp * evals[0].z;
                    for (size_t i = 0; i < std::min(evals[0].w.size(), index.shift.size()); ++i) {
                        tmp *= gamma + (beta * zeta * index.shift[i]) + evals[0].w[i];
                    }

                    ft_eval0 -= tmp;

                    typename scalar_field_type::value_type numerator = ((zeta1m1 * alpha1 * (zeta - index.w)) +
                                                                        (zeta1m1 * alpha2 * (zeta -
                                                                                             scalar_field_type::value_type::one()))) *
                                                                       (scalar_field_type::value_type::one() -
                                                                        evals[0].z);

                    typename scalar_field_type::value_type denominator =
                            (zeta - index.w) * (zeta - scalar_field_type::value_type::one());
                    denominator = denominator.inversed();

                    ft_eval0 += numerator * denominator;

                    Constants<scalar_field_type> cs{alpha, beta, gamma, std::get<1>(joint_combiner), index.endo,
                                                    index.fr_sponge_params.mds_matrix};

                    ft_eval0 -=
                            PolishToken<scalar_field_type>::evaluate(index.linearization.constant_term, index.domain,
                                                                     zeta, evals, cs);


                    std::vector<std::tuple<evaluation_type, int>> es;

                    for (auto &poly: polys) {
                        evaluation_type eval(commitment_type(), std::get<1>(poly), -1);
                        es.emplace_back(eval, -1);
                    }

                    es.emplace_back(evaluation_type(commitment_type(), p_eval, -1), -1);
                    std::vector<std::vector<typename scalar_field_type::value_type>> ft_eval = {{ft_eval0},
                                                                                                {proof.ft_eval1}};
                    es.emplace_back(evaluation_type(commitment_type(), ft_eval, -1), -1);

                    std::vector<std::vector<typename scalar_field_type::value_type>> z;
                    std::vector<std::vector<typename scalar_field_type::value_type>> generic_selector;
                    std::vector<std::vector<typename scalar_field_type::value_type>> poseidon_selector;
                    for (auto &eval: proof.evals) {
                        z.push_back(eval.z);
                        generic_selector.push_back(eval.generic_selector);
                        poseidon_selector.push_back(eval.poseidon_selector);
                    }
                    es.emplace_back(evaluation_type(commitment_type(), z, -1), -1);
                    es.emplace_back(evaluation_type(commitment_type(), generic_selector, -1), -1);
                    es.emplace_back(evaluation_type(commitment_type(), poseidon_selector, -1), -1);

                    for (int i = 0; i < proof.evals[0].w.size(); ++i) {
                        std::vector<std::vector<typename scalar_field_type::value_type>> w_copy = {proof.evals[0].w[i],
                                                                                                   proof.evals[1].w[i]};
                        es.emplace_back(evaluation_type(commitment_type(), w_copy, -1), -1);
                    }

                    for (int i = 0; i < proof.evals[0].s.size(); ++i) {
                        std::vector<std::vector<typename scalar_field_type::value_type>> s_copy = {proof.evals[0].s[i],
                                                                                                   proof.evals[1].s[i]};
                        es.emplace_back(evaluation_type(commitment_type(), s_copy, -1), -1);
                    }


                    typename scalar_field_type::value_type combined_inner_product0 = commitment_scheme::combined_inner_product(
                            evaluation_points,
                            v,
                            u,
                            es,
                            index.srs.g.size()
                    );

                    RandomOracles<scalar_field_type> oracles = {
                            joint_combiner, beta, gamma, alpha_chal, alpha, zeta, v, u, zeta_chal, v_chal, u_chal
                    };

                    return OraclesResult<CurveType, EFqSponge>{fq_sponge, digest, oracles,
                                                               all_alphas, p_eval, powers_of_eval_points_for_chunks,
                                                               polys, zeta1, ft_eval0, combined_inner_product0};
                }
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
};                   // namespace nil

#endif    // CRYPTO3_ZK_PLONK_BATCHED_PICKLES_ORACLES_HPP
