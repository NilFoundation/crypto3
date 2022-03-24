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
#include <nil/crypto3/zk/commitments/polynomial/kimchi_pedersen.hpp>

#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <map>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType>
                struct RandomOracles {
                    std::tuple<ScalarChallenge<FieldType>, FieldType> joint_combiner;
                    FieldType beta;
                    FieldType gamma;
                    ScalarChallenge<FieldType> alpha_chal;
                    FieldType alpha;
                    FieldType zeta;
                    FieldType v;
                    FieldType u;
                    ScalarChallenge<FieldType> zeta_chal;
                    ScalarChallenge<FieldType> v_chal;
                    ScalarChallenge<FieldType> u_chal;
                };

                template<typename CurveType, typename EFqSponge>
                struct OraclesResult {
                    typedef kimchi_pedersen<CurveType> commitment_scheme;
                    using Fr = typename CurveType::scalar_field_type;
                    using Fq = typename CurveType::base_field_type;
                    /// A sponge that acts on the base field of a curve
                    EFqSponge fq_sponge;
                    /// the last evaluation of the Fq-Sponge in this protocol
                    Fr digest;
                    /// the challenges produced in the protocol
                    RandomOracles<Fr> oracles;
                    /// the computed powers of alpha
                    Alphas<Fr> all_alphas;
                    /// public polynomial evaluations
                    std::vector<std::vector<Fr>> p_eval;
                    /// zeta^n and (zeta * omega)^n
                    std::array<Fr, 2> powers_of_eval_points_for_chunks;
                    /// ?
                    std::vector < std::tuple < commitment_scheme, std::vector<std::vector<Fr>> polys;
                    /// pre-computed zeta^n
                    Fr zeta1;
                    /// The evaluation f(zeta) - t(zeta) * Z_H(zeta)
                    Fr ft_eval0;
                };

                /// This function runs the random oracle argument
                template<typename CurveType, typename EFqSponge>
                OraclesResult<CurveType, EFqSponge> oracles(pickles_proof<CurveType, WiresAmount> proof,
                                                            verifier_index<CurveType> index,
                                                            pedersen_commitment_scheme<CurveType> p_comm) {
                    typedef kimchi_pedersen<CurveType> commitment_scheme;
                    using Fr = typename CurveType::scalar_field_type;
                    using Fq = typename CurveType::base_field_type;
                    //~
                    //~ #### Fiat-Shamir argument
                    //~
                    //~ We run the following algorithm:
                    //~
                    size_t n = index.domain.size;

                    //~typename CurveType::scalar_field_type; 1. Setup the Fq-Sponge.
                    EFqSponge fq_sponge = EFqSponge(index.fq_sponge_params);

                    //~ 2. Absorb the commitment of the public input polynomial with the Fq-Sponge.
                    fq_sponge.absorb_g(&p_comm.unshifted);

                    //~ 3. Absorb the commitments to the registers / witness columns with the Fq-Sponge.
                    for (size_t i = 0; i < proof.w_comm.size(); ++i) {
                        proof.w_comm[i] = fq_sponge.absorb_g(proof.w_comm[i]);
                    }

                    //~ 4. TODO: lookup (joint combiner challenge)
                    ScalarChallenge<typename CurveType::scalar_field_type> s;
                    if (index.lookup_index.lookup_used == lookup_verifier_index::lookups_used::Single) {
                        s = ScalarChallenge(typename CurveType::scalar_field_type::zero());
                    }
                    if (index.lookup_index.lookup_used == lookup_verifier_index::lookups_used::Joint) {
                        s = ScalarChallenge(fq_sponge.challenge());
                    }
                    std::tuple<ScalarChallenge<typename CurveType::scalar_field_type>,
                               typename CurveType::scalar_field_type>
                        joint_combiner = (s, s.to_field(&index.srs.endo_r));

                    //~ 5. TODO: lookup (absorb)

                    for (size_t i = 0; i < proof.commitments.lookup.size(); ++i) {
                        proof.commitments.lookup[i] = fq_sponge.absorb_g(proof.commitments.lookup[i].unshifted);
                    }

                    //~ 6. Sample $\beta$ with the Fq-Sponge.
                    Fq beta = fq_sponge.challenge();

                    //~ 7. Sample $\gamma$ with the Fq-Sponge.
                    Fq gamma = fq_sponge.challenge();

                    //~ 8. TODO: lookup
                    for (size_t i = 0; i < proof.commitments.lookup.size(); ++i) {
                        proof.commitments.lookup[i] = fq_sponge.absorb_g(proof.commitments.lookup[i].aggreg.unshifted);
                    }

                    //~ 9. Absorb the commitment to the permutation trace with the Fq-Sponge.
                    fq_sponge.absorb_g(proof.commitments.z_comm.unshifted);

                    //~ 10. Sample $\alpha'$ with the Fq-Sponge.
                    ScalarChallenge<Fq> alpha_chal = ScalarChallenge(fq_sponge.challenge());

                    //~ 11. Derive $\alpha$ from $\alpha'$ using the endomorphism (TODO: details).
                    Fq alpha = alpha_chal.to_field(index.srs.endo_r);

                    //~ 12. Enforce that the length of the $t$ commitment is of size `PERMUTS`.
                    BOOST_ASSERT_MSG(proof.commitments.t_comm.unshifted.size() == PERMUTS,
                                     "IncorrectCommitmentLength(t)")

                    //~ 13. Absorb the commitment to the quotient polynomial $t$ into the argument.
                    fq_sponge.absorb_g(proof.commitments.t_comm.unshifted);

                    //~ 14. Sample $\zeta'$ with the Fq-Sponge.
                    ScalarChallenge<Fq> zeta_chal = ScalarChallenge(fq_sponge.challenge());

                    //~ 15. Derive $\zeta$ from $\zeta'$ using the endomorphism (TODO: specify).
                    Fq zeta = zeta_chal.to_field(index.srs.endo_r);

                    //~ 16. Setup the Fr-Sponge.
                    Fq digest = fq_sponge.clone().digest();
                    EFrSponge fr_sponge = EFrSponge(index.fr_sponge_params);

                    //~ 17. Squeeze the Fq-sponge and absorb the result with the Fr-Sponge.
                    fr_sponge.absorb(digest);

                    // prepare some often used values
                    Fq zeta1 = zeta.pow(n);
                    Fq zetaw = zeta * index.domain.group_gen;

                    // retrieve ranges for the powers of alphas
                    Alphas<Fr> all_alphas = index.powers_of_alpha;
                    all_alphas.instantiate(alpha);

                    // compute Lagrange base evaluation denominators
                    std::vector<Fq> w(index.domain.elements().begin(),
                                      index.domain.elements().begin() + proof.public_p.size());
                    std::vector<Fq> zeta_minus_x;
                    for (auto i : &w) {
                        zeta_minus_x.push_back(zeta - i);
                    }

                    for (size_t i = 0; i < proof.public_p.size(); ++i) {
                        zeta_minus_x.push_back(zetaw - w[i]);
                    }

                    ark_ff::fields::batch_inversion::<Fr<G>>(&mut zeta_minus_x);

                    //~ 18. Evaluate the negated public polynomial (if present) at $\zeta$ and $\zeta\omega$.
                    //~     NOTE: this works only in the case when the poly segment size is not smaller than that of the
                    // domain.
                    std::array<std::vector<Fr>, 2> p_eval;
                    if (!proof.public_p.is_empty()) {
                        Fr tmp = Fr::zero();
                        for (auto i : &proof.public_p) {
                            for (auto j : &zeta_minus_x) {
                                for (auto k : &index.domain.elements()) {
                                    tmp += -i * j * k;
                                }
                            }
                        }
                        p_eval[0].push_back(tmp * (zeta1 - Fr::one()) * index.domain.size_inv);
                        p_eval[1].push_back(tmp * (zetaw.pow(n) - Fr::one()) * index.domain.size_inv);
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
                    ScalarChallenge<Fq> v_chal = fr_sponge.challenge();

                    //~ 22. Derive $v$ from $v'$ using the endomorphism (TODO: specify).
                    Fq v = v_chal.to_field(index.srs.endo_r);

                    //~ 23. Sample $u'$ with the Fr-Sponge.
                    ScalarChallenge<Fq> u_chal = fr_sponge.challenge();

                    //~ 24. Derive $u$ from $u'$ using the endomorphism (TODO: specify).
                    Fq u = u_chal.to_field(index.srs.endo_r);

                    //~ 25. Create a list of all polynomials that have an evaluation proof.
                    std::array<Fq, 2> evaluation_points = {zeta, zetaw};
                    std::array<Fq, 2> powers_of_eval_points_for_chunks = {zeta.pow(index.max_poly_size),
                                                                          zetaw.pow(index.max_poly_size)};

                    let polys : Vec<(PolyComm<G>, _)> =
                                    self.prev_challenges.iter()
                                        .zip(self.prev_chal_evals(index, &evaluation_points,
                                                                  &powers_of_eval_points_for_chunks))
                                        .map(| (c, e) | (c .1.clone(), e))
                                        .collect();

                    let evals = vec ![
                        self.evals[0].combine(powers_of_eval_points_for_chunks[0]),
                        self.evals[1].combine(powers_of_eval_points_for_chunks[1]),
                    ];

                    //~ 26. Compute the evaluation of $ft(\zeta)$.
                    Fq ft_eval0;
                    Fq zkp = index.zkpm.evaluate(zeta);
                    Fq zeta1m1 = zeta1 - Fq::one();

                    std::vector<Fr> alpha_powers = all_alphas.get_alphas(permutation::CONSTRAINTS);
                    Fr alpha0 = alpha_powers[0];
                    Fr alpha1 = alpha_powers[1];
                    Fr alpha2 = alpha_powers[2];

                    Fq init = (evals[0].w[PERMUTS - 1] + gamma) * evals[1].z * alpha0 * zkp;
                    Fq ft_eval0;
                    for (size_t i = 0; i < evals[0].size(); ++i) {
                        ft_eval0 *= (beta * evals[0].s[i]) + evals[0][i] + gamma;
                    }

                    if (!p_eval[0].is_empty()) {
                        t_eval0 -= p_eval[0][0];
                    } else {
                        t_eval0 -= Fr::zero();
                    }

                    Fq tmp = alpha0 * zkp * evals[0].z;
                    for (size_t = 0; i < evals[0].w.size(); ++i) {
                        tmp *= gamma + (beta * zeta * index.shift[i]) + evals[0].w[i]);
                    }

                    ft_eval0 -= tmp;

                    Fq nominator = ((zeta1m1 * alpha1 * (zeta - index.w)) + (zeta1m1 * alpha2 * (zeta - Fr::one()))) *
                                   (Fr::one() - evals[0].z);

                    Fq denominator = (zeta - index.w) * (zeta - Fr::one());
                    let denominator = denominator.inverse().expect("negligible probability");

                    ft_eval0 += nominator * denominator;

                    Constants<Fr> cs = {alpha = alpha,
                                        beta = beta,
                                        gamma = gamma,
                                        joint_combiner = joint_combiner .1,
                                        endo_coefficient = index.endo,
                                        mds = index.fr_sponge_params.mds.clone()};
                    ft_eval0 -=
                        PolishToken::evaluate(index.linearization.constant_term, index.domain, zeta, &evals, &cs);

                    RandomOracles oracles = {
                        beta, gamma, alpha_chal, alpha, zeta, v, u, zeta_chal, v_chal, u_chal, joint_combiner,
                    };

                    return OraclesResult {fq_sponge,  digest, oracles,
                                          all_alphas, p_eval, powers_of_eval_points_for_chunks,
                                          polys,      zeta1,  ft_eval0};
                }    // namespace snark
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
};                   // namespace nil

#endif    // CRYPTO3_ZK_PLONK_BATCHED_PICKLES_ORACLES_HPP
