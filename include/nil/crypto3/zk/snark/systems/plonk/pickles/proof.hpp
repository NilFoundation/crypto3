//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_PICKLES_PROOF_HPP
#define CRYPTO3_ZK_PICKLES_PROOF_HPP

#include <array>
#include <tuple>
#include <vector>
#include <optional>

#include <nil/crypto3/zk/commitments/polynomial/kimchi_pedersen.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/constants.hpp>


namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType, std::size_t WiresAmount = kimchi_constant::COLUMNS, std::size_t Permuts = kimchi_constant::PERMUTES>
                class prover_proof {
                    typedef commitments::kimchi_pedersen<CurveType> commitment_scheme;
                    typedef typename commitments::kimchi_pedersen<CurveType>::commitment_type commitment_type;
                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    typedef typename CurveType::base_field_type base_field_type;

                public:
                    // Commitments:

                    template<typename value_type>
                    struct lookup_evaluation_type {
                        std::vector<typename value_type> sorted;
                        typename value_type aggreg;
                        typename value_type table;
                        std::optional<typename value_type> runtime;

                        lookup_evaluation_type(std::vector<typename value_type>& sorted, typename value_type& aggreg, 
                            typename value_type& table, std::optional<typename value_type>& runtime) : sorted(sorted),
                            aggreg(aggreg), table(table), runtime(runtime) {};
                    };

                    template<typename value_type>
                    struct proof_evaluation_type {
                        std::array<typename value_type, WiresAmount> w;
                        typename value_type z;
                        std::array<typename value_type, Permuts - 1> s;
                        std::optional<typename lookup_evaluation_type<typename value_type>> lookup;
                        typename value_type generic_selector;
                        typename value_type poseidon_selector;

                        proof_evaluation_type(std::array<value_type, WiresAmount>& w, 
                            typename value_type& z, std::array<typename value_type, Permuts - 1>& s,
                            std::optional<typename lookup_evaluation_type<value_type>> &lookup, 
                            typename value_type& generic_selector, typename value_type& poseidon_selector) : 
                            w(w), z(z), s(s), lookup(lookup), generic_selector(generic_selector), 
                            poseidon_selector(poseidon_selector) {}
                    };

                    template <typename value_type>
                    struct proof_evaluation_type<std::vector<typename value_type>> : proof_evaluation_type<value_type>{
                        proof_evaluation_type<typename value_type> combine(typename value_type& pt){
                            std::array<typename value_type, Permuts - 1> s_combined;
                            for(int i = 0; i < s_combined.size(); ++i){
                                math::polynomial<typename value_type> temp_polynomial(this->s[i].begin(), this->s[i].end());
                                s_combined[i] = temp_polynomial.evaluate(pt);
                            }

                            std::array<value_type, WiresAmount> w_combined;
                            for(int i = 0; i < s_combined.size(); ++i){
                                math::polynomial<typename value_type> temp_polynomial(this->w[i].begin(), this->w[i].end());
                                w_combined[i] = temp_polynomial.evaluate(pt);
                            }

                            math::polynomial<typename value_type> temp_polynomial_z(this->z[i].begin(), this->z[i].end());
                            typename value_type z_combined = temp_polynomial.evaluate(pt);

                            math::polynomial<typename value_type> temp_polynomial_gs(this->generic_selector[i].begin(), this->generic_selector[i].end());
                            typename value_type generic_selector_combined = temp_polynomial.evaluate(pt);

                            math::polynomial<typename value_type> temp_polynomial_ps(this->poseidon_selector[i].begin(), this->poseidon_selector[i].end());
                            typename value_type poseidon_selector_combined = temp_polynomial.evaluate(pt);

                            std::optional<typename lookup_evaluation_type<value_type>> lookup_combined;
                            if(this->lookup){
                                lookup_combined = lookup_evaluation_type<value_type>();

                                math::polynomial<typename value_type> temp_polynomial_table(this->lookup.table.begin(), this->lookup.table.end());
                                lookup_combined.value().table = temp_polynomial_table.evaluate(pt);

                                math::polynomial<typename value_type> temp_polynomial_aggreg(this->lookup.aggreg.begin(), this->lookup.aggreg.end());
                                lookup_combined.value().aggreg = temp_polynomial_aggreg.evaluate(pt);

                                for(int i = 0; i < this->lookup.sorted.size(); ++i){
                                    math::polynomial<typename value_type> temp_polynomial_sorted(this->lookup.sorted[i].begin(), this->lookup.sorted[i].end());
                                    lookup_combined.value().sorted[i] = temp_polynomial_sorted.evaluate(pt);
                                }
                                
                                if(this->lookup.value().runtime){
                                    math::polynomial<typename value_type> temp_polynomial_runtime(this->lookup.value().runtime.value().begin(),
                                                                                                this->lookup.value().runtime.value().end());
                                    lookup_combined.value().runtime.value() = temp_polynomial_runtime.evaluate(pt);
                                }
                            }

                            return proof_evaluation_type<typename value_type>(w_combined, z_combined, s_combined, lookup_combined, 
                                    generic_selector_combined, poseidon_selector_combined);
                        }
                    };

                    struct lookup_commitment_type {
                        std::vector<commitment_type> sorted;
                        commitment_type aggreg;
                        std::optional<commitment_type> runtime;
                    };

                    struct proof_commitment_type {
                        std::array<commitment_type, WiresAmount> w_comm;
                        commitment_type z_comm;
                        commitment_type t_comm;
                        std::optional<lookup_commitment_type> lookup;
                    };

                    proof_commitment_type commitments;
                    typename commitments::kimchi_pedersen<CurveType>::proof_type proof;
                    std::array<proof_evaluation_type<std::vector<scalar_field_type::value_type>>, 2> evals;

                    // ft_eval1
                    typename scalar_field_type::value_type ft_eval1;
                    // public
                    std::vector<typename scalar_field_type::value_type> public_input;
                    // Previous challenges
                    std::vector<
                        std::pair<std::vector<typename CurveType::scalar_field_type::value_type>, commitment_type>>
                        prev_challenges;

                     /// This function runs the random oracle argument
                    template<typename EFqSponge>
                    OraclesResult<EFqSponge> oracles(pickles_proof<CurveType> proof,
                                verifier_index<CurveType> index,
                                commitments::kimchi_pedersen<CurveType> p_comm) {
                        // typedef commitments::kimchi_pedersen<CurveType> commitment_scheme;
                        // typedef typename commitments::kimchi_pedersen<CurveType>::commitment_type commitment_type;
                        // using scalar_field_type = typename CurveType::scalar_field_type; // Fr
                        // using base_field_type = typename CurveType::base_field_type; // Fq
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
                        for (auto &commit : commitments.w_comm) {
                            fq_sponge.absorb_g(commit.unshifted);
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

                        // Given a vector of field elements {v_i}, compute the vector {coeff * v_i^(-1)}, where coeff =
                        // F::one()
                        //                    ark_ff::fields::batch_inversion::<Fr<G>>(&mut zeta_minus_x);
                        zeta_minus_x = zeta_minus_x.inverse() * Fr::one();

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

                        std::array<typename commitment_scheme::evals_t, 2> evals = {
                            proof.evals[0].combine(powers_of_eval_points_for_chunks[0]),
                            proof.evals[1].combine(powers_of_eval_points_for_chunks[1])};

                        //~ 26. Compute the evaluation of $ft(\zeta)$.
                        Fq ft_eval0;
                        Fq zkp = index.zkpm.evaluate(zeta);
                        Fq zeta1m1 = zeta1 - Fq::one();

                        std::vector<Fr> alpha_powers = all_alphas.get_alphas(CONSTRAINTS);
                        Fr alpha0 = alpha_powers[0];
                        Fr alpha1 = alpha_powers[1];
                        Fr alpha2 = alpha_powers[2];

                        Fq init = (evals[0].w[PERMUTS - 1] + gamma) * evals[1].z * alpha0 * zkp;
                        for (size_t i = 0; i < evals[0].size(); ++i) {
                            ft_eval0 *= (beta * evals[0].s[i]) + evals[0][i] + gamma;
                        }

                        if (!p_eval[0].is_empty()) {
                            ft_eval0 -= p_eval[0][0];
                        } else {
                            ft_eval0 -= Fr::zero();
                        }

                        Fq tmp = alpha0 * zkp * evals[0].z;
                        for (size_t i = 0; i < evals[0].w.size(); ++i) {
                            tmp *= gamma + (beta * zeta * index.shift[i]) + evals[0].w[i]);
                        }

                        ft_eval0 -= tmp;

                        Fq nominator = ((zeta1m1 * alpha1 * (zeta - index.w)) + (zeta1m1 * alpha2 * (zeta - Fr::one()))) *
                                    (Fr::one() - evals[0].z);

                        Fq denominator = (zeta - index.w) * (zeta - Fr::one());
                        denominator = denominator.inverse();

                        ft_eval0 += nominator * denominator;

                        Constants<Fr> cs = {alpha, beta, gamma, joint_combiner, index.endo, index.fr_sponge_params.mds};
                        ft_eval0 -=
                            PolishToken::evaluate(index.linearization.constant_term, index.domain, zeta, &evals, &cs);

                        RandomOracles oracles = {
                            beta, gamma, alpha_chal, alpha, zeta, v, u, zeta_chal, v_chal, u_chal, joint_combiner,
                        };

                        return OraclesResult {fq_sponge,  digest, oracles,
                                            all_alphas, p_eval, powers_of_eval_points_for_chunks,
                                            polys,      zeta1,  ft_eval0};
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PROOF_HPP
