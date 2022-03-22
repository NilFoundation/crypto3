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
#include <nil/crypto3/zk/snark/commitments/polynmomial/pedersen.hpp>

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
                    typedef pedersen_commitment_scheme<CurveType> commitment_scheme;
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
                    template <typename CurveType, typename EFqSponge>
                OraclesResult<CurveType, EFqSponge> oracles(verifier_index<CurveType> index,
                                                            pedersen_commitment_scheme<CurveType> p_comm) {
        //~
        //~ #### Fiat-Shamir argument
        //~
        //~ We run the following algorithm:
        //~
        size_t n = index.domain.size;

        //~ 1. Setup the Fq-Sponge.
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        //~ 2. Absorb the commitment of the public input polynomial with the Fq-Sponge.
        fq_sponge.absorb_g(&p_comm.unshifted);

        //~ 3. Absorb the commitments to the registers / witness columns with the Fq-Sponge.
        self.commitments
            .w_comm
            .iter()
            .for_each(|c| fq_sponge.absorb_g(&c.unshifted));

        //~ 4. TODO: lookup (joint combiner challenge)
        let joint_combiner = {
            let s = match index.lookup_index {
                None
                | Some(LookupVerifierIndex {
                    lookup_used: LookupsUsed::Single,
                    ..
                }) => ScalarChallenge(Fr::<G>::zero()),
                Some(LookupVerifierIndex {
                    lookup_used: LookupsUsed::Joint,
                    ..
                }) => ScalarChallenge(fq_sponge.challenge()),
            };
            (s, s.to_field(&index.srs.endo_r))
        };

        //~ 5. TODO: lookup (absorb)
        self.commitments.lookup.iter().for_each(|l| {
            l.sorted
                .iter()
                .for_each(|c| fq_sponge.absorb_g(&c.unshifted));
        });

        //~ 6. Sample $\beta$ with the Fq-Sponge.
        let beta = fq_sponge.challenge();

        //~ 7. Sample $\gamma$ with the Fq-Sponge.
        let gamma = fq_sponge.challenge();

        //~ 8. TODO: lookup
        self.commitments.lookup.iter().for_each(|l| {
            fq_sponge.absorb_g(&l.aggreg.unshifted);
        });

        //~ 9. Absorb the commitment to the permutation trace with the Fq-Sponge.
        fq_sponge.absorb_g(&self.commitments.z_comm.unshifted);

        //~ 10. Sample $\alpha'$ with the Fq-Sponge.
        let alpha_chal = ScalarChallenge(fq_sponge.challenge());

        //~ 11. Derive $\alpha$ from $\alpha'$ using the endomorphism (TODO: details).
        let alpha = alpha_chal.to_field(&index.srs.endo_r);

        //~ 12. Enforce that the length of the $t$ commitment is of size `PERMUTS`.
        if self.commitments.t_comm.unshifted.len() != PERMUTS {
            return Err(VerifyError::IncorrectCommitmentLength("t"));
        }

        //~ 13. Absorb the commitment to the quotient polynomial $t$ into the argument.
        fq_sponge.absorb_g(&self.commitments.t_comm.unshifted);

        //~ 14. Sample $\zeta'$ with the Fq-Sponge.
        let zeta_chal = ScalarChallenge(fq_sponge.challenge());

        //~ 15. Derive $\zeta$ from $\zeta'$ using the endomorphism (TODO: specify).
        let zeta = zeta_chal.to_field(&index.srs.endo_r);

        //~ 16. Setup the Fr-Sponge.
        let digest = fq_sponge.clone().digest();
        let mut fr_sponge = EFrSponge::new(index.fr_sponge_params.clone());

        //~ 17. Squeeze the Fq-sponge and absorb the result with the Fr-Sponge.
        fr_sponge.absorb(&digest);

        // prepare some often used values
        let zeta1 = zeta.pow(&[n]);
        let zetaw = zeta * index.domain.group_gen;

        // retrieve ranges for the powers of alphas
        let mut all_alphas = index.powers_of_alpha.clone();
        all_alphas.instantiate(alpha);

        // compute Lagrange base evaluation denominators
        let w: Vec<_> = index.domain.elements().take(self.public.len()).collect();

        let mut zeta_minus_x: Vec<_> = w.iter().map(|w| zeta - w).collect();

        w.iter()
            .take(self.public.len())
            .for_each(|w| zeta_minus_x.push(zetaw - w));

        ark_ff::fields::batch_inversion::<Fr<G>>(&mut zeta_minus_x);

        //~ 18. Evaluate the negated public polynomial (if present) at $\zeta$ and $\zeta\omega$.
        //~     NOTE: this works only in the case when the poly segment size is not smaller than that of the domain.
        let p_eval = if !self.public.is_empty() {
            vec![
                vec![
                    (self
                        .public
                        .iter()
                        .zip(zeta_minus_x.iter())
                        .zip(index.domain.elements())
                        .map(|((p, l), w)| -*l * p * w)
                        .fold(Fr::<G>::zero(), |x, y| x + y))
                        * (zeta1 - Fr::<G>::one())
                        * index.domain.size_inv,
                ],
                vec![
                    (self
                        .public
                        .iter()
                        .zip(zeta_minus_x[self.public.len()..].iter())
                        .zip(index.domain.elements())
                        .map(|((p, l), w)| -*l * p * w)
                        .fold(Fr::<G>::zero(), |x, y| x + y))
                        * index.domain.size_inv
                        * (zetaw.pow(&[n as u64]) - Fr::<G>::one()),
                ],
            ]
        } else {
            vec![Vec::<Fr<G>>::new(), Vec::<Fr<G>>::new()]
        };

        //~ 19. Absorb all the polynomial evaluations in $\zeta$ and $\zeta\omega$:
        //~     - the public polynomial
        //~     - z
        //~     - generic selector
        //~     - poseidon selector
        //~     - the 15 register/witness
        //~     - 6 sigmas evaluations (the last one is not evaluated)
        for (p, e) in p_eval.iter().zip(&self.evals) {
            fr_sponge.absorb_evaluations(p, e);
        }

        //~ 20. Absorb the unique evaluation of ft: $ft(\zeta\omega)$.
        fr_sponge.absorb(&self.ft_eval1);

        //~ 21. Sample $v'$ with the Fr-Sponge.
        let v_chal = fr_sponge.challenge();

        //~ 22. Derive $v$ from $v'$ using the endomorphism (TODO: specify).
        let v = v_chal.to_field(&index.srs.endo_r);

        //~ 23. Sample $u'$ with the Fr-Sponge.
        let u_chal = fr_sponge.challenge();

        //~ 24. Derive $u$ from $u'$ using the endomorphism (TODO: specify).
        let u = u_chal.to_field(&index.srs.endo_r);

        //~ 25. Create a list of all polynomials that have an evaluation proof.
        let evaluation_points = [zeta, zetaw];
        let powers_of_eval_points_for_chunks = [
            zeta.pow(&[index.max_poly_size as u64]),
            zetaw.pow(&[index.max_poly_size as u64]),
        ];

        let polys: Vec<(PolyComm<G>, _)> = self
            .prev_challenges
            .iter()
            .zip(self.prev_chal_evals(index, &evaluation_points, &powers_of_eval_points_for_chunks))
            .map(|(c, e)| (c.1.clone(), e))
            .collect();

        let evals = vec![
            self.evals[0].combine(powers_of_eval_points_for_chunks[0]),
            self.evals[1].combine(powers_of_eval_points_for_chunks[1]),
        ];

        //~ 26. Compute the evaluation of $ft(\zeta)$.
        let ft_eval0 = {
            let zkp = index.zkpm.evaluate(&zeta);
            let zeta1m1 = zeta1 - Fr::<G>::one();

            let mut alpha_powers =
                all_alphas.get_alphas(ArgumentType::Permutation, permutation::CONSTRAINTS);
            let alpha0 = alpha_powers
                .next()
                .expect("missing power of alpha for permutation");
            let alpha1 = alpha_powers
                .next()
                .expect("missing power of alpha for permutation");
            let alpha2 = alpha_powers
                .next()
                .expect("missing power of alpha for permutation");

            let init = (evals[0].w[PERMUTS - 1] + gamma) * evals[1].z * alpha0 * zkp;
            let mut ft_eval0 = evals[0]
                .w
                .iter()
                .zip(evals[0].s.iter())
                .map(|(w, s)| (beta * s) + w + gamma)
                .fold(init, |x, y| x * y);

            ft_eval0 -= if !p_eval[0].is_empty() {
                p_eval[0][0]
            } else {
                Fr::<G>::zero()
            };

            ft_eval0 -= evals[0]
                .w
                .iter()
                .zip(index.shift.iter())
                .map(|(w, s)| gamma + (beta * zeta * s) + w)
                .fold(alpha0 * zkp * evals[0].z, |x, y| x * y);

            let nominator = ((zeta1m1 * alpha1 * (zeta - index.w))
                + (zeta1m1 * alpha2 * (zeta - Fr::<G>::one())))
                * (Fr::<G>::one() - evals[0].z);

            let denominator = (zeta - index.w) * (zeta - Fr::<G>::one());
            let denominator = denominator.inverse().expect("negligible probability");

            ft_eval0 += nominator * denominator;

            let cs = Constants {
                alpha,
                beta,
                gamma,
                joint_combiner: joint_combiner.1,
                endo_coefficient: index.endo,
                mds: index.fr_sponge_params.mds.clone(),
            };
            ft_eval0 -= PolishToken::evaluate(
                &index.linearization.constant_term,
                index.domain,
                zeta,
                &evals,
                &cs,
            )
            .unwrap();

            ft_eval0
        };

        let oracles = RandomOracles {
            beta,
            gamma,
            alpha_chal,
            alpha,
            zeta,
            v,
            u,
            zeta_chal,
            v_chal,
            u_chal,
            joint_combiner,
        };

        Ok(OraclesResult {
            fq_sponge,
            digest,
            oracles,
            all_alphas,
            p_eval,
            powers_of_eval_points_for_chunks,
            polys,
            zeta1,
            ft_eval0,
        })
    }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
};               // namespace nil

#endif    // CRYPTO3_ZK_PLONK_BATCHED_PICKLES_ORACLES_HPP
