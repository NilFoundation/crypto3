//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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

#ifndef CRYPTO3_ZK_COMMITMENTS_KZG_HPP
#define CRYPTO3_ZK_COMMITMENTS_KZG_HPP

#include <tuple>
#include <vector>
#include <type_traits>

#include <boost/assert.hpp>
#include <boost/iterator/zip_iterator.hpp>
#include <boost/accumulators/accumulators.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/algebra/type_traits.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/algebra/multiexp/multiexp.hpp>
#include <nil/crypto3/algebra/multiexp/policies.hpp>
#include <nil/crypto3/algebra/pairing/pairing_policy.hpp>

using namespace nil::crypto3::math;

#include <nil/crypto3/math/polynomial/polynomial.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                template<typename CurveType>
                struct kzg_commitment;

                template<typename CurveType>
                struct kzg_commitment {

                    typedef CurveType curve_type;
                    typedef algebra::pairing::pairing_policy<curve_type> pairing_policy;
                    typedef typename curve_type::gt_type::value_type gt_value_type;

                    using multiexp_method = typename algebra::policies::multiexp_method_BDLO12;
                    using scalar_value_type = typename curve_type::scalar_field_type::value_type;
                    using commitment_key_type = std::vector<typename curve_type::template g1_type<>::value_type>;
                    using verification_key_type = typename curve_type::template g2_type<>::value_type;
                    using commitment_type = typename curve_type::template g1_type<>::value_type;
                    using proof_type = commitment_type;

                    struct kzg_params_type {
                        std::size_t n;            //max polynomial degree
                        scalar_value_type alpha;  //secret key
                        kzg_params_type(std::size_t _n, scalar_value_type _alpha) : n(_n), alpha(_alpha) {}
                        kzg_params_type(std::size_t _n) {
                            alpha = scalar_value_type::random_element();
                            n = _n;
                        }
                    };

                    struct srs_type {
                        commitment_key_type commitment_key;
                        verification_key_type verification_key;
                        srs_type(commitment_key_type ck, verification_key_type vk) :
                            commitment_key(ck), verification_key(vk) {}
                    };

                    static srs_type setup(kzg_params_type params) {
                        scalar_value_type alpha_scaled = params.alpha;
                        commitment_key_type commitment_key = {curve_type::template g1_type<>::value_type::one()};
                        verification_key_type verification_key =
                            curve_type::template g2_type<>::value_type::one() * params.alpha;

                        for (std::size_t i = 0; i < params.n; i++) {
                            commitment_key.emplace_back(alpha_scaled * (curve_type::template g1_type<>::value_type::one()));
                            alpha_scaled = alpha_scaled * params.alpha;
                        }

                        return srs_type(std::move(commitment_key), verification_key);
                    }

                    static commitment_type commit(const srs_type &srs,
                                                  const polynomial<scalar_value_type> &f) {
                        // assert(f.size() <= srs.commitment_key.size());
                        return algebra::multiexp<multiexp_method>(srs.commitment_key.begin(),
                                                srs.commitment_key.begin() + f.size(), f.begin(), f.end(), 1);
                    }

                    static bool verify_poly(const srs_type &srs,
                                            const polynomial<scalar_value_type> &f,
                                            const commitment_type &C_f) {
                        return C_f == commit(srs, f);
                    }

                    static proof_type proof_eval(srs_type srs,
                                                 const polynomial<scalar_value_type> &f,
                                                 scalar_value_type i,
                                                 scalar_value_type eval) {

                        const polynomial<scalar_value_type> denominator_polynom = {-i, 1};
                        const polynomial<scalar_value_type> q =
                            (f - polynomial<scalar_value_type>{eval}) / denominator_polynom;

                        return commit(srs, q);
                    }

                    static bool verify_eval(srs_type srs,
                                            proof_type p,
                                            commitment_type C_f,
                                            scalar_value_type i,
                                            scalar_value_type eval) {

                        auto A_1 = algebra::precompute_g1<curve_type>(p);
                        auto A_2 = algebra::precompute_g2<curve_type>(srs.verification_key -
                                                                        i * curve_type::template g2_type<>::value_type::one());
                        auto B_1 = algebra::precompute_g1<curve_type>(eval * curve_type::template g1_type<>::value_type::one() -
                                                                        C_f);
                        auto B_2 = algebra::precompute_g2<curve_type>(curve_type::template g2_type<>::value_type::one());

                        gt_value_type gt3 = algebra::double_miller_loop<curve_type>(A_1, A_2, B_1, B_2);
                        gt_value_type gt_4 = algebra::final_exponentiation<curve_type>(gt3);

                        return gt_4 == gt_value_type::one();
                    }
                };

                template<typename CurveType>
                struct kzg_batched_commitment : public kzg_commitment<CurveType> {

                    typedef CurveType curve_type;
                    typedef algebra::pairing::pairing_policy<curve_type> pairing_policy;
                    typedef typename curve_type::gt_type::value_type gt_value_type;

                    using multiexp_method = typename algebra::policies::multiexp_method_BDLO12;
                    using scalar_value_type = typename curve_type::scalar_field_type::value_type;
                    using commitment_key_type = std::vector<typename curve_type::template g1_type<>::value_type>;
                    using verification_key_type = typename curve_type::template g2_type<>::value_type;
                    using commitment_type = typename curve_type::template g1_type<>::value_type;

                    using kzg = kzg_commitment<CurveType>;
                    using kzg_params_type = typename kzg::kzg_params_type;  
                    using srs_type = typename kzg::srs_type;

                    struct evals_type {
                        std::vector<scalar_value_type> evals_at_z0;
                        std::vector<scalar_value_type> evals_at_z1;
                        evals_type(const std::vector<scalar_value_type> &e1, const std::vector<scalar_value_type> &e2) 
                                    : evals_at_z0(e1), evals_at_z1(e2) {}
                    };

                    struct batched_proof_type {
                        commitment_type commit0;
                        commitment_type commit1;
                        batched_proof_type(commitment_type c0, commitment_type c1) : commit0(c0), commit1(c1) {}
                    };

                    static polynomial<scalar_value_type> accumulate(const std::vector<polynomial<scalar_value_type>> &polys,
                                                                    const scalar_value_type &factor) {
                        std::size_t num = polys.size();
                        if (num == 1) return polys[0];

                        polynomial<scalar_value_type> result = polys[num - 1];
                        for (int i = num - 2; i >= 0; --i) {
                            result = result * factor + polys[i];
                        }
                        return result;
                    }

                    static evals_type evaluate_polynomials(const std::vector<polynomial<scalar_value_type>> &polys0,
                                                            const std::vector<polynomial<scalar_value_type>> &polys1,
                                                            scalar_value_type z0, scalar_value_type z1) {
                        std::vector<scalar_value_type> evals_at_z0;
                        for (const auto &poly : polys0) {
                            evals_at_z0.emplace_back(poly.evaluate(z0));
                        }

                        std::vector<scalar_value_type> evals_at_z1;
                        for (const auto &poly : polys1) {
                            evals_at_z1.emplace_back(poly.evaluate(z1));
                        }

                        return evals_type(evals_at_z0, evals_at_z1);
                    }

                    static std::vector<commitment_type> commit(const srs_type &srs, 
                                                                const std::vector<polynomial<scalar_value_type>> &polys) {
                        std::vector<commitment_type> commitments;
                        for (const auto &poly : polys) {
                            commitments.emplace_back(kzg::commit(srs, poly));
                        }
                        return commitments;
                    }

                    static batched_proof_type proof_eval(const srs_type &srs, 
                                                        const std::vector<polynomial<scalar_value_type>> &polys0,
                                                        const std::vector<polynomial<scalar_value_type>> &polys1,
                                                        const evals_type &evals,
                                                        scalar_value_type z0, scalar_value_type z1,
                                                        scalar_value_type gamma0, scalar_value_type gamma1) {

                        auto accum0 = accumulate(polys0, gamma0);
                        auto accum_eval0 = polynomial<scalar_value_type>{evals.evals_at_z0}.evaluate(gamma0);
                        typename kzg::proof_type proof0 = kzg::proof_eval(srs, accum0, z0, accum_eval0);

                        auto accum1 = accumulate(polys1, gamma1);
                        auto accum_eval1 = polynomial<scalar_value_type>{evals.evals_at_z1}.evaluate(gamma1);
                        typename kzg::proof_type proof1 = kzg::proof_eval(srs, accum1, z1, accum_eval1);
                        
                        return batched_proof_type(proof0, proof1);
                    }

                    static bool verify_eval(srs_type srs,
                                            const batched_proof_type &proof,
                                            const evals_type &evals,
                                            const std::vector<commitment_type> &commits0,
                                            const std::vector<commitment_type> &commits1,
                                            scalar_value_type z0, scalar_value_type z1,
                                            scalar_value_type gamma0, scalar_value_type gamma1,
                                            scalar_value_type r) {
                        
                        auto eval0_accum = evals.evals_at_z0.back();
                        auto comm0_accum = commits0.back();
                        for (int i = commits0.size() - 2; i >= 0; --i) {
                            comm0_accum = (gamma0 * comm0_accum) + commits0[i];
                            eval0_accum = (eval0_accum * gamma0) + evals.evals_at_z0[i];
                        }

                        auto eval1_accum = evals.evals_at_z1.back();
                        auto comm1_accum = commits1.back();
                        for (int i = commits1.size() - 2; i >= 0; --i) {
                            comm1_accum = (gamma1 * comm1_accum) + commits1[i];
                            eval1_accum = (eval1_accum * gamma1) + evals.evals_at_z1[i];
                        }

                        auto F = (comm0_accum - eval0_accum * curve_type::template g1_type<>::value_type::one()) +
                                r * (comm1_accum - eval1_accum * curve_type::template g1_type<>::value_type::one());

                        auto A_1 = algebra::precompute_g1<curve_type>(F + z0 * proof.commit0 + z1 * r * proof.commit1);
                        auto A_2 = algebra::precompute_g2<curve_type>(curve_type::template g2_type<>::value_type::one());
                        auto B_1 = algebra::precompute_g1<curve_type>(-proof.commit0 - r * proof.commit1);
                        auto B_2 = algebra::precompute_g2<curve_type>(srs.verification_key);

                        gt_value_type gt3 = algebra::double_miller_loop<curve_type>(A_1, A_2, B_1, B_2);
                        gt_value_type gt_4 = algebra::final_exponentiation<curve_type>(gt3);

                        return gt_4 == gt_value_type::one();
                    }
                };
            };    // namespace commitments
        }         // namespace zk
    }             // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_COMMITMENTS_KZG_HPP
