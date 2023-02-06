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
                            commitment_key.push_back(alpha_scaled * (curve_type::template g1_type<>::value_type::one()));
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
                    using batched_proof_type = std::vector<commitment_type>;
                    using evals_type = std::vector<std::vector<scalar_value_type>>;
                    using batch_of_batches_of_polynomials_type = std::vector<std::vector<polynomial<scalar_value_type>>>;

                    using kzg = kzg_commitment<CurveType>;
                    using kzg_params_type = typename kzg::kzg_params_type;  
                    using srs_type = typename kzg::srs_type;

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

                    static evals_type evaluate_polynomials(const batch_of_batches_of_polynomials_type &polys,
                                                            const std::vector<scalar_value_type> zs) {

                        assert(polys.size() == zs.size());

                        std::vector<std::vector<scalar_value_type>> evals;
                        for (std::size_t i = 0; i < polys.size(); ++i) {
                            std::vector<scalar_value_type> evals_at_z_i;
                            for (const auto &poly : polys[i]) {
                                evals_at_z_i.push_back(poly.evaluate(zs[i]));
                            }
                            evals.push_back(evals_at_z_i);
                        }

                        return evals;
                    }

                    static std::vector<commitment_type> commit(const srs_type &srs, 
                                                                const std::vector<polynomial<scalar_value_type>> &polys) {
                        std::vector<commitment_type> commitments;
                        for (const auto &poly : polys) {
                            commitments.push_back(kzg::commit(srs, poly));
                        }
                        return commitments;
                    }

                    static batched_proof_type proof_eval(const srs_type &srs, 
                                                        const batch_of_batches_of_polynomials_type &polys,
                                                        const evals_type &evals,
                                                        const std::vector<scalar_value_type> zs,
                                                        const std::vector<scalar_value_type> gammas) {
                        
                        std::vector<commitment_type> proofs;

                        for (std::size_t i = 0; i < polys.size(); ++i) {
                            auto accum = accumulate(polys[i], gammas[i]);
                            auto accum_eval = polynomial<scalar_value_type>{evals[i]}.evaluate(gammas[i]);
                            typename kzg::proof_type proof = kzg::proof_eval(srs, accum, zs[i], accum_eval);
                            proofs.push_back(proof);
                        }
                        
                        return proofs;
                    }

                    static bool verify_eval(srs_type srs,
                                            const batched_proof_type &proof,
                                            const evals_type &evals,
                                            const std::vector<std::vector<commitment_type>> &commits,
                                            std::vector<scalar_value_type> zs,
                                            std::vector<scalar_value_type> gammas,
                                            scalar_value_type r) {
                        
                        auto F = curve_type::template g1_type<>::value_type::zero();
                        auto z_r_proofs = curve_type::template g1_type<>::value_type::zero();
                        auto r_proofs = curve_type::template g1_type<>::value_type::zero();
                        auto cur_r = scalar_value_type::one();
                        for (std::size_t i = 0; i < proof.size(); ++i) {
                            auto eval_accum = evals[i].back();
                            auto comm_accum = commits[i].back();
                            for (int j = commits[i].size() - 2; j >= 0; --j) {
                                comm_accum = (gammas[i] * comm_accum) + commits[i][j];
                                eval_accum = (eval_accum * gammas[i]) + evals[i][j];
                            }
                            F = F + cur_r * (comm_accum - eval_accum * curve_type::template g1_type<>::value_type::one());
                            z_r_proofs = z_r_proofs + cur_r * zs[i] * proof[i];
                            r_proofs = r_proofs - cur_r * proof[i];
                            cur_r = cur_r * r;
                        }

                        auto A_1 = algebra::precompute_g1<curve_type>(F + z_r_proofs);
                        auto A_2 = algebra::precompute_g2<curve_type>(curve_type::template g2_type<>::value_type::one());
                        auto B_1 = algebra::precompute_g1<curve_type>(r_proofs);
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
