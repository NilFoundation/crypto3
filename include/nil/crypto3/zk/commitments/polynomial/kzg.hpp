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

#include <nil/crypto3/math/polynomial/polynomial.hpp>

using namespace nil::crypto3;

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {

                /**
                 * @brief The KZG Polynomial Commitment..
                 *
                 * References:
                 * "Constant-Size Commitments to Polynomials and
                 * Their Applications",
                 * Aniket Kate, Gregory M. Zaverucha, and Ian Goldberg,
                 * <https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf>
                 */
                template<typename CurveType>
                struct kzg {

                    typedef CurveType curve_type;
                    typedef typename curve_type::gt_type::value_type gt_value_type;

                    using multiexp_method = typename algebra::policies::multiexp_method_BDLO12;
                    using scalar_value_type = typename curve_type::scalar_field_type::value_type;
                    using commitment_key_type = std::vector<typename curve_type::template g1_type<>::value_type>;
                    using verification_key_type = typename curve_type::template g2_type<>::value_type;
                    using commitment_type = typename curve_type::template g1_type<>::value_type;
                    using proof_type = commitment_type;

                    struct params_type {
                        commitment_key_type commitment_key;
                        verification_key_type verification_key;
                        params_type(commitment_key_type ck, verification_key_type vk) :
                            commitment_key(ck), verification_key(vk) {}
                    };
                };
            } // namespace commitments

            namespace algorithms {
                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::kzg<typename KZG::curve_type>,
                                 KZG>::value,
                             bool>::type = true>
                static typename KZG::params_type setup(std::size_t max_degree, typename KZG::scalar_value_type alpha) {
                    typename KZG::scalar_value_type alpha_scaled = alpha;
                    typename KZG::commitment_key_type commitment_key = {KZG::curve_type::template g1_type<>::value_type::one()};
                    typename KZG::verification_key_type verification_key =
                        KZG::curve_type::template g2_type<>::value_type::one() * alpha;

                    for (std::size_t i = 0; i < max_degree; i++) {
                        commitment_key.push_back(alpha_scaled * (KZG::curve_type::template g1_type<>::value_type::one()));
                        alpha_scaled = alpha_scaled * alpha;
                    }

                    return typename KZG::params_type(commitment_key, verification_key);
                }

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::kzg<typename KZG::curve_type>,
                                 KZG>::value,
                             bool>::type = true>
                static typename KZG::commitment_type commit(const typename KZG::params_type &params,
                                                const typename math::polynomial<typename KZG::scalar_value_type> &f) {
                    BOOST_ASSERT(f.size() <= params.commitment_key.size());
                    return algebra::multiexp<typename KZG::multiexp_method>(params.commitment_key.begin(),
                                            params.commitment_key.begin() + f.size(), f.begin(), f.end(), 1);
                }

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::kzg<typename KZG::curve_type>,
                                 KZG>::value,
                             bool>::type = true>
                static typename KZG::proof_type proof_eval(typename KZG::params_type params,
                                            const typename math::polynomial<typename KZG::scalar_value_type> &f,
                                            typename KZG::scalar_value_type i,
                                            typename KZG::scalar_value_type eval) {

                    const typename math::polynomial<typename KZG::scalar_value_type> denominator_polynom = {-i, 1};

                    typename math::polynomial<typename KZG::scalar_value_type> q = f;
                    q[0] -= eval;
                    auto r = q % denominator_polynom;
                    if (r != typename KZG::scalar_value_type(0)) {
                        throw std::runtime_error("incorrect eval or point i");
                    }
                    q = q / denominator_polynom;

                    return commit<KZG>(params, q);
                }

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::kzg<typename KZG::curve_type>,
                                 KZG>::value,
                             bool>::type = true>
                static bool verify_eval(typename KZG::params_type params,
                                        typename KZG::proof_type p,
                                        typename KZG::commitment_type C_f,
                                        typename KZG::scalar_value_type i,
                                        typename KZG::scalar_value_type eval) {
                    auto A_1 = algebra::precompute_g1<typename KZG::curve_type>(p);
                    auto A_2 = algebra::precompute_g2<typename KZG::curve_type>(params.verification_key -
                                                                    i * KZG::curve_type::template g2_type<>::value_type::one());
                    auto B_1 = algebra::precompute_g1<typename KZG::curve_type>(eval * KZG::curve_type::template g1_type<>::value_type::one() -
                                                                    C_f);
                    auto B_2 = algebra::precompute_g2<typename KZG::curve_type>(KZG::curve_type::template g2_type<>::value_type::one());

                    typename KZG::gt_value_type gt3 = algebra::double_miller_loop<typename KZG::curve_type>(A_1, A_2, B_1, B_2);
                    typename KZG::gt_value_type gt_4 = algebra::final_exponentiation<typename KZG::curve_type>(gt3);

                    return gt_4 == KZG::gt_value_type::one();
                }
            } // namespace algorithms 

            namespace commitments {

                template<std::size_t BatchSize>
                struct batched_kzg_params {
                    constexpr static const std::size_t batch_size = BatchSize;
                };

                /**
                 * @brief Based on the KZG Commitment.
                 *
                 * References:
                 * "PlonK: Permutations over Lagrange-bases for
                 * Oecumenical Noninteractive arguments of Knowledge",
                 * Ariel Gabizon, Zachary J. Williamson, Oana Ciobotaru,
                 * <https://eprint.iacr.org/2019/953.pdf>
                 */
                template<typename CurveType, typename KZGParams>
                struct batched_kzg : public kzg<CurveType> {

                    typedef CurveType curve_type;
                    typedef KZGParams kzg_type;
                    constexpr static const std::size_t batch_size = KZGParams::batch_size;
                    typedef typename curve_type::gt_type::value_type gt_value_type;

                    using multiexp_method = typename algebra::policies::multiexp_method_BDLO12;
                    using scalar_value_type = typename curve_type::scalar_field_type::value_type;
                    using commitment_key_type = std::vector<typename curve_type::template g1_type<>::value_type>;
                    using verification_key_type = typename curve_type::template g2_type<>::value_type;
                    using commitment_type = typename curve_type::template g1_type<>::value_type;
                    using batched_proof_type = std::vector<commitment_type>;
                    using evals_type = std::vector<std::vector<scalar_value_type>>;
                    using batch_of_batches_of_polynomials_type = std::vector<std::vector<typename math::polynomial<scalar_value_type>>>;

                    using basic_kzg = kzg<CurveType>;  
                    using params_type = typename basic_kzg::params_type;
                };
            } // namespace commitments

            namespace algorithms {

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::batched_kzg<typename KZG::curve_type, typename KZG::kzg_type>,
                                 KZG>::value,
                             bool>::type = true>
                static typename math::polynomial<typename KZG::scalar_value_type> accumulate(const std::vector<typename math::polynomial<typename KZG::scalar_value_type>> &polys,
                                                                const typename KZG::scalar_value_type &factor) {
                    std::size_t num = polys.size();
                    if (num == 1) return polys[0];

                    typename math::polynomial<typename KZG::scalar_value_type> result = polys[num - 1];
                    for (int i = num - 2; i >= 0; --i) {
                        result = result * factor + polys[i];
                    }
                    return result;
                }

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::batched_kzg<typename KZG::curve_type, typename KZG::kzg_type>,
                                 KZG>::value,
                             bool>::type = true>
                static typename KZG::evals_type evaluate_polynomials(const typename KZG::batch_of_batches_of_polynomials_type &polys,
                                                        const std::vector<typename KZG::scalar_value_type> zs) {

                    BOOST_ASSERT(polys.size() == zs.size());

                    std::vector<std::vector<typename KZG::scalar_value_type>> evals;
                    for (std::size_t i = 0; i < polys.size(); ++i) {
                        std::vector<typename KZG::scalar_value_type> evals_at_z_i;
                        for (const auto &poly : polys[i]) {
                            evals_at_z_i.push_back(poly.evaluate(zs[i]));
                        }
                        evals.push_back(evals_at_z_i);
                    }

                    return evals;
                }

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::batched_kzg<typename KZG::curve_type, typename KZG::kzg_type>,
                                 KZG>::value,
                             bool>::type = true>
                static std::vector<typename KZG::commitment_type> commit(const typename KZG::params_type &params, 
                                                            const std::vector<typename math::polynomial<typename KZG::scalar_value_type>> &polys) {
                    std::vector<typename KZG::commitment_type> commitments;
                    for (const auto &poly : polys) {
                        commitments.push_back(commit<typename KZG::basic_kzg>(params, poly));
                    }
                    return commitments;
                }

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::batched_kzg<typename KZG::curve_type, typename KZG::kzg_type>,
                                 KZG>::value,
                             bool>::type = true>
                static typename KZG::batched_proof_type proof_eval(const typename KZG::params_type &params, 
                                                    const typename KZG::batch_of_batches_of_polynomials_type &polys,
                                                    const typename KZG::evals_type &evals,
                                                    const std::vector<typename KZG::scalar_value_type> zs,
                                                    const std::vector<typename KZG::scalar_value_type> gammas) {
                    
                    BOOST_ASSERT(polys.size() == evals.size());
                    BOOST_ASSERT(polys.size() == gammas.size());
                    std::vector<typename KZG::commitment_type> proofs;

                    for (std::size_t i = 0; i < polys.size(); ++i) {
                        auto accum = accumulate<KZG>(polys[i], gammas[i]);
                        auto accum_eval = typename math::polynomial<typename KZG::scalar_value_type>{evals[i]}.evaluate(gammas[i]);
                        typename KZG::basic_kzg::proof_type proof = proof_eval<typename KZG::basic_kzg>(params, accum, zs[i], accum_eval);
                        proofs.push_back(proof);
                    }
                    
                    return proofs;
                }

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::batched_kzg<typename KZG::curve_type, typename KZG::kzg_type>,
                                 KZG>::value,
                             bool>::type = true>
                static bool verify_eval(typename KZG::params_type params,
                                        const typename KZG::batched_proof_type &proof,
                                        const typename KZG::evals_type &evals,
                                        const std::vector<std::vector<typename KZG::commitment_type>> &commits,
                                        std::vector<typename KZG::scalar_value_type> zs,
                                        std::vector<typename KZG::scalar_value_type> gammas,
                                        typename KZG::scalar_value_type r) {
                    
                    auto F = KZG::curve_type::template g1_type<>::value_type::zero();
                    auto z_r_proofs = KZG::curve_type::template g1_type<>::value_type::zero();
                    auto r_proofs = KZG::curve_type::template g1_type<>::value_type::zero();
                    auto cur_r = KZG::scalar_value_type::one();
                    for (std::size_t i = 0; i < proof.size(); ++i) {
                        auto eval_accum = evals[i].back();
                        auto comm_accum = commits[i].back();
                        for (int j = commits[i].size() - 2; j >= 0; --j) {
                            comm_accum = (gammas[i] * comm_accum) + commits[i][j];
                            eval_accum = (eval_accum * gammas[i]) + evals[i][j];
                        }
                        F = F + cur_r * (comm_accum - eval_accum * KZG::curve_type::template g1_type<>::value_type::one());
                        z_r_proofs = z_r_proofs + cur_r * zs[i] * proof[i];
                        r_proofs = r_proofs - cur_r * proof[i];
                        cur_r = cur_r * r;
                    }

                    auto A_1 = algebra::precompute_g1<typename KZG::curve_type>(F + z_r_proofs);
                    auto A_2 = algebra::precompute_g2<typename KZG::curve_type>(KZG::curve_type::template g2_type<>::value_type::one());
                    auto B_1 = algebra::precompute_g1<typename KZG::curve_type>(r_proofs);
                    auto B_2 = algebra::precompute_g2<typename KZG::curve_type>(params.verification_key);

                    typename KZG::gt_value_type gt3 = algebra::double_miller_loop<typename KZG::curve_type>(A_1, A_2, B_1, B_2);
                    typename KZG::gt_value_type gt_4 = algebra::final_exponentiation<typename KZG::curve_type>(gt3);

                    return gt_4 == KZG::gt_value_type::one();
                }
            }     // namespace algorithms
        }         // namespace zk
    }             // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_COMMITMENTS_KZG_HPP
