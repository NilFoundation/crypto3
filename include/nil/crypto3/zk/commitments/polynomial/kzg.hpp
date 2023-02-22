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
#include <nil/crypto3/algebra/curves/detail/marshalling.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>

using namespace nil::crypto3;

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {

                /**
                 * @brief The KZG Polynomial Commitment with Fiat-Shamir heuristic.
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
                    using field_type = typename curve_type::scalar_field_type;
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
                    struct public_key_type {
                        commitment_type commit;
                        scalar_value_type z;
                        scalar_value_type eval;
                        public_key_type() {}
                        public_key_type(commitment_type c, scalar_value_type z, scalar_value_type e)
                                    : commit(c), z(z), eval(e) {}
                        public_key_type operator=(const public_key_type &other) {
                            eval = other.eval;
                            commit = other.commit;
                            z = other.z;
                            return *this;
                        }
                    };
                };
            } // namespace commitments

            namespace algorithms {
                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::kzg<typename KZG::curve_type>, KZG>::value,
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
                                 commitments::kzg<typename KZG::curve_type>, KZG>::value,
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
                                 commitments::kzg<typename KZG::curve_type>, KZG>::value,
                             bool>::type = true>
                static typename KZG::proof_type proof_eval(typename KZG::params_type params,
                                            const typename math::polynomial<typename KZG::scalar_value_type> &f,
                                            typename KZG::scalar_value_type z) {

                    const typename math::polynomial<typename KZG::scalar_value_type> denominator_polynom = {-z, 1};

                    typename math::polynomial<typename KZG::scalar_value_type> q = f;
                    q[0] -= f.evaluate(z);
                    auto r = q % denominator_polynom;
                    if (r != typename KZG::scalar_value_type(0)) {
                        throw std::runtime_error("incorrect eval or point z");
                    }
                    q = q / denominator_polynom;

                    return commit<KZG>(params, q);
                }

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::kzg<typename KZG::curve_type>, KZG>::value,
                             bool>::type = true>
                static typename KZG::proof_type proof_eval(typename KZG::params_type params,
                                const typename math::polynomial<typename KZG::scalar_value_type> &f,
                                typename KZG::public_key_type &pk) {

                    return proof_eval<KZG>(params, f, pk.z);
                }

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::kzg<typename KZG::curve_type>, KZG>::value,
                             bool>::type = true>
                static bool verify_eval(const typename KZG::params_type &params,
                                        const typename KZG::proof_type &proof,
                                        const typename KZG::public_key_type &public_key) {

                    auto A_1 = algebra::precompute_g1<typename KZG::curve_type>(proof);
                    auto A_2 = algebra::precompute_g2<typename KZG::curve_type>(params.verification_key -
                                                                    public_key.z * KZG::curve_type::template g2_type<>::value_type::one());
                    auto B_1 = algebra::precompute_g1<typename KZG::curve_type>(public_key.eval * KZG::curve_type::template g1_type<>::value_type::one() -
                                                                    public_key.commit);
                    auto B_2 = algebra::precompute_g2<typename KZG::curve_type>(KZG::curve_type::template g2_type<>::value_type::one());

                    typename KZG::gt_value_type gt3 = algebra::double_miller_loop<typename KZG::curve_type>(A_1, A_2, B_1, B_2);
                    typename KZG::gt_value_type gt_4 = algebra::final_exponentiation<typename KZG::curve_type>(gt3);

                    return gt_4 == KZG::gt_value_type::one();
                }
            } // namespace algorithms 

            namespace commitments {

                /**
                 * @brief Based on the KZG Commitment.
                 *
                 * References:
                 * "PlonK: Permutations over Lagrange-bases for
                 * Oecumenical Noninteractive arguments of Knowledge",
                 * Ariel Gabizon, Zachary J. Williamson, Oana Ciobotaru,
                 * <https://eprint.iacr.org/2019/953.pdf>
                 */
                template<typename CurveType, typename TranscriptHashType, std::size_t BatchSize>
                struct batched_kzg : public kzg<CurveType> {

                    typedef CurveType curve_type;
                    typedef TranscriptHashType transcript_hash_type;
                    constexpr static const std::size_t batch_size = BatchSize;
                    typedef typename curve_type::gt_type::value_type gt_value_type;

                    using multiexp_method = typename algebra::policies::multiexp_method_BDLO12;
                    using scalar_value_type = typename curve_type::scalar_field_type::value_type;
                    using commitment_key_type = std::vector<typename curve_type::template g1_type<>::value_type>;
                    using verification_key_type = typename curve_type::template g2_type<>::value_type;
                    using commitment_type = typename curve_type::template g1_type<>::value_type;
                    using batch_of_batches_of_polynomials_type = std::array<std::vector<typename math::polynomial<scalar_value_type>>, batch_size>;
                    using evals_type = std::array<std::vector<scalar_value_type>, batch_size>;
                    using batched_proof_type = std::array<commitment_type, batch_size>;
                    
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<TranscriptHashType>;
                    using serializer = typename nil::marshalling::curve_element_serializer<curve_type>;

                    using basic_kzg = kzg<CurveType>;  
                    using params_type = typename basic_kzg::params_type;

                    struct batched_public_key_type {
                        std::array<std::vector<commitment_type>, batch_size> commits;
                        std::array<scalar_value_type, batch_size> zs;
                        evals_type evals;
                        batched_public_key_type() {};
                        batched_public_key_type(std::array<commitment_type, batch_size> commitments,
                            std::array<scalar_value_type, batch_size> zs, evals_type evals) : commits(commitments), zs(zs), evals(evals) {};
                        batched_public_key_type operator=(const batched_public_key_type &other) {
                            commits = other.commits;
                            zs = other.zs;
                            evals = other.evals;
                            return *this;
                        }
                    };
                };
            } // namespace commitments

            namespace algorithms {
                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::batched_kzg<typename KZG::curve_type,
                                 typename KZG::transcript_hash_type, KZG::batch_size>,
                                 KZG>::value,
                             bool>::type = true>
                static typename KZG::transcript_type setup_transcript(const typename KZG::params_type &params) {
                    typename KZG::transcript_type transcript = typename KZG::transcript_type();
                    for (auto g1_elem : params.commitment_key) {
                        transcript(KZG::serializer::point_to_octets(g1_elem));
                    }
                    transcript(KZG::serializer::point_to_octets(params.verification_key));

                    return transcript;
                }

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::batched_kzg<typename KZG::curve_type,
                                 typename KZG::transcript_hash_type, KZG::batch_size>,
                                 KZG>::value,
                             bool>::type = true>
                static typename math::polynomial<typename KZG::scalar_value_type>
                    accumulate(const std::vector<typename math::polynomial<typename KZG::scalar_value_type>> &polys,
                                typename KZG::scalar_value_type factor) {
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
                                 commitments::batched_kzg<typename KZG::curve_type,
                                 typename KZG::transcript_hash_type, KZG::batch_size>,
                                 KZG>::value,
                             bool>::type = true>
                static typename KZG::evals_type evaluate_polynomials(const typename KZG::batch_of_batches_of_polynomials_type &polys,
                                                        const std::array<typename KZG::scalar_value_type, KZG::batch_size> zs) {

                    typename KZG::evals_type evals;
                    for (std::size_t i = 0; i < KZG::batch_size; ++i) {
                        std::vector<typename KZG::scalar_value_type> evals_at_z_i;
                        for (const auto &poly : polys[i]) {
                            evals_at_z_i.push_back(poly.evaluate(zs[i]));
                        }
                        evals[i] = evals_at_z_i;
                    }

                    return evals;
                }

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::batched_kzg<typename KZG::curve_type,
                                 typename KZG::transcript_hash_type, KZG::batch_size>,
                                 KZG>::value,
                             bool>::type = true>
                static std::vector<typename KZG::commitment_type>
                    commit(const typename KZG::params_type &params, 
                            const std::vector<typename math::polynomial<typename KZG::scalar_value_type>> &polys) {
                    std::vector<typename KZG::commitment_type> commitments;
                    for (const auto &poly : polys) {
                        commitments.push_back(commit<KZG>(params, poly));
                    }
                    return commitments;
                }
                
                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::batched_kzg<typename KZG::curve_type,
                                 typename KZG::transcript_hash_type, KZG::batch_size>,
                                 KZG>::value,
                             bool>::type = true>
                static typename KZG::batched_public_key_type setup_public_key(const typename KZG::params_type &params, 
                                                        const typename KZG::batch_of_batches_of_polynomials_type &polys,
                                                        const std::array<typename KZG::scalar_value_type, KZG::batch_size> zs) {
                    typename KZG::batched_public_key_type pk;
                    std::array<typename KZG::evals_type, KZG::batch_size> evals;
                    for (int i = 0; i < KZG::batch_size; ++i) {
                        pk.commits[i] = commit<KZG>(params, polys[i]);
                    }
                    pk.zs = zs;
                    pk.evals = evaluate_polynomials<KZG>(polys, zs);

                    return pk;
                }

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::batched_kzg<typename KZG::curve_type,
                                 typename KZG::transcript_hash_type, KZG::batch_size>,
                                 KZG>::value,
                             bool>::type = true>
                static typename KZG::batched_proof_type proof_eval(const typename KZG::params_type &params, 
                                const typename KZG::batch_of_batches_of_polynomials_type &polys,
                                typename KZG::batched_public_key_type &public_key,
                                typename KZG::transcript_type &transcript) {
            
                    typename KZG::batched_proof_type proof;

                    for (std::size_t i = 0; i < KZG::batch_size; ++i) {
                        auto commits = commit<KZG>(params, polys[i]);
                        for (const auto &commit : commits) {
                            transcript(KZG::serializer::point_to_octets(commit));
                        }
                        auto gamma = transcript.template challenge<typename KZG::curve_type::scalar_field_type>();
                        auto accum = accumulate<KZG>(polys[i], gamma);
                        proof[i] = proof_eval<KZG>(params, accum, public_key.zs[i]);
                    }
                    
                    return proof;
                }

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::batched_kzg<typename KZG::curve_type,
                                 typename KZG::transcript_hash_type, KZG::batch_size>,
                                 KZG>::value,
                             bool>::type = true>
                static bool verify_eval(typename KZG::params_type params,
                                        const typename KZG::batched_proof_type &proof,
                                        const typename KZG::batched_public_key_type &public_key,
                                        typename KZG::transcript_type &transcript) {

                    std::array<typename KZG::scalar_value_type, KZG::batch_size> gammas;
                    for (std::size_t i = 0; i < KZG::batch_size; ++i) {
                        for (const auto &commit : public_key.commits[i]) {
                            transcript(KZG::serializer::point_to_octets(commit));
                        }
                        gammas[i] = transcript.template challenge<typename KZG::curve_type::scalar_field_type>();
                    }
                    typename KZG::scalar_value_type r = algebra::random_element<typename KZG::curve_type::scalar_field_type>();
                    
                    auto F = KZG::curve_type::template g1_type<>::value_type::zero();
                    auto z_r_proofs = KZG::curve_type::template g1_type<>::value_type::zero();
                    auto r_proofs = KZG::curve_type::template g1_type<>::value_type::zero();
                    auto cur_r = KZG::scalar_value_type::one();
                    for (std::size_t i = 0; i < KZG::batch_size; ++i) {
                        auto eval_accum = public_key.evals[i].back();
                        auto comm_accum = public_key.commits[i].back();
                        for (int j = public_key.commits[i].size() - 2; j >= 0; --j) {
                            comm_accum = (gammas[i] * comm_accum) + public_key.commits[i][j];
                            eval_accum = (eval_accum * gammas[i]) + public_key.evals[i][j];
                        }
                        F = F + cur_r * (comm_accum - eval_accum * KZG::curve_type::template g1_type<>::value_type::one());
                        z_r_proofs = z_r_proofs + cur_r * public_key.zs[i] * proof[i];
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
            } // namespace algorithms
        }         // namespace zk
    }             // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_COMMITMENTS_KZG_HPP
