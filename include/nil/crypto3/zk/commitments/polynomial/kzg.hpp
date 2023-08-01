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
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/algebra/type_traits.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/algebra/multiexp/multiexp.hpp>
#include <nil/crypto3/algebra/multiexp/policies.hpp>
#include <nil/crypto3/algebra/curves/detail/marshalling.hpp>
#include <nil/crypto3/algebra/marshalling.hpp>

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
                        params_type() {}
                        params_type(std::size_t d) {
                            auto alpha = algebra::random_element<field_type>();
                            verification_key = verification_key_type::one() * alpha;
                            commitment_key.resize(d);
                            auto alpha_com = commitment_type::one();
                            for (std::size_t i = 0; i < d; i++) {
                                commitment_key[i] = alpha_com;
                                alpha_com = alpha * alpha_com;
                            }
                        }
                        params_type(std::size_t d, scalar_value_type alpha) {
                            verification_key = verification_key_type::one() * alpha;
                            commitment_key.resize(d);
                            auto alpha_com = commitment_type::one();
                            for (std::size_t i = 0; i < d; i++) {
                                commitment_key[i] = alpha_com;
                                alpha_com = alpha * alpha_com;
                            }
                        }
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
                 * @brief Based on the KZG Commitment from [KZG10].
                 *
                 * References:
                 * "Efficient polynomial commitment schemes for
                 * multiple points and polynomials",
                 * Dan Boneh, Justin Drake, Ben Fisch,
                 * <https://eprint.iacr.org/2020/081.pdf>
                 */
                template<typename CurveType, typename TranscriptHashType, std::size_t BatchSize>
                struct batched_kzg {

                    typedef CurveType curve_type;
                    typedef TranscriptHashType transcript_hash_type;
                    constexpr static const std::size_t batch_size = BatchSize;
                    typedef typename curve_type::gt_type::value_type gt_value_type;

                    using multiexp_method = typename algebra::policies::multiexp_method_BDLO12;
                    using field_type = typename curve_type::scalar_field_type;
                    using scalar_value_type = typename curve_type::scalar_field_type::value_type;
                    using verification_type = typename curve_type::template g2_type<>::value_type;
                    using commitment_type = typename curve_type::template g1_type<>::value_type;
                    using batch_of_polynomials_type = std::array<typename math::polynomial<scalar_value_type>, batch_size>;
                    using evals_type = std::array<std::vector<scalar_value_type>, batch_size>;
                    using proof_type = commitment_type;
                    
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<TranscriptHashType>;
                    using serializer = typename nil::marshalling::curve_element_serializer<curve_type>;

                    const static std::size_t scalar_blob_size = field_type::arity * (field_type::modulus_bits / 8 + (field_type::modulus_bits % 8 ? 1 : 0));
                    using bincode = typename nil::marshalling::bincode::field<field_type>;

                    struct params_type {
                        std::vector<commitment_type> commitment_key;
                        std::vector<verification_type> verification_key;
                        params_type() {};
                        params_type(std::size_t d, std::size_t t) {
                            auto alpha = algebra::random_element<typename curve_type::scalar_field_type>();
                            commitment_key.resize(d);
                            verification_key.resize(t + 1);
                            auto alpha_comm = commitment_type::one();
                            for (std::size_t i = 0; i < d; ++i) {
                                commitment_key[i] = alpha_comm;
                                alpha_comm = alpha * alpha_comm;
                            }
                            auto alpha_ver = verification_type::one();
                            for (std::size_t i = 0; i <= t; ++i) {
                                verification_key[i] = alpha_ver;
                                alpha_ver = alpha * alpha_ver;
                            }
                        }
                        params_type(std::size_t d, std::size_t t, scalar_value_type alpha) {
                            commitment_key.resize(d);
                            verification_key.resize(t + 1);
                            auto alpha_comm = commitment_type::one();
                            for (std::size_t i = 0; i < d; ++i) {
                                commitment_key[i] = alpha_comm;
                                alpha_comm = alpha * alpha_comm;
                            }
                            auto alpha_ver = verification_type::one();
                            for (std::size_t i = 0; i <= t; ++i) {
                                verification_key[i] = alpha_ver;
                                alpha_ver = alpha * alpha_ver;
                            }
                        }
                        params_type(std::vector<commitment_type> commitment_key, std::vector<verification_type> verification_key) :
                                    commitment_key(commitment_key), verification_key(verification_key) {};
                        params_type operator=(const params_type &other) {
                            commitment_key = other.commitment_key;
                            verification_key = other.verification_key;
                            return *this;
                        }
                    };

                    struct public_key_type {
                        std::array<commitment_type, batch_size> commits;
                        std::vector<scalar_value_type> T;
                        std::array<std::vector<scalar_value_type>, batch_size> S;
                        std::array<math::polynomial<scalar_value_type>, batch_size> r;
                        public_key_type() {};
                        public_key_type(std::array<commitment_type, batch_size> commits,
                                                std::vector<scalar_value_type> T,
                                                std::array<std::vector<scalar_value_type>, batch_size> S,
                                                std::array<math::polynomial<scalar_value_type>, batch_size> r) :
                                                commits(commits), T(T), S(S), r(r) {};
                        public_key_type operator=(const public_key_type &other) {
                            commits = other.commits;
                            T = other.T;
                            S = other.S;
                            r = other.r;
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
                    for (auto g2_elem : params.verification_key) {
                        transcript(KZG::serializer::point_to_octets(g2_elem));
                    }

                    return transcript;
                }
                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::batched_kzg<typename KZG::curve_type,
                                 typename KZG::transcript_hash_type, KZG::batch_size>,
                                 KZG>::value,
                             bool>::type = true>
                static void update_transcript(const typename KZG::public_key_type &public_key,
                                            typename KZG::transcript_type &transcript) {
                    std::vector<std::uint8_t> byteblob(KZG::scalar_blob_size);

                    for (const auto commit : public_key.commits) {
                        transcript(KZG::serializer::point_to_octets(commit));
                    }
                    for (const auto S : public_key.S) {
                        for (const auto s : S) {
                            KZG::bincode::template field_element_to_bytes<std::vector<std::uint8_t>::iterator>(s, byteblob.begin(), byteblob.end());
                            transcript(byteblob);
                        }
                    }
                    for (const auto r : public_key.r) {
                        for (std::size_t i = 0; i < r.size(); ++i) {
                            KZG::bincode::template field_element_to_bytes<std::vector<std::uint8_t>::iterator>(r[i], byteblob.begin(), byteblob.end());
                            transcript(byteblob);
                        }
                    }
                }

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::batched_kzg<typename KZG::curve_type,
                                 typename KZG::transcript_hash_type, KZG::batch_size>,
                                 KZG>::value,
                             bool>::type = true>
                static typename std::array<math::polynomial<typename KZG::scalar_value_type>, KZG::batch_size>
                    create_evals_polys(const typename KZG::batch_of_polynomials_type &polys,
                                        const std::array<std::vector<typename KZG::scalar_value_type>, KZG::batch_size> S) {
                    std::array<math::polynomial<typename KZG::scalar_value_type>, KZG::batch_size> rs;
                    for (std::size_t i = 0; i < KZG::batch_size; ++i) {
                        typename std::vector<std::pair<typename KZG::scalar_value_type, typename KZG::scalar_value_type>> evals;
                        for (auto s : S[i]) {
                            evals.push_back(std::make_pair(s, polys[i].evaluate(s)));
                        }
                        rs[i] = math::lagrange_interpolation(evals);
                    }
                    return rs;
                }

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::batched_kzg<typename KZG::curve_type,
                                 typename KZG::transcript_hash_type, KZG::batch_size>,
                                 KZG>::value,
                             bool>::type = true>
                static typename KZG::commitment_type commit(const typename KZG::params_type &params, 
                                                            const typename math::polynomial<typename KZG::scalar_value_type> &poly) {
                    BOOST_ASSERT(poly.size() <= params.commitment_key.size());
                    return algebra::multiexp<typename KZG::multiexp_method>(params.commitment_key.begin(),
                                    params.commitment_key.begin() + poly.size(), poly.begin(), poly.end(), 1);
                }

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::batched_kzg<typename KZG::curve_type,
                                 typename KZG::transcript_hash_type, KZG::batch_size>,
                                 KZG>::value,
                             bool>::type = true>
                static std::array<typename KZG::commitment_type, KZG::batch_size>
                    commit(const typename KZG::params_type &params, 
                            const std::array<typename math::polynomial<typename KZG::scalar_value_type>, KZG::batch_size> &polys) {
                    std::array<typename KZG::commitment_type, KZG::batch_size> commitments;
                    for (std::size_t i = 0; i < KZG::batch_size; ++i) {
                        BOOST_ASSERT(polys[i].size() <= params.commitment_key.size());
                        commitments[i] = commit<KZG>(params, polys[i]);
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
                static typename KZG::verification_type commit_g2(const typename KZG::params_type &params, 
                                                            typename math::polynomial<typename KZG::scalar_value_type> poly) {
                    BOOST_ASSERT(poly.size() <= params.verification_key.size());
                    auto result = algebra::multiexp<typename KZG::multiexp_method>(params.verification_key.begin(),
                                    params.verification_key.begin() + poly.size(), poly.begin(), poly.end(), 1);
                    return result;
                }

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::batched_kzg<typename KZG::curve_type,
                                 typename KZG::transcript_hash_type, KZG::batch_size>,
                                 KZG>::value,
                             bool>::type = true>
                static typename math::polynomial<typename KZG::scalar_value_type>
                    create_polynom_by_zeros(const std::vector<typename KZG::scalar_value_type> S) {
                    assert(S.size() > 0);
                    typename math::polynomial<typename KZG::scalar_value_type> Z = {-S[0], 1};
                    for (std::size_t i = 1; i < S.size(); ++i) {
                        Z = Z * typename math::polynomial<typename KZG::scalar_value_type>({-S[i], 1});
                    }
                    return Z;
                }

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::batched_kzg<typename KZG::curve_type,
                                 typename KZG::transcript_hash_type, KZG::batch_size>,
                                 KZG>::value,
                             bool>::type = true>
                static typename math::polynomial<typename KZG::scalar_value_type>
                    set_difference_polynom(std::vector<typename KZG::scalar_value_type> T,
                                            std::vector<typename KZG::scalar_value_type> S) {
                    std::sort(T.begin(), T.end());
                    std::sort(S.begin(), S.end());
                    std::vector<typename KZG::scalar_value_type> result;
                    std::set_difference(T.begin(), T.end(), S.begin(), S.end(), std::back_inserter(result));
                    if (result.size() == 0) {
                        return typename math::polynomial<typename KZG::scalar_value_type>({{1}});
                    }
                    return create_polynom_by_zeros<KZG>(result);
                }

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::batched_kzg<typename KZG::curve_type,
                                 typename KZG::transcript_hash_type, KZG::batch_size>,
                                 KZG>::value,
                             bool>::type = true>
                static std::vector<typename KZG::scalar_value_type>
                    merge_eval_points(std::array<std::vector<typename KZG::scalar_value_type>, KZG::batch_size> S) {
                    std::set<typename KZG::scalar_value_type> result;
                    for (std::size_t i = 0; i < KZG::batch_size; ++i) {
                        result.insert(S[i].begin(), S[i].end());
                    }
                    return std::vector<typename KZG::scalar_value_type>(result.begin(), result.end());
                }

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::batched_kzg<typename KZG::curve_type,
                                 typename KZG::transcript_hash_type, KZG::batch_size>,
                                 KZG>::value,
                             bool>::type = true>
                static typename KZG::commitment_type
                    proof_eval(const typename KZG::params_type &params, 
                                const typename KZG::batch_of_polynomials_type &polys,
                                typename KZG::public_key_type &public_key,
                                typename KZG::transcript_type &transcript) {
                    update_transcript<KZG>(public_key, transcript);

                    auto gamma = transcript.template challenge<typename KZG::curve_type::scalar_field_type>();
                    auto factor = KZG::scalar_value_type::one();
                    typename math::polynomial<typename KZG::scalar_value_type> accum;

                    for (std::size_t i = 0; i < KZG::batch_size; ++i) {
                        auto spare_poly = polys[i] - public_key.r[i];
                        auto denom = create_polynom_by_zeros<KZG>(public_key.S[i]);
                        for (auto s : public_key.S[i]) {
                            assert(spare_poly.evaluate(s) == 0);
                            assert(denom.evaluate(s) == 0);
                        }
                        assert(spare_poly % denom == typename math::polynomial<typename KZG::scalar_value_type>({{0}}));
                        spare_poly = spare_poly / denom;
                        accum = accum + spare_poly * factor;
                        factor = factor * gamma;
                    }

                    //verify without pairing
                    {
                        typename math::polynomial<typename KZG::scalar_value_type> right_side({{0}});
                        factor = KZG::scalar_value_type::one();
                        for (std::size_t i = 0; i < KZG::batch_size; ++i) {
                            right_side = right_side + factor * (polys[i] - public_key.r[i]) * set_difference_polynom<KZG>(public_key.T, public_key.S[i]);
                            factor = factor * gamma;
                        }
                        assert(accum * create_polynom_by_zeros<KZG>(public_key.T) == right_side);
                    }
                    
                    return commit<KZG>(params, accum);
                }

                template<typename KZG,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::batched_kzg<typename KZG::curve_type,
                                 typename KZG::transcript_hash_type, KZG::batch_size>,
                                 KZG>::value,
                             bool>::type = true>
                static bool verify_eval(typename KZG::params_type params,
                                        const typename KZG::proof_type &proof,
                                        const typename KZG::public_key_type &public_key,
                                        typename KZG::transcript_type &transcript) {
                    update_transcript<KZG>(public_key, transcript);

                    auto gamma = transcript.template challenge<typename KZG::curve_type::scalar_field_type>();
                    auto factor = KZG::scalar_value_type::one();
                    auto left_side_pairing = KZG::gt_value_type::one();
                    
                    for (std::size_t i = 0; i < KZG::batch_size; ++i) {
                        auto r_commit = commit<KZG>(params, public_key.r[i]);
                        auto left = factor * (public_key.commits[i] - r_commit);
                        auto right = commit_g2<KZG>(params, set_difference_polynom<KZG>(public_key.T, public_key.S[i]));
                        if (KZG::batch_size == 1) {
                            assert(right == KZG::verification_type::one());
                        }
                        left_side_pairing = left_side_pairing * algebra::pair_reduced<typename KZG::curve_type>(left, right);
                        factor = factor * gamma;
                    }

                    auto right = commit_g2<KZG>(params, create_polynom_by_zeros<KZG>(public_key.T));
                    auto right_side_pairing = algebra::pair_reduced<typename KZG::curve_type>(proof, right);
                    
                    return left_side_pairing == right_side_pairing;
                    // return true;
                }
            } // namespace algorithms
        }         // namespace zk
    }             // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_COMMITMENTS_KZG_HPP
