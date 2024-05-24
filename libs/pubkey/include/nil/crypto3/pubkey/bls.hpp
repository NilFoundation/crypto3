//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_BLS_HPP
#define CRYPTO3_PUBKEY_BLS_HPP

#include <map>
#include <vector>
#include <iterator>
#include <type_traits>
#include <utility>
#include <functional>

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>

#include <boost/range/concepts.hpp>

#include <boost/mpl/vector.hpp>

#include <nil/crypto3/detail/stream_endian.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/pubkey/detail/bls/bls_basic_policy.hpp>
#include <nil/crypto3/pubkey/detail/bls/bls_basic_functions.hpp>
#include <nil/crypto3/pubkey/keys/private_key.hpp>
#include <nil/crypto3/pubkey/operations/aggregate_op.hpp>
#include <nil/crypto3/pubkey/operations/aggregate_verify_op.hpp>
#include <nil/crypto3/pubkey/operations/aggregate_verify_single_msg_op.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            /*!
             * @brief Basic BLS Scheme
             * @tparam SignatureVersion
             * @tparam BlsParams
             * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-3.1
             */
            template<typename SignatureVersion>
            struct bls_basic_scheme {
                typedef SignatureVersion signature_version;
                typedef typename signature_version::basic_functions basic_functions;

                typedef typename basic_functions::private_key_type private_key_type;
                typedef typename basic_functions::public_key_type public_key_type;
                typedef typename basic_functions::signature_type signature_type;

                typedef typename basic_functions::internal_accumulator_type internal_accumulator_type;
                typedef typename basic_functions::internal_aggregation_accumulator_type
                    internal_aggregation_accumulator_type;

                static inline public_key_type generate_public_key(const private_key_type &privkey) {
                    return basic_functions::privkey_to_pubkey(privkey);
                }

                static inline void init_accumulator(internal_accumulator_type &acc, const private_key_type &privkey) {
                }

                static inline void init_accumulator(internal_accumulator_type &acc, const public_key_type &pubkey) {
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                    basic_functions::update(acc, range);
                }

                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    basic_functions::update(acc, first, last);
                }

                static inline signature_type sign(internal_accumulator_type &acc, const private_key_type &privkey) {
                    return basic_functions::sign(acc, privkey);
                }

                static inline bool verify(internal_accumulator_type &acc, const public_key_type &pubkey,
                                          const signature_type &sig) {
                    return basic_functions::verify(acc, pubkey, sig);
                }

                template<typename SignatureRange>
                static inline void update_aggregate(signature_type &acc, const SignatureRange &signatures) {
                    basic_functions::aggregate(acc, signatures);
                }

                template<typename SignatureIterator>
                static inline void update_aggregate(signature_type &acc, SignatureIterator sig_first,
                                                    SignatureIterator sig_last) {
                    basic_functions::aggregate(acc, sig_first, sig_last);
                }

                static inline bool aggregate_verify(internal_aggregation_accumulator_type &acc,
                                                    const signature_type &signature) {
                    // TODO: add check - If any two input messages are equal, return INVALID.
                    return basic_functions::aggregate_verify(acc, signature);
                }
            };

            /*!
             * @brief
             * @tparam SignatureVersion
             * @tparam BlsParams
             * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-3.2
             */
            template<typename SignatureVersion>
            struct bls_aug_scheme {
                typedef SignatureVersion signature_version;
                typedef typename signature_version::basic_functions basic_functions;

                typedef typename basic_functions::private_key_type private_key_type;
                typedef typename basic_functions::public_key_type public_key_type;
                typedef typename basic_functions::signature_type signature_type;

                typedef typename basic_functions::internal_accumulator_type internal_accumulator_type;
                typedef typename basic_functions::internal_aggregation_accumulator_type
                    internal_aggregation_accumulator_type;

                static inline public_key_type generate_public_key(const private_key_type &privkey) {
                    return basic_functions::privkey_to_pubkey(privkey);
                }

                static inline void init_accumulator(internal_accumulator_type &acc, const private_key_type &privkey) {
                    init_accumulator(acc, generate_public_key(privkey));
                }

                static inline void init_accumulator(internal_accumulator_type &acc, const public_key_type &pubkey) {
                    basic_functions::update(acc, basic_functions::point_to_pubkey(pubkey));
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                    basic_functions::update(acc, range);
                }

                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    basic_functions::update(acc, first, last);
                }

                static inline signature_type sign(internal_accumulator_type &acc, const private_key_type &privkey) {
                    return basic_functions::sign(acc, privkey);
                }

                static inline bool verify(internal_accumulator_type &acc, const public_key_type &pubkey,
                                          const signature_type &sig) {
                    return basic_functions::verify(acc, pubkey, sig);
                }

                template<typename SignatureRange>
                static inline void update_aggregate(signature_type &acc, const SignatureRange &signatures) {
                    basic_functions::aggregate(acc, signatures);
                }

                template<typename SignatureIterator>
                static inline void update_aggregate(signature_type &acc, SignatureIterator sig_first,
                                                    SignatureIterator sig_last) {
                    basic_functions::aggregate(acc, sig_first, sig_last);
                }

                static inline bool aggregate_verify(internal_aggregation_accumulator_type &acc,
                                                    const signature_type &signature) {
                    return basic_functions::aggregate_verify(acc, signature);
                }
            };

            /*!
             * @brief Proof of possession BLS Scheme
             * @tparam SignatureVersion
             * @tparam BlsParams
             * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-3.3
             */
            template<typename SignatureVersion>
            struct bls_pop_scheme {
                typedef SignatureVersion signature_version;
                typedef typename signature_version::basic_functions basic_functions;

                typedef typename basic_functions::private_key_type private_key_type;
                typedef typename basic_functions::public_key_type public_key_type;
                typedef typename basic_functions::signature_type signature_type;

                typedef typename basic_functions::internal_accumulator_type internal_accumulator_type;
                typedef typename basic_functions::internal_aggregation_accumulator_type
                    internal_aggregation_accumulator_type;
                typedef typename basic_functions::internal_fast_aggregation_accumulator_type
                    internal_fast_aggregation_accumulator_type;

                static inline public_key_type generate_public_key(const private_key_type &privkey) {
                    return basic_functions::privkey_to_pubkey(privkey);
                }

                static inline void init_accumulator(internal_accumulator_type &acc, const private_key_type &privkey) {
                }

                static inline void init_accumulator(internal_accumulator_type &acc, const public_key_type &pubkey) {
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                    basic_functions::update(acc, range);
                }

                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    basic_functions::update(acc, first, last);
                }

                static inline signature_type sign(internal_accumulator_type &acc, const private_key_type &privkey) {
                    return basic_functions::sign(acc, privkey);
                }

                static inline bool verify(internal_accumulator_type &acc, const public_key_type &pubkey,
                                          const signature_type &sig) {
                    return basic_functions::verify(acc, pubkey, sig);
                }

                template<typename SignatureRange>
                static inline void update_aggregate(signature_type &acc, const SignatureRange &signatures) {
                    basic_functions::aggregate(acc, signatures);
                }

                template<typename SignatureIterator>
                static inline void update_aggregate(signature_type &acc, SignatureIterator sig_first,
                                                    SignatureIterator sig_last) {
                    basic_functions::aggregate(acc, sig_first, sig_last);
                }

                static inline bool aggregate_verify(internal_aggregation_accumulator_type &acc,
                                                    const signature_type &signature) {
                    return basic_functions::aggregate_verify(acc, signature);
                }

                static inline bool aggregate_verify(internal_fast_aggregation_accumulator_type &acc,
                                                    const signature_type &signature) {
                    return basic_functions::aggregate_verify(acc, signature);
                }

                static inline signature_type pop_prove(const private_key_type &privkey) {
                    return basic_functions::pop_prove(privkey);
                }

                static inline bool pop_verify(const public_key_type &pubkey, const signature_type &proof) {
                    return basic_functions::pop_verify(pubkey, proof);
                }
            };

            //
            // Minimal-signature-size
            // Random oracle version of hash-to-point
            //
            template<typename PublicParams, typename CurveType = algebra::curves::bls12_381>
            struct bls_mss_ro_version {
                typedef detail::bls_mss_ro_policy<PublicParams, CurveType> policy_type;
                typedef detail::bls_basic_functions<policy_type> basic_functions;
            };

            //
            // Minimal-pubkey-size
            // Random oracle version of hash-to-point
            //
            template<typename PublicParams, typename CurveType = algebra::curves::bls12_381>
            struct bls_mps_ro_version {
                typedef detail::bls_mps_ro_policy<PublicParams, CurveType> policy_type;
                typedef detail::bls_basic_functions<policy_type> basic_functions;
            };

            template<std::size_t _k = 128,
                     hashes::UniformityCount _uniformity_count = hashes::UniformityCount::uniform_count,
                     hashes::ExpandMsgVariant _expand_msg_variant = hashes::ExpandMsgVariant::rfc_xmd>
            struct bls_default_public_params {
                constexpr static hashes::UniformityCount uniformity_count = _uniformity_count;
                constexpr static hashes::ExpandMsgVariant expand_msg_variant = _expand_msg_variant;
                constexpr static std::size_t k = _k;

                // "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
                typedef std::array<std::uint8_t, 43> dst_type;
                static constexpr dst_type dst = {0x42, 0x4c, 0x53, 0x5f, 0x53, 0x49, 0x47, 0x5f, 0x42, 0x4c, 0x53,
                                                 0x31, 0x32, 0x33, 0x38, 0x31, 0x47, 0x32, 0x5f, 0x58, 0x4d, 0x44,
                                                 0x3a, 0x53, 0x48, 0x41, 0x2d, 0x32, 0x35, 0x36, 0x5f, 0x53, 0x53,
                                                 0x57, 0x55, 0x5f, 0x52, 0x4f, 0x5f, 0x4e, 0x55, 0x4c, 0x5f};
            };

            template<std::size_t _k = 128,
                     hashes::UniformityCount _uniformity_count = hashes::UniformityCount::uniform_count,
                     hashes::ExpandMsgVariant _expand_msg_variant = hashes::ExpandMsgVariant::rfc_xmd>
            struct bls_pop_prove_default_public_params {
                constexpr static hashes::UniformityCount uniformity_count = _uniformity_count;
                constexpr static hashes::ExpandMsgVariant expand_msg_variant = _expand_msg_variant;
                constexpr static std::size_t k = _k;

                typedef std::vector<std::uint8_t> dst_type;
                static inline dst_type dst = []() {
                    const std::string _dst_str = "BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
                    const std::vector<std::uint8_t> _dst(_dst_str.begin(), _dst_str.end());
                    return _dst;
                }();
            };

            template<std::size_t _k = 128,
                     hashes::UniformityCount _uniformity_count = hashes::UniformityCount::uniform_count,
                     hashes::ExpandMsgVariant _expand_msg_variant = hashes::ExpandMsgVariant::rfc_xmd>
            struct bls_pop_sign_default_public_params {
                constexpr static hashes::UniformityCount uniformity_count = _uniformity_count;
                constexpr static hashes::ExpandMsgVariant expand_msg_variant = _expand_msg_variant;
                constexpr static std::size_t k = _k;

                typedef std::vector<std::uint8_t> dst_type;
                static inline dst_type dst = []() {
                    const std::string _dst_str = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
                    const std::vector<std::uint8_t> _dst(_dst_str.begin(), _dst_str.end());
                    return _dst;
                }();
            };

            template<typename PublicParams = bls_default_public_params<>,
                     template<typename, typename> class BlsVersion = bls_mss_ro_version,
                     template<typename> class BlsScheme = bls_basic_scheme,
                     typename CurveType = algebra::curves::bls12_381>
            struct bls {
                typedef bls<PublicParams, BlsVersion, BlsScheme, CurveType> self_type;
                typedef BlsVersion<PublicParams, CurveType> bls_version_type;
                typedef BlsScheme<bls_version_type> bls_scheme_type;

                typedef public_key<self_type> public_key_type;
                typedef private_key<self_type> private_key_type;
                typedef aggregate_op<self_type> aggregate_op_policy;
                typedef aggregate_verify_op<self_type> aggregate_verify_op_policy;
            };

            template<typename PublicParams, template<typename, typename> class BlsVersion,
                     template<typename> class BlsScheme, typename CurveType>
            struct public_key<bls<PublicParams, BlsVersion, BlsScheme, CurveType>> {
                typedef bls<PublicParams, BlsVersion, BlsScheme, CurveType> scheme_type;
                typedef typename scheme_type::bls_scheme_type bls_scheme_type;

                typedef typename bls_scheme_type::private_key_type private_key_type;
                typedef typename bls_scheme_type::public_key_type public_key_type;
                typedef typename bls_scheme_type::signature_type signature_type;

                typedef typename public_key_type::group_type public_key_group_type;
                typedef typename signature_type::group_type signature_group_type;

                typedef typename bls_scheme_type::internal_accumulator_type internal_accumulator_type;

                typedef public_key_type key_type;

                public_key() = delete;
                public_key(const key_type &pubkey) : pubkey(pubkey) {
                }

                inline void init_accumulator(internal_accumulator_type &acc) const {
                    bls_scheme_type::init_accumulator(acc, pubkey);
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                    bls_scheme_type::update(acc, range);
                }

                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    bls_scheme_type::update(acc, first, last);
                }

                inline bool verify(internal_accumulator_type &acc, const signature_type &sig) const {
                    return bls_scheme_type::verify(acc, pubkey, sig);
                }

                inline public_key_type public_key_data() const {
                    return pubkey;
                }

                // TODO: refactor pop
                template<typename FakeAccumulator>
                inline bool pop_verify(FakeAccumulator, const signature_type &proof) const {
                    return bls_scheme_type::pop_verify(pubkey, proof);
                }

                // FIXME: copy pubkey between equivalent public keys is a bottleneck
                // TODO: support using of the same pubkey even if scheme policy differs in public params and scheme type
                template<typename ToPublicParams, template<typename> class ToBlsScheme>
                operator public_key<bls<ToPublicParams, BlsVersion, ToBlsScheme, CurveType>>() const {
                    return public_key<bls<ToPublicParams, BlsVersion, BlsScheme, CurveType>>(pubkey);
                }

            protected:
                public_key_type pubkey;
            };

            template<typename PublicParams, template<typename, typename> class BlsVersion,
                     template<typename> class BlsScheme, typename CurveType>
            struct private_key<bls<PublicParams, BlsVersion, BlsScheme, CurveType>>
                : public public_key<bls<PublicParams, BlsVersion, BlsScheme, CurveType>> {
                typedef bls<PublicParams, BlsVersion, BlsScheme, CurveType> scheme_type;
                typedef typename scheme_type::bls_scheme_type bls_scheme_type;
                typedef public_key<scheme_type> base_type;

                typedef typename base_type::private_key_type private_key_type;
                typedef typename base_type::public_key_type public_key_type;
                typedef typename base_type::signature_type signature_type;

                typedef typename bls_scheme_type::internal_accumulator_type internal_accumulator_type;

                typedef private_key_type key_type;

                private_key() = delete;
                private_key(const key_type &privkey) :
                    privkey(privkey), base_type(bls_scheme_type::generate_public_key(privkey)) {
                }

                inline void init_accumulator(internal_accumulator_type &acc) const {
                    bls_scheme_type::init_accumulator(acc, privkey);
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                    bls_scheme_type::update(acc, range);
                }

                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    bls_scheme_type::update(acc, first, last);
                }

                inline signature_type sign(internal_accumulator_type &acc) const {
                    return bls_scheme_type::sign(acc, privkey);
                }

                inline signature_type pop_prove() const {
                    return bls_scheme_type::pop_prove(privkey);
                }

                // FIXME: copy privkey between equivalent private keys is a bottleneck
                // TODO: support using of the same privkey even if scheme policy differs in public params and scheme
                //  type
                template<typename ToPublicParams, template<typename> class ToBlsScheme>
                operator private_key<bls<ToPublicParams, BlsVersion, ToBlsScheme, CurveType>>() const {
                    return private_key<bls<ToPublicParams, BlsVersion, BlsScheme, CurveType>>(privkey);
                }

            protected:
                private_key_type privkey;
            };

            template<typename PublicParams, template<typename, typename> class BlsVersion,
                     template<typename> class BlsScheme, typename CurveType>
            struct aggregate_op<bls<PublicParams, BlsVersion, BlsScheme, CurveType>> {
                typedef bls<PublicParams, BlsVersion, BlsScheme, CurveType> scheme_type;
                typedef typename scheme_type::bls_scheme_type bls_scheme_type;

                typedef typename bls_scheme_type::private_key_type private_key_type;
                typedef typename bls_scheme_type::public_key_type public_key_type;
                typedef typename bls_scheme_type::signature_type signature_type;

                typedef signature_type internal_accumulator_type;
                typedef signature_type result_type;

                static inline void init_accumulator(internal_accumulator_type &acc) {
                    acc = signature_type::zero();
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                    bls_scheme_type::update_aggregate(acc, range);
                }

                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    bls_scheme_type::update_aggregate(acc, first, last);
                }

                static inline result_type process(internal_accumulator_type &acc) {
                    return acc;
                }
            };

            template<typename PublicParams, template<typename, typename> class BlsVersion,
                     template<typename> class BlsScheme, typename CurveType>
            struct aggregate_verify_op<bls<PublicParams, BlsVersion, BlsScheme, CurveType>> {
                typedef bls<PublicParams, BlsVersion, BlsScheme, CurveType> scheme_type;
                typedef typename scheme_type::bls_scheme_type bls_scheme_type;
                typedef public_key<scheme_type> scheme_public_key_type;

                typedef typename bls_scheme_type::private_key_type private_key_type;
                typedef typename bls_scheme_type::public_key_type public_key_type;
                typedef typename bls_scheme_type::signature_type signature_type;

                typedef typename bls_scheme_type::internal_accumulator_type _internal_accumulator_type;
                typedef typename bls_scheme_type::internal_aggregation_accumulator_type
                    _internal_aggregation_accumulator_type;
                typedef _internal_aggregation_accumulator_type internal_accumulator_type;
                typedef bool result_type;

                static inline void init_accumulator(internal_accumulator_type &acc) {
                }

                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, const scheme_public_key_type &scheme_pubkey,
                                          InputIterator first, InputIterator last) {
                    auto index = get_public_key_index(acc, scheme_pubkey);
                    bls_scheme_type::update(acc.second[index], first, last);
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, const scheme_public_key_type &scheme_pubkey,
                                          const InputRange &range) {
                    auto index = get_public_key_index(acc, scheme_pubkey);
                    bls_scheme_type::update(acc.second[index], range);
                }

                static inline result_type process(internal_accumulator_type &acc, const signature_type &sig) {
                    return bls_scheme_type::aggregate_verify(acc, sig);
                }

            private:
                static inline std::size_t get_public_key_index(internal_accumulator_type &acc,
                                                               const scheme_public_key_type &scheme_pubkey) {
                    assert(std::distance(std::cbegin(acc.first), std::cend(acc.first)) ==
                           std::distance(std::cbegin(acc.second), std::cend(acc.second)));

                    auto found_pos_it =
                        std::find(std::cbegin(acc.first), std::cend(acc.first), scheme_pubkey.public_key_data());

                    if (std::cend(acc.first) == found_pos_it) {
                        acc.first.push_back(scheme_pubkey.public_key_data());
                        acc.second.push_back(_internal_accumulator_type());
                        bls_scheme_type::init_accumulator(acc.second.back(), acc.first.back());
                        return std::size(acc.first) - 1;
                    }

                    return std::distance(std::cbegin(acc.first), found_pos_it);
                }
            };

            template<typename PublicParams, template<typename, typename> class BlsVersion, typename CurveType>
            struct aggregate_verify_single_msg_op<bls<PublicParams, BlsVersion, bls_pop_scheme, CurveType>> {
                typedef bls<PublicParams, BlsVersion, bls_pop_scheme, CurveType> scheme_type;
                typedef typename scheme_type::bls_scheme_type bls_scheme_type;
                typedef public_key<scheme_type> scheme_public_key_type;

                typedef typename bls_scheme_type::private_key_type private_key_type;
                typedef typename bls_scheme_type::public_key_type public_key_type;
                typedef typename bls_scheme_type::signature_type signature_type;

                typedef typename bls_scheme_type::internal_accumulator_type _internal_accumulator_type;
                typedef typename bls_scheme_type::internal_fast_aggregation_accumulator_type
                    _internal_fast_aggregation_accumulator_type;
                typedef _internal_fast_aggregation_accumulator_type internal_accumulator_type;
                typedef bool result_type;

                static inline void init_accumulator(internal_accumulator_type &acc) {
                }

                template<typename InputIterator>
                static inline typename std::enable_if<!std::is_convertible<
                    typename std::iterator_traits<InputIterator>::value_type, scheme_public_key_type>::value>::type
                    update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    bls_scheme_type::update(acc.second, first, last);
                }

                template<typename InputRange>
                static inline typename std::enable_if<
                    !std::is_convertible<typename std::iterator_traits<typename InputRange::iterator>::value_type,
                                         scheme_public_key_type>::value>::type
                    update(internal_accumulator_type &acc, const InputRange &range) {
                    bls_scheme_type::update(acc.second, range);
                }

                template<typename InputIterator>
                static inline typename std::enable_if<std::is_convertible<
                    typename std::iterator_traits<InputIterator>::value_type, scheme_public_key_type>::value>::type
                    update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    for (auto iter = first; iter != last; ++iter) {
                        update(acc, *iter);
                    }
                }

                template<typename InputRange>
                static inline typename std::enable_if<
                    std::is_convertible<typename std::iterator_traits<typename InputRange::iterator>::value_type,
                                        scheme_public_key_type>::value>::type
                    update(internal_accumulator_type &acc, const InputRange &range) {
                    for (const auto &scheme_pubkey : range) {
                        update(acc, scheme_pubkey);
                    }
                }

                static inline void update(internal_accumulator_type &acc, const scheme_public_key_type &scheme_pubkey) {
                    auto found_pos_it =
                        std::find(std::cbegin(acc.first), std::cend(acc.first), scheme_pubkey.public_key_data());
                    if (std::cend(acc.first) == found_pos_it) {
                        acc.first.push_back(scheme_pubkey.public_key_data());
                    }
                }

                static inline result_type process(internal_accumulator_type &acc, const signature_type &sig) {
                    return bls_scheme_type::aggregate_verify(acc, sig);
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_BLS_HPP
