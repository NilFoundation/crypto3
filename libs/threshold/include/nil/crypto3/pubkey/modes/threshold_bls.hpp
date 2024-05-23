//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_MODES_DETAIL_THRESHOLD_BLS_HPP
#define CRYPTO3_PUBKEY_MODES_DETAIL_THRESHOLD_BLS_HPP

#include <type_traits>
#include <iterator>
#include <utility>
#include <unordered_map>

#include <nil/crypto3/pubkey/type_traits.hpp>

#include <nil/crypto3/pubkey/algorithm/deal_shares.hpp>
#include <nil/crypto3/pubkey/algorithm/verify_share.hpp>
#include <nil/crypto3/pubkey/algorithm/reconstruct_public_secret.hpp>

#include <nil/crypto3/pubkey/keys/private_key.hpp>
#include <nil/crypto3/pubkey/modes/part_public_key.hpp>
#include <nil/crypto3/pubkey/operations/aggregate_op.hpp>

#include <nil/crypto3/pubkey/modes/detail/threshold_scheme.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Scheme, template<typename> class SecretSharingScheme>
            struct part_public_key<
                detail::threshold_scheme<Scheme, SecretSharingScheme>,
                typename std::enable_if<
                    is_bls<Scheme>::value &&
                    (is_shamir_sss<SecretSharingScheme<typename public_key<Scheme>::public_key_group_type>>::value ||
                     is_feldman_sss<SecretSharingScheme<typename public_key<Scheme>::public_key_group_type>>::value ||
                     is_pedersen_dkg<SecretSharingScheme<typename public_key<Scheme>::public_key_group_type>>::value)>::
                    type> {
                typedef detail::threshold_scheme<Scheme, SecretSharingScheme> scheme_type;
                typedef typename scheme_type::base_scheme_type base_scheme_type;

                typedef private_key<base_scheme_type> base_scheme_private_key_type;
                typedef public_key<base_scheme_type> base_scheme_public_key_type;

                typedef typename base_scheme_public_key_type::public_key_group_type public_key_group_type;
                typedef typename base_scheme_public_key_type::signature_group_type signature_group_type;

                typedef typename scheme_type::template sss_type<public_key_group_type> sss_public_key_group_type;
                typedef typename scheme_type::template sss_type<signature_group_type> sss_signature_group_type;

                typedef std::pair<std::size_t, base_scheme_public_key_type> part_public_key_type;
                typedef public_share_sss<sss_signature_group_type> part_signature_type;

                typedef typename base_scheme_public_key_type::internal_accumulator_type internal_accumulator_type;

                part_public_key() = default;

                //
                // VK_i
                //
                part_public_key(const public_share_sss<sss_public_key_group_type> &key_data) :
                    part_pubkey(key_data.get_index(), base_scheme_public_key_type(key_data.get_value())) {
                }

                inline void init_accumulator(internal_accumulator_type &acc) const {
                    part_pubkey.second.init_accumulator(acc);
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                    base_scheme_public_key_type::update(acc, range);
                }

                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    base_scheme_public_key_type::update(acc, first, last);
                }

                inline bool part_verify(internal_accumulator_type &acc, const part_signature_type &part_sig) const {
                    assert(part_pubkey.first == part_sig.get_index());
                    return part_pubkey.second.verify(acc, part_sig.get_value());
                }

                // TODO: make private
            protected:
                part_public_key_type part_pubkey;
            };

            template<typename Scheme, template<typename> class SecretSharingScheme>
            struct public_key<
                detail::threshold_scheme<Scheme, SecretSharingScheme>,
                typename std::enable_if<
                    is_bls<Scheme>::value &&
                    (is_shamir_sss<SecretSharingScheme<typename public_key<Scheme>::public_key_group_type>>::value ||
                     is_feldman_sss<SecretSharingScheme<typename public_key<Scheme>::public_key_group_type>>::value ||
                     is_pedersen_dkg<SecretSharingScheme<typename public_key<Scheme>::public_key_group_type>>::value)>::
                    type> {
                typedef detail::threshold_scheme<Scheme, SecretSharingScheme> scheme_type;
                typedef typename scheme_type::base_scheme_type base_scheme_type;

                typedef private_key<base_scheme_type> base_scheme_private_key_type;
                typedef public_key<base_scheme_type> base_scheme_public_key_type;

                typedef typename base_scheme_public_key_type::public_key_group_type public_key_group_type;
                typedef typename base_scheme_public_key_type::signature_group_type signature_group_type;

                typedef typename scheme_type::template sss_type<public_key_group_type> sss_public_key_group_type;
                typedef typename scheme_type::template sss_type<signature_group_type> sss_signature_group_type;

                typedef base_scheme_public_key_type public_key_type;
                typedef typename base_scheme_public_key_type::signature_type signature_type;

                typedef typename base_scheme_public_key_type::internal_accumulator_type internal_accumulator_type;

                public_key() = default;

                //
                // PK
                //
                public_key(const typename public_key_group_type::value_type &key) : pubkey(key) {
                }

                inline void init_accumulator(internal_accumulator_type &acc) const {
                    pubkey.init_accumulator(acc);
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                    base_scheme_public_key_type::update(acc, range);
                }

                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    base_scheme_public_key_type::update(acc, first, last);
                }

                inline bool verify(internal_accumulator_type &acc, const signature_type &sig) const {
                    return pubkey.verify(acc, sig);
                }

                // TODO: make private
            protected:
                public_key_type pubkey;
            };

            template<typename Scheme, template<typename> class SecretSharingScheme>
            struct private_key<
                detail::threshold_scheme<Scheme, SecretSharingScheme>,
                typename std::enable_if<
                    is_bls<Scheme>::value &&
                    (is_shamir_sss<SecretSharingScheme<typename public_key<Scheme>::public_key_group_type>>::value ||
                     is_feldman_sss<SecretSharingScheme<typename public_key<Scheme>::public_key_group_type>>::value ||
                     is_pedersen_dkg<SecretSharingScheme<typename public_key<Scheme>::public_key_group_type>>::value)>::
                    type> : part_public_key<detail::threshold_scheme<Scheme, SecretSharingScheme>> {
                typedef part_public_key<detail::threshold_scheme<Scheme, SecretSharingScheme>> base_type;
                typedef typename base_type::scheme_type scheme_type;
                typedef typename base_type::base_scheme_type base_scheme_type;
                typedef typename base_type::base_scheme_private_key_type base_scheme_private_key_type;

                typedef typename base_type::sss_public_key_group_type sss_public_key_group_type;
                typedef typename base_type::sss_signature_group_type sss_signature_group_type;

                typedef std::pair<std::size_t, base_scheme_private_key_type> private_key_type;
                typedef typename base_type::part_signature_type part_signature_type;

                typedef typename base_scheme_private_key_type::internal_accumulator_type internal_accumulator_type;

                private_key() = default;

                private_key(const share_sss<sss_public_key_group_type> &key_data) :
                    verifiable_key_data(key_data),
                    privkey(key_data.get_index(), base_scheme_private_key_type(key_data.get_value())),
                    base_type(key_data) {
                }

                inline void init_accumulator(internal_accumulator_type &acc) const {
                    privkey.second.init_accumulator(acc);
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                    base_scheme_private_key_type::update(acc, range);
                }

                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    base_scheme_private_key_type::update(acc, first, last);
                }

                inline part_signature_type sign(internal_accumulator_type &acc) const {
                    return part_signature_type(privkey.first, privkey.second.sign(acc));
                }

                template<typename PublicCoeffs>
                inline bool verify_key(const PublicCoeffs &public_coeffs) {
                    return nil::crypto3::verify_share<sss_public_key_group_type>(public_coeffs, verifiable_key_data);
                }

                // TODO: make private
            protected:
                share_sss<sss_public_key_group_type> verifiable_key_data;
                private_key_type privkey;
            };

            template<typename Scheme, template<typename> class SecretSharingScheme>
            struct aggregate_op<
                detail::threshold_scheme<Scheme, SecretSharingScheme>,
                typename std::enable_if<
                    is_bls<Scheme>::value &&
                    (is_shamir_sss<SecretSharingScheme<typename public_key<Scheme>::public_key_group_type>>::value ||
                     is_feldman_sss<SecretSharingScheme<typename public_key<Scheme>::public_key_group_type>>::value ||
                     is_pedersen_dkg<SecretSharingScheme<typename public_key<Scheme>::public_key_group_type>>::value)>::
                    type> {
                typedef detail::threshold_scheme<Scheme, SecretSharingScheme> scheme_type;
                typedef typename scheme_type::base_scheme_type base_scheme_type;

                typedef public_key<scheme_type> scheme_public_key_type;
                typedef part_public_key<scheme_type> scheme_part_public_key_type;

                typedef typename scheme_public_key_type::sss_public_key_group_type sss_public_key_group_type;
                typedef typename scheme_public_key_type::sss_signature_group_type sss_signature_group_type;

                typedef typename scheme_part_public_key_type::part_signature_type part_signature_type;
                typedef typename scheme_public_key_type::signature_type signature_type;

                typedef typename modes::isomorphic<sss_signature_group_type>::template bind<
                    public_secret_reconstructing_policy<sss_signature_group_type>>::type acc_processing_mode;
                typedef reconstructing_accumulator_set<acc_processing_mode> internal_accumulator_type;

                static inline void init_accumulator(internal_accumulator_type &acc) {
                }

                template<typename PartSignatures>
                static inline typename std::enable_if<
                    std::is_same<part_signature_type,
                                 typename std::remove_cv<typename std::remove_reference<typename std::iterator_traits<
                                     typename PartSignatures::iterator>::value_type>::type>::type>::value>::type
                    update(internal_accumulator_type &acc, const PartSignatures &s) {
                    nil::crypto3::reconstruct_public_secret<sss_signature_group_type>(s, acc);
                }

                template<typename PartSignatureIt>
                static inline typename std::enable_if<
                    std::is_same<part_signature_type,
                                 typename std::remove_cv<typename std::remove_reference<typename std::iterator_traits<
                                     PartSignatureIt>::value_type>::type>::type>::value>::type
                    update(internal_accumulator_type &acc, PartSignatureIt first, PartSignatureIt last) {
                    nil::crypto3::reconstruct_public_secret<sss_signature_group_type>(first, last, acc);
                }

                static inline signature_type aggregate(const internal_accumulator_type &acc) {
                    return nil::crypto3::pubkey::accumulators::extract::reconstruct<acc_processing_mode>(acc)
                        .get_value();
                }
            };

            template<typename Scheme, template<typename> class SecretSharingScheme>
            struct part_public_key<
                detail::threshold_scheme<Scheme, SecretSharingScheme>,
                typename std::enable_if<is_bls<Scheme>::value &&
                                        is_weighted_shamir_sss<SecretSharingScheme<
                                            typename public_key<Scheme>::public_key_group_type>>::value>::type> {
                typedef detail::threshold_scheme<Scheme, SecretSharingScheme> scheme_type;
                typedef typename scheme_type::base_scheme_type base_scheme_type;

                typedef private_key<base_scheme_type> base_scheme_private_key_type;
                typedef public_key<base_scheme_type> base_scheme_public_key_type;

                typedef typename base_scheme_public_key_type::public_key_group_type public_key_group_type;
                typedef typename base_scheme_public_key_type::signature_group_type signature_group_type;

                typedef typename scheme_type::template sss_type<public_key_group_type> sss_public_key_group_type;
                typedef typename scheme_type::template sss_type<signature_group_type> sss_signature_group_type;
                typedef shamir_sss<public_key_group_type> _sss_public_key_group_type;
                typedef shamir_sss<signature_group_type> _sss_signature_group_type;

                typedef public_share_sss<sss_public_key_group_type> part_public_key_type;
                typedef public_share_sss<_sss_signature_group_type> part_signature_type;
                typedef typename sss_public_key_group_type::weights_type weights_type;

                typedef std::pair<weights_type, typename base_scheme_private_key_type::internal_accumulator_type>
                    internal_accumulator_type;

                part_public_key() = default;

                //
                // VK_i
                //
                part_public_key(const public_share_sss<sss_public_key_group_type> &key_data) : part_pubkey(key_data) {
                }

                inline void init_accumulator(internal_accumulator_type &acc,
                                             const weights_type &confirmed_weights) const {
                    // TODO: somehow mark that such type of key cannot pre-initialize accumulator
                    //  because set of users aggregating final signature is not known at the moment of part key creating
                    acc.first = confirmed_weights;
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                    base_scheme_public_key_type::update(acc.second, range);
                }

                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    base_scheme_public_key_type::update(acc.second, first, last);
                }

                inline bool part_verify(internal_accumulator_type &acc, const part_signature_type &part_sig) const {
                    assert(part_pubkey.get_index() == part_sig.get_index());
                    base_scheme_public_key_type VK_i(part_pubkey.to_shamir(acc.first).get_value());
                    return VK_i.verify(acc.second, part_sig.get_value());
                }

                inline std::size_t get_weight() const {
                    return part_pubkey.get_weight();
                }

                inline std::size_t get_threshold_number() const {
                    return part_pubkey.get_threshold_number();
                }

                inline std::size_t get_index() const {
                    return part_pubkey.get_index();
                }

            protected:
                part_public_key_type part_pubkey;
            };

            template<typename Scheme, template<typename> class SecretSharingScheme>
            struct public_key<detail::threshold_scheme<Scheme, SecretSharingScheme>,
                              typename std::enable_if<is_bls<Scheme>::value &&
                                                      is_weighted_shamir_sss<SecretSharingScheme<typename public_key<
                                                          Scheme>::public_key_group_type>>::value>::type> {
                typedef detail::threshold_scheme<Scheme, SecretSharingScheme> scheme_type;
                typedef typename scheme_type::base_scheme_type base_scheme_type;

                typedef private_key<base_scheme_type> base_scheme_private_key_type;
                typedef public_key<base_scheme_type> base_scheme_public_key_type;

                typedef typename base_scheme_public_key_type::public_key_group_type public_key_group_type;
                typedef typename base_scheme_public_key_type::signature_group_type signature_group_type;

                typedef typename scheme_type::template sss_type<public_key_group_type> sss_public_key_group_type;
                typedef typename scheme_type::template sss_type<signature_group_type> sss_signature_group_type;
                typedef shamir_sss<public_key_group_type> _sss_public_key_group_type;
                typedef shamir_sss<signature_group_type> _sss_signature_group_type;

                typedef base_scheme_public_key_type public_key_type;
                typedef typename base_scheme_public_key_type::signature_type signature_type;

                typedef typename base_scheme_public_key_type::internal_accumulator_type internal_accumulator_type;

                public_key() {
                }

                //
                // PK
                //
                public_key(const typename public_key_group_type::value_type &key) : pubkey(key) {
                }

                inline void init_accumulator(internal_accumulator_type &acc) const {
                    pubkey.init_accumulator(acc);
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                    base_scheme_public_key_type::update(acc, range);
                }

                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    base_scheme_public_key_type::update(acc, first, last);
                }

                inline bool verify(internal_accumulator_type &acc, const signature_type &sig) const {
                    return pubkey.verify(acc, sig);
                }

            protected:
                public_key_type pubkey;
            };

            template<typename Scheme, template<typename> class SecretSharingScheme>
            struct private_key<detail::threshold_scheme<Scheme, SecretSharingScheme>,
                               typename std::enable_if<is_bls<Scheme>::value &&
                                                       is_weighted_shamir_sss<SecretSharingScheme<typename public_key<
                                                           Scheme>::public_key_group_type>>::value>::type>
                : part_public_key<detail::threshold_scheme<Scheme, SecretSharingScheme>> {
                typedef part_public_key<detail::threshold_scheme<Scheme, SecretSharingScheme>> base_type;
                typedef typename base_type::scheme_type scheme_type;
                typedef typename base_type::base_scheme_type base_scheme_type;
                typedef typename base_type::base_scheme_private_key_type base_scheme_private_key_type;

                typedef typename base_type::sss_public_key_group_type sss_public_key_group_type;
                typedef typename base_type::sss_signature_group_type sss_signature_group_type;

                typedef share_sss<sss_public_key_group_type> private_key_type;
                typedef typename base_type::part_signature_type part_signature_type;
                typedef typename base_type::weights_type weights_type;

                typedef typename base_type::internal_accumulator_type internal_accumulator_type;

                private_key() {
                }

                private_key(const share_sss<sss_public_key_group_type> &key_data) :
                    privkey(key_data), base_type(key_data) {
                }

                inline void init_accumulator(internal_accumulator_type &acc,
                                             const weights_type &confirmed_weights) const {
                    // TODO: somehow mark that such type of key cannot pre-initialize accumulator
                    //  because set of users aggregating final signature is not known at the moment of part key creating
                    acc.first = confirmed_weights;
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                    base_scheme_private_key_type::update(acc.second, range);
                }

                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    base_scheme_private_key_type::update(acc.second, first, last);
                }

                inline part_signature_type sign(internal_accumulator_type &acc) const {
                    base_scheme_private_key_type s_i(privkey.to_shamir(acc.first).get_value());
                    return part_signature_type(privkey.get_index(), s_i.sign(acc.second));
                }

            protected:
                private_key_type privkey;
            };

            template<typename Scheme, template<typename> class SecretSharingScheme>
            struct aggregate_op<detail::threshold_scheme<Scheme, SecretSharingScheme>,
                                typename std::enable_if<is_bls<Scheme>::value &&
                                                        is_weighted_shamir_sss<SecretSharingScheme<typename public_key<
                                                            Scheme>::public_key_group_type>>::value>::type> {
                typedef detail::threshold_scheme<Scheme, SecretSharingScheme> scheme_type;
                typedef typename scheme_type::base_scheme_type base_scheme_type;

                typedef public_key<scheme_type> scheme_public_key_type;
                typedef part_public_key<scheme_type> scheme_part_public_key_type;

                typedef typename scheme_public_key_type::sss_public_key_group_type sss_public_key_group_type;
                typedef typename scheme_public_key_type::sss_signature_group_type sss_signature_group_type;

                typedef typename scheme_part_public_key_type::part_signature_type part_signature_type;
                typedef typename scheme_public_key_type::signature_type signature_type;

                typedef signature_type internal_accumulator_type;

                static inline void init_accumulator(internal_accumulator_type &acc) {
                    acc = signature_type::zero();
                }

                template<typename PartSignatures>
                static inline typename std::enable_if<
                    std::is_same<part_signature_type,
                                 typename std::remove_cv<typename std::remove_reference<typename std::iterator_traits<
                                     typename PartSignatures::iterator>::value_type>::type>::type>::value>::type
                    update(internal_accumulator_type &acc, const PartSignatures &s) {
                    for (const auto &s_i : s) {
                        acc = acc + s_i.get_value();
                    }
                }

                template<typename PartSignatureIt>
                static inline typename std::enable_if<
                    std::is_same<part_signature_type,
                                 typename std::remove_cv<typename std::remove_reference<typename std::iterator_traits<
                                     PartSignatureIt>::value_type>::type>::type>::value>::type
                    update(internal_accumulator_type &acc, PartSignatureIt first, PartSignatureIt last) {
                    for (auto iter = first; iter != last; ++iter) {
                        acc = acc + iter->get_value();
                    }
                }

                static inline signature_type aggregate(const internal_accumulator_type &acc) {
                    return acc;
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_MODES_DETAIL_THRESHOLD_BLS_HPP
