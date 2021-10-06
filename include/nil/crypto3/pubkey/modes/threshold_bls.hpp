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
#include <nil/crypto3/pubkey/operations/aggregate_op.hpp>

#include <nil/crypto3/pubkey/modes/detail/threshold_scheme.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
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

                // typedef std::pair<std::size_t, base_scheme_private_key_type> private_key_type;
                typedef std::pair<std::size_t, base_scheme_public_key_type> public_key_type;
                typedef public_share_sss<sss_signature_group_type> part_signature_type;
                typedef typename base_scheme_public_key_type::signature_type signature_type;

                typedef typename base_scheme_public_key_type::internal_accumulator_type internal_accumulator_type;

                public_key() = default;

                //
                // PK
                //
                public_key(const typename public_key_group_type::value_type &key) : pubkey(0, key) {
                }

                //
                // VK_i
                //
                public_key(const public_share_sss<sss_public_key_group_type> &key_data) :
                    pubkey(key_data.get_index(), base_scheme_public_key_type(key_data.get_value())) {
                }

                inline void init_accumulator(internal_accumulator_type &acc) const {
                    pubkey.second.init_accumulator(acc);
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
                    assert(check_PK());
                    return pubkey.second.verify(acc, sig);
                }

                inline bool part_verify(internal_accumulator_type &acc, const part_signature_type &part_sig) const {
                    assert(pubkey.first == part_sig.get_index());
                    return pubkey.second.verify(acc, part_sig.get_value());
                }

                // TODO: make private
            protected:
                inline bool check_PK() const {
                    return 0 == pubkey.first;
                }

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
                    type> : public_key<detail::threshold_scheme<Scheme, SecretSharingScheme>> {
                typedef public_key<detail::threshold_scheme<Scheme, SecretSharingScheme>> base_type;
                typedef typename base_type::scheme_type scheme_type;
                typedef typename base_type::base_scheme_type base_scheme_type;
                typedef typename base_type::base_scheme_private_key_type base_scheme_private_key_type;

                typedef typename base_type::sss_public_key_group_type sss_public_key_group_type;
                typedef typename base_type::sss_signature_group_type sss_signature_group_type;

                typedef std::pair<std::size_t, base_scheme_private_key_type> private_key_type;
                typedef typename base_type::public_key_type public_key_type;
                typedef typename base_type::part_signature_type part_signature_type;
                typedef typename base_type::signature_type signature_type;

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

                typedef typename scheme_public_key_type::sss_public_key_group_type sss_public_key_group_type;
                typedef typename scheme_public_key_type::sss_signature_group_type sss_signature_group_type;

                typedef typename scheme_public_key_type::part_signature_type part_signature_type;
                typedef typename scheme_public_key_type::signature_type signature_type;

                typedef typename modes::isomorphic<sss_signature_group_type>::template bind<
                    public_secret_reconstructing_policy<sss_signature_group_type>>::type acc_processing_mode;
                typedef reconstructing_accumulator_set<acc_processing_mode> internal_accumulator_type;

                static inline void init_accumulator(internal_accumulator_type &acc) {
                }

                template<typename PartSignatures>
                static inline void update(internal_accumulator_type &acc, const PartSignatures &s) {
                    nil::crypto3::reconstruct_public_secret<sss_signature_group_type>(s, acc);
                }

                template<typename PartSignatureIt>
                static inline void update(internal_accumulator_type &acc, PartSignatureIt first, PartSignatureIt last) {
                    nil::crypto3::reconstruct_public_secret<sss_signature_group_type>(first, last, acc);
                }

                static inline signature_type aggregate(const internal_accumulator_type &acc) {
                    return nil::crypto3::pubkey::accumulators::extract::reconstruct<acc_processing_mode>(acc)
                        .get_value();
                }
            };

            // template<typename Scheme, template<typename> class SecretSharingScheme>
            // struct public_key<
            //     detail::threshold_bls<Scheme, SecretSharingScheme>,
            //     typename std::enable_if<std::is_same<
            //         weighted_shamir_sss<typename public_key<Scheme>::public_key_group_type>,
            //         SecretSharingScheme<typename public_key<Scheme>::public_key_group_type>>::value>::type> {
            //     typedef detail::threshold_bls<Scheme, SecretSharingScheme> scheme_type;
            //     typedef typename scheme_type::base_scheme_type base_scheme_type;
            //     typedef private_key<base_scheme_type> base_scheme_private_key_type;
            //     typedef public_key<base_scheme_type> base_scheme_public_key_type;
            //
            //     template<typename Group>
            //     using secret_sharing_scheme_type = typename scheme_type::template secret_sharing_scheme_type<Group>;
            //
            //     typedef secret_sharing_scheme_type<typename base_scheme_public_key_type::public_key_type::group_type>
            //         sss_public_key_group_type;
            //     typedef secret_sharing_scheme_type<typename base_scheme_public_key_type::signature_type::group_type>
            //         sss_signature_group_type;
            //
            //     typedef no_key_ops<sss_public_key_group_type> sss_public_key_no_key_ops_type;
            //     typedef no_key_ops<sss_signature_group_type> sss_signature_no_key_ops_type;
            //
            //     typedef typename sss_public_key_no_key_ops_type::share_type private_key_type;
            //     typedef typename sss_public_key_no_key_ops_type::public_share_type public_key_type;
            //     typedef typename sss_signature_no_key_ops_type::indexed_public_element_type part_signature_type;
            //     typedef typename base_scheme_public_key_type::signature_type signature_type;
            //
            //     typedef typename base_scheme_public_key_type::pubkey_id_type pubkey_id_type;
            //
            //     typedef std::vector<std::uint8_t> input_block_type;
            //     constexpr static const std::size_t input_block_bits = 0;    // non-restricted length
            //
            //     typedef typename input_block_type::value_type input_value_type;
            //     constexpr static const std::size_t input_value_bits = 8;
            //
            //     public_key() {
            //     }
            //
            //     //
            //     // PK
            //     //
            //     template<typename Number>
            //     public_key(const typename sss_public_key_no_key_ops_type::public_element_type &key, Number t) :
            //         t(t), weight(0), pubkey(0, typename public_key_type::second_type(
            //                                        {typename public_key_type::second_type::value_type(0, key)})) {
            //     }
            //
            //     //
            //     // VK_i
            //     //
            //     template<typename Number>
            //     public_key(const typename sss_public_key_no_key_ops_type::public_share_type &key, Number t) :
            //         t(t), weight(key.second.size()), pubkey(key) {
            //     }
            //
            //     template<typename MsgRange>
            //     inline bool verify(const MsgRange &msg, const signature_type &sig) const {
            //         assert(check_PK());
            //         return base_scheme_public_key_type(pubkey.second.begin()->second).verify(msg, sig);
            //     }
            //
            //     template<typename MsgRange, typename ConfirmedWeights>
            //     inline bool part_verify(const MsgRange &msg, const part_signature_type &part_sig,
            //                             const ConfirmedWeights &confirmed_weights) const {
            //         assert(pubkey.first == part_sig.first);
            //         base_scheme_public_key_type VK_i(sss_public_key_no_key_ops_type::reconstruct_part_public_element(
            //             pubkey.second, confirmed_weights, t));
            //         return VK_i.verify(msg, part_sig.second);
            //     }
            //
            //     inline std::size_t get_weight() const {
            //         return weight;
            //     }
            //
            //     inline std::size_t get_t() const {
            //         return t;
            //     }
            //
            //     inline std::size_t get_index() const {
            //         return pubkey.first;
            //     }
            //
            // protected:
            //     inline bool check_PK() const {
            //         return 0 == pubkey.first && 1 == pubkey.second.size() && 0 == pubkey.second.begin()->first &&
            //                0 == weight;
            //     }
            //
            //     std::size_t t;
            //     std::size_t weight;
            //     public_key_type pubkey;
            // };
            //
            // template<typename Scheme, template<typename> class SecretSharingScheme>
            // struct private_key<
            //     detail::threshold_bls<Scheme, SecretSharingScheme>,
            //     typename std::enable_if<std::is_same<
            //         weighted_shamir_sss<typename public_key<Scheme>::public_key_group_type>,
            //         SecretSharingScheme<typename public_key<Scheme>::public_key_group_type>>::value>::type>
            //     : public_key<detail::threshold_bls<Scheme, SecretSharingScheme>> {
            //     typedef public_key<detail::threshold_bls<Scheme, SecretSharingScheme>> base_type;
            //     typedef typename base_type::scheme_type scheme_type;
            //     typedef typename base_type::base_scheme_type base_scheme_type;
            //     typedef typename base_type::base_scheme_private_key_type base_scheme_private_key_type;
            //
            //     typedef typename base_type::sss_public_key_group_type sss_public_key_group_type;
            //     typedef typename base_type::sss_signature_group_type sss_signature_group_type;
            //
            //     typedef typename base_type::sss_public_key_no_key_ops_type sss_public_key_no_key_ops_type;
            //     typedef typename base_type::sss_signature_no_key_ops_type sss_signature_no_key_ops_type;
            //
            //     typedef typename base_type::private_key_type private_key_type;
            //     typedef typename base_type::public_key_type public_key_type;
            //     typedef typename base_type::part_signature_type part_signature_type;
            //     typedef typename base_type::signature_type signature_type;
            //
            //     typedef typename base_type::pubkey_id_type pubkey_id_type;
            //
            //     typedef std::vector<std::uint8_t> input_block_type;
            //     constexpr static const std::size_t input_block_bits = 0;    // non-restricted length
            //
            //     typedef typename input_block_type::value_type input_value_type;
            //     constexpr static const std::size_t input_value_bits = 8;
            //
            //     private_key() {
            //     }
            //
            //     template<typename Number>
            //     private_key(const typename sss_public_key_no_key_ops_type::share_type &key, Number t) :
            //         privkey(key), base_type(sss_public_key_no_key_ops_type::get_public_share(key), t) {
            //     }
            //
            //     template<typename MsgRange, typename ConfirmedWeights>
            //     inline part_signature_type sign(const MsgRange &msg, const ConfirmedWeights &confirmed_weights) const
            //     {
            //         base_scheme_private_key_type s_i(sss_public_key_no_key_ops_type::reconstruct_part_secret(
            //             privkey.second, confirmed_weights, this->t));
            //         return part_signature_type(privkey.first, s_i.sign(msg));
            //     }
            //
            // protected:
            //     private_key_type privkey;
            // };
            //
            // template<typename Scheme, template<typename> class SecretSharingScheme>
            // struct no_key_ops<
            //     detail::threshold_bls<Scheme, SecretSharingScheme>,
            //     typename std::enable_if<std::is_same<
            //         weighted_shamir_sss<typename public_key<Scheme>::public_key_group_type>,
            //         SecretSharingScheme<typename public_key<Scheme>::public_key_group_type>>::value>::type> {
            //     typedef detail::threshold_bls<Scheme, SecretSharingScheme> scheme_type;
            //     typedef public_key<scheme_type> scheme_public_key_type;
            //     typedef typename scheme_type::base_scheme_type base_scheme_type;
            //     typedef typename scheme_public_key_type::base_scheme_private_key_type base_scheme_private_key_type;
            //     typedef typename scheme_public_key_type::base_scheme_public_key_type base_scheme_public_key_type;
            //     typedef no_key_ops<base_scheme_type> base_scheme_no_key_ops_type;
            //
            //     typedef typename scheme_public_key_type::sss_public_key_group_type sss_public_key_group_type;
            //     typedef typename scheme_public_key_type::sss_signature_group_type sss_signature_group_type;
            //
            //     typedef typename scheme_public_key_type::sss_public_key_no_key_ops_type
            //     sss_public_key_no_key_ops_type; typedef typename
            //     scheme_public_key_type::sss_signature_no_key_ops_type sss_signature_no_key_ops_type;
            //
            //     typedef typename scheme_public_key_type::private_key_type private_key_type;
            //     typedef typename scheme_public_key_type::public_key_type public_key_type;
            //     typedef typename scheme_public_key_type::part_signature_type part_signature_type;
            //     typedef typename scheme_public_key_type::signature_type signature_type;
            //
            //     typedef typename scheme_public_key_type::pubkey_id_type pubkey_id_type;
            //
            //     typedef std::vector<part_signature_type> input_block_type;
            //     constexpr static const std::size_t input_block_bits = 0;    // non-restricted length
            //
            //     typedef typename input_block_type::value_type input_value_type;
            //     constexpr static const std::size_t input_value_bits = 0;    // non-integral objects
            //
            //     template<typename Signatures>
            //     static inline signature_type aggregate(const Signatures &signatures) {
            //         return sss_signature_no_key_ops_type::reduce_public_elements(signatures);
            //     }
            // };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_MODES_DETAIL_THRESHOLD_BLS_HPP
