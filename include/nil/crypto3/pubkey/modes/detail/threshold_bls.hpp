//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_THRESHOLD_BLS_HPP
#define CRYPTO3_PUBKEY_THRESHOLD_BLS_HPP

#include <type_traits>
#include <iterator>
#include <utility>
#include <unordered_map>

#include <nil/crypto3/pubkey/private_key.hpp>
#include <nil/crypto3/pubkey/no_key_ops.hpp>
#include <nil/crypto3/pubkey/bls.hpp>
#include <nil/crypto3/pubkey/secret_sharing.hpp>
#include <nil/crypto3/pubkey/dkg.hpp>

#include <nil/crypto3/pubkey/detail/stream_processor.hpp>

#include <nil/crypto3/pubkey/algorithm/deal_shares.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename Scheme, template<typename> class SecretSharingScheme>
                struct threshold_bls;

                template<typename SignatureVariant, template<typename, typename> class BlsScheme, typename PublicParams,
                         template<typename> class SecretSharingScheme>
                struct threshold_bls<bls<SignatureVariant, BlsScheme, PublicParams>, SecretSharingScheme> {
                    typedef bls<SignatureVariant, BlsScheme, PublicParams> base_scheme_type;

                    template<typename Group>
                    using secret_sharing_scheme_type = SecretSharingScheme<Group>;

                    template<typename Mode, typename AccumulatorSet, std::size_t ValueBits = 0>
                    struct stream_processor {
                        struct params_type {
                            typedef stream_endian::little_octet_big_bit endian_type;

                            constexpr static const std::size_t value_bits = ValueBits;
                        };
                        typedef ::nil::crypto3::pubkey::stream_processor<Mode, AccumulatorSet, params_type> type;
                    };
                };
            }    // namespace detail

            template<typename Scheme, template<typename> class SecretSharingScheme>
            struct public_key<
                detail::threshold_bls<Scheme, SecretSharingScheme>,
                typename std::enable_if<
                    std::is_same<
                        shamir_sss<typename public_key<Scheme>::public_key_type::group_type>,
                        SecretSharingScheme<typename public_key<Scheme>::public_key_type::group_type>>::value ||
                    std::is_same<
                        feldman_sss<typename public_key<Scheme>::public_key_type::group_type>,
                        SecretSharingScheme<typename public_key<Scheme>::public_key_type::group_type>>::value ||
                    std::is_same<
                        pedersen_dkg<typename public_key<Scheme>::public_key_type::group_type>,
                        SecretSharingScheme<typename public_key<Scheme>::public_key_type::group_type>>::value>::type> {
                typedef detail::threshold_bls<Scheme, SecretSharingScheme> scheme_type;
                typedef typename scheme_type::base_scheme_type base_scheme_type;
                typedef private_key<base_scheme_type> base_scheme_private_key_type;
                typedef public_key<base_scheme_type> base_scheme_public_key_type;

                template<typename Group>
                using secret_sharing_scheme_type = typename scheme_type::template secret_sharing_scheme_type<Group>;

                typedef secret_sharing_scheme_type<typename base_scheme_public_key_type::public_key_type::group_type>
                    sss_public_key_group_type;
                typedef secret_sharing_scheme_type<typename base_scheme_public_key_type::signature_type::group_type>
                    sss_signature_group_type;

                typedef no_key_ops<sss_public_key_group_type> sss_public_key_no_key_ops_type;
                typedef no_key_ops<sss_signature_group_type> sss_signature_no_key_ops_type;

                typedef std::pair<typename sss_public_key_no_key_ops_type::share_type::first_type,
                                  base_scheme_private_key_type>
                    private_key_type;
                typedef std::pair<typename sss_public_key_no_key_ops_type::public_share_type::first_type,
                                  base_scheme_public_key_type>
                    public_key_type;
                typedef typename sss_signature_no_key_ops_type::indexed_public_element_type part_signature_type;
                typedef typename base_scheme_public_key_type::signature_type signature_type;

                typedef typename base_scheme_public_key_type::pubkey_id_type pubkey_id_type;

                typedef std::vector<std::uint8_t> input_block_type;
                constexpr static const std::size_t input_block_bits = 0;    // non-restricted length

                typedef typename input_block_type::value_type input_value_type;
                constexpr static const std::size_t input_value_bits = 8;

                public_key() {
                }

                //
                // PK
                //
                public_key(const typename sss_public_key_no_key_ops_type::public_element_type &key) : pubkey(0, key) {
                }

                //
                // VK_i
                //
                public_key(const typename sss_public_key_no_key_ops_type::public_share_type &key) :
                    pubkey(key.first, base_scheme_public_key_type(key.second)) {
                    assert(sss_public_key_no_key_ops_type::check_participant_index(key.first));
                }

                template<typename MsgRange,
                         typename std::enable_if<
                             std::is_same<input_value_type, typename std::iterator_traits<
                                                                typename MsgRange::iterator>::value_type>::value,
                             bool>::type = true>
                inline bool verify(const MsgRange &msg, const signature_type &sig) const {
                    assert(check_PK());
                    return pubkey.second.verify(msg, sig);
                }

                template<typename MsgRange,
                         typename std::enable_if<
                             std::is_same<input_value_type, typename std::iterator_traits<
                                                                typename MsgRange::iterator>::value_type>::value,
                             bool>::type = true>
                inline bool part_verify(const MsgRange &msg, const part_signature_type &part_sig) const {
                    assert(pubkey.first == part_sig.first);
                    return pubkey.second.verify(msg, part_sig.second);
                }

            protected:
                inline bool check_PK() const {
                    return 0 == pubkey.first;
                }

                public_key_type pubkey;
            };

            template<typename Scheme, template<typename> class SecretSharingScheme>
            struct private_key<
                detail::threshold_bls<Scheme, SecretSharingScheme>,
                typename std::enable_if<
                    std::is_same<
                        shamir_sss<typename public_key<Scheme>::public_key_type::group_type>,
                        SecretSharingScheme<typename public_key<Scheme>::public_key_type::group_type>>::value ||
                    std::is_same<
                        feldman_sss<typename public_key<Scheme>::public_key_type::group_type>,
                        SecretSharingScheme<typename public_key<Scheme>::public_key_type::group_type>>::value ||
                    std::is_same<
                        pedersen_dkg<typename public_key<Scheme>::public_key_type::group_type>,
                        SecretSharingScheme<typename public_key<Scheme>::public_key_type::group_type>>::value>::type>
                : public_key<detail::threshold_bls<Scheme, SecretSharingScheme>> {
                typedef public_key<detail::threshold_bls<Scheme, SecretSharingScheme>> base_type;
                typedef typename base_type::scheme_type scheme_type;
                typedef typename base_type::base_scheme_type base_scheme_type;
                typedef typename base_type::base_scheme_private_key_type base_scheme_private_key_type;

                typedef typename base_type::sss_public_key_group_type sss_public_key_group_type;
                typedef typename base_type::sss_signature_group_type sss_signature_group_type;

                typedef typename base_type::sss_public_key_no_key_ops_type sss_public_key_no_key_ops_type;
                typedef typename base_type::sss_signature_no_key_ops_type sss_signature_no_key_ops_type;

                typedef typename base_type::private_key_type private_key_type;
                typedef typename base_type::public_key_type public_key_type;
                typedef typename base_type::part_signature_type part_signature_type;
                typedef typename base_type::signature_type signature_type;

                typedef typename base_type::pubkey_id_type pubkey_id_type;

                typedef std::vector<std::uint8_t> input_block_type;
                constexpr static const std::size_t input_block_bits = 0;    // non-restricted length

                typedef typename input_block_type::value_type input_value_type;
                constexpr static const std::size_t input_value_bits = 8;

                private_key() {
                }

                private_key(const typename sss_public_key_no_key_ops_type::share_type &key) :
                    privkey(key.first, base_scheme_private_key_type(key.second)),
                    base_type(sss_public_key_no_key_ops_type::get_public_share(key)) {
                    assert(sss_public_key_no_key_ops_type::check_participant_index(key.first));
                }

                template<typename MsgRange,
                         typename std::enable_if<
                             std::is_same<input_value_type, typename std::iterator_traits<
                                                                typename MsgRange::iterator>::value_type>::value,
                             bool>::type = true>
                inline part_signature_type sign(const MsgRange &msg) const {
                    return part_signature_type(privkey.first, privkey.second.sign(msg));
                }

            protected:
                private_key_type privkey;
            };

            template<typename Scheme, template<typename> class SecretSharingScheme>
            struct no_key_ops<
                detail::threshold_bls<Scheme, SecretSharingScheme>,
                typename std::enable_if<
                    std::is_same<
                        shamir_sss<typename public_key<Scheme>::public_key_type::group_type>,
                        SecretSharingScheme<typename public_key<Scheme>::public_key_type::group_type>>::value ||
                    std::is_same<
                        feldman_sss<typename public_key<Scheme>::public_key_type::group_type>,
                        SecretSharingScheme<typename public_key<Scheme>::public_key_type::group_type>>::value ||
                    std::is_same<
                        pedersen_dkg<typename public_key<Scheme>::public_key_type::group_type>,
                        SecretSharingScheme<typename public_key<Scheme>::public_key_type::group_type>>::value>::type> {
                typedef detail::threshold_bls<Scheme, SecretSharingScheme> scheme_type;
                typedef public_key<scheme_type> scheme_public_key_type;
                typedef typename scheme_type::base_scheme_type base_scheme_type;
                typedef typename scheme_public_key_type::base_scheme_private_key_type base_scheme_private_key_type;
                typedef typename scheme_public_key_type::base_scheme_public_key_type base_scheme_public_key_type;
                typedef no_key_ops<base_scheme_type> base_scheme_no_key_ops_type;

                typedef typename scheme_public_key_type::sss_public_key_group_type sss_public_key_group_type;
                typedef typename scheme_public_key_type::sss_signature_group_type sss_signature_group_type;

                typedef typename scheme_public_key_type::sss_public_key_no_key_ops_type sss_public_key_no_key_ops_type;
                typedef typename scheme_public_key_type::sss_signature_no_key_ops_type sss_signature_no_key_ops_type;

                typedef typename scheme_public_key_type::private_key_type private_key_type;
                typedef typename scheme_public_key_type::public_key_type public_key_type;
                typedef typename scheme_public_key_type::part_signature_type part_signature_type;
                typedef typename scheme_public_key_type::signature_type signature_type;

                typedef typename scheme_public_key_type::pubkey_id_type pubkey_id_type;

                typedef std::vector<part_signature_type> input_block_type;
                constexpr static const std::size_t input_block_bits = 0;    // non-restricted length

                typedef typename input_block_type::value_type input_value_type;
                constexpr static const std::size_t input_value_bits = 0;    // non-integral objects

                template<typename Signatures,
                         typename sss_signature_no_key_ops_type::template check_public_shares_type<Signatures> = true>
                static inline signature_type aggregate(const Signatures &signatures) {
                    return sss_signature_no_key_ops_type::reconstruct_public_element(signatures);
                }
            };

            template<typename Scheme, template<typename> class SecretSharingScheme>
            struct public_key<
                detail::threshold_bls<Scheme, SecretSharingScheme>,
                typename std::enable_if<std::is_same<
                    weighted_shamir_sss<typename public_key<Scheme>::public_key_type::group_type>,
                    SecretSharingScheme<typename public_key<Scheme>::public_key_type::group_type>>::value>::type> {
                typedef detail::threshold_bls<Scheme, SecretSharingScheme> scheme_type;
                typedef typename scheme_type::base_scheme_type base_scheme_type;
                typedef private_key<base_scheme_type> base_scheme_private_key_type;
                typedef public_key<base_scheme_type> base_scheme_public_key_type;

                template<typename Group>
                using secret_sharing_scheme_type = typename scheme_type::template secret_sharing_scheme_type<Group>;

                typedef secret_sharing_scheme_type<typename base_scheme_public_key_type::public_key_type::group_type>
                    sss_public_key_group_type;
                typedef secret_sharing_scheme_type<typename base_scheme_public_key_type::signature_type::group_type>
                    sss_signature_group_type;

                typedef no_key_ops<sss_public_key_group_type> sss_public_key_no_key_ops_type;
                typedef no_key_ops<sss_signature_group_type> sss_signature_no_key_ops_type;

                typedef typename sss_public_key_no_key_ops_type::share_type private_key_type;
                typedef typename sss_public_key_no_key_ops_type::public_share_type public_key_type;
                typedef typename sss_signature_no_key_ops_type::indexed_public_element_type part_signature_type;
                typedef typename base_scheme_public_key_type::signature_type signature_type;

                typedef typename base_scheme_public_key_type::pubkey_id_type pubkey_id_type;

                typedef std::vector<std::uint8_t> input_block_type;
                constexpr static const std::size_t input_block_bits = 0;    // non-restricted length

                typedef typename input_block_type::value_type input_value_type;
                constexpr static const std::size_t input_value_bits = 8;

                public_key() {
                }

                //
                // PK
                //
                public_key(const typename sss_public_key_no_key_ops_type::public_element_type &key) :
                    pubkey(0, typename public_key_type::second_type(
                                  {typename public_key_type::second_type::value_type(0, key)})) {
                }

                //
                // VK_i
                //
                template<typename Number>
                public_key(const typename sss_public_key_no_key_ops_type::public_share_type &key, Number t) :
                    t(t), pubkey(key) {
                }

                template<typename MsgRange>
                inline bool verify(const MsgRange &msg, const signature_type &sig) const {
                    assert(check_PK());
                    return base_scheme_public_key_type(pubkey.second.begin()->second).verify(msg, sig);
                }

                template<typename MsgRange, typename ConfirmedWeights>
                inline bool part_verify(const MsgRange &msg, const part_signature_type &part_sig,
                                        const ConfirmedWeights &confirmed_weights) const {
                    assert(pubkey.first == part_sig.first);
                    base_scheme_public_key_type VK_i(
                        sss_public_key_no_key_ops_type::reconstruct_weighted_public_element(pubkey.second,
                                                                                            confirmed_weights, t));
                    return VK_i.verify(msg, part_sig.second);
                }

            protected:
                inline bool check_PK() const {
                    return 0 == pubkey.first && 1 == pubkey.second.size() && 0 == pubkey.second.begin()->first;
                }

                std::size_t t;
                public_key_type pubkey;
            };

            template<typename Scheme, template<typename> class SecretSharingScheme>
            struct private_key<
                detail::threshold_bls<Scheme, SecretSharingScheme>,
                typename std::enable_if<std::is_same<
                    weighted_shamir_sss<typename public_key<Scheme>::public_key_type::group_type>,
                    SecretSharingScheme<typename public_key<Scheme>::public_key_type::group_type>>::value>::type>
                : public_key<detail::threshold_bls<Scheme, SecretSharingScheme>> {
                typedef public_key<detail::threshold_bls<Scheme, SecretSharingScheme>> base_type;
                typedef typename base_type::scheme_type scheme_type;
                typedef typename base_type::base_scheme_type base_scheme_type;
                typedef typename base_type::base_scheme_private_key_type base_scheme_private_key_type;

                typedef typename base_type::sss_public_key_group_type sss_public_key_group_type;
                typedef typename base_type::sss_signature_group_type sss_signature_group_type;

                typedef typename base_type::sss_public_key_no_key_ops_type sss_public_key_no_key_ops_type;
                typedef typename base_type::sss_signature_no_key_ops_type sss_signature_no_key_ops_type;

                typedef typename base_type::private_key_type private_key_type;
                typedef typename base_type::public_key_type public_key_type;
                typedef typename base_type::part_signature_type part_signature_type;
                typedef typename base_type::signature_type signature_type;

                typedef typename base_type::pubkey_id_type pubkey_id_type;

                typedef std::vector<std::uint8_t> input_block_type;
                constexpr static const std::size_t input_block_bits = 0;    // non-restricted length

                typedef typename input_block_type::value_type input_value_type;
                constexpr static const std::size_t input_value_bits = 8;

                private_key() {
                }

                template<typename Number>
                private_key(const typename sss_public_key_no_key_ops_type::share_type &key, Number t) :
                    t(t), privkey(key), base_type(sss_public_key_no_key_ops_type::get_public_share(key), t) {
                }

                template<typename MsgRange, typename ConfirmedWeights>
                inline part_signature_type sign(const MsgRange &msg, const ConfirmedWeights &confirmed_weights) const {
                    base_scheme_private_key_type s_i(sss_public_key_no_key_ops_type::reconstruct_weighted_secret(
                        privkey.second, confirmed_weights, t));
                    return part_signature_type(privkey.first, s_i.sign(msg));
                }

            protected:
                std::size_t t;
                private_key_type privkey;
            };

            template<typename Scheme, template<typename> class SecretSharingScheme>
            struct no_key_ops<
                detail::threshold_bls<Scheme, SecretSharingScheme>,
                typename std::enable_if<std::is_same<
                    weighted_shamir_sss<typename public_key<Scheme>::public_key_type::group_type>,
                    SecretSharingScheme<typename public_key<Scheme>::public_key_type::group_type>>::value>::type> {
                typedef detail::threshold_bls<Scheme, SecretSharingScheme> scheme_type;
                typedef public_key<scheme_type> scheme_public_key_type;
                typedef typename scheme_type::base_scheme_type base_scheme_type;
                typedef typename scheme_public_key_type::base_scheme_private_key_type base_scheme_private_key_type;
                typedef typename scheme_public_key_type::base_scheme_public_key_type base_scheme_public_key_type;
                typedef no_key_ops<base_scheme_type> base_scheme_no_key_ops_type;

                typedef typename scheme_public_key_type::sss_public_key_group_type sss_public_key_group_type;
                typedef typename scheme_public_key_type::sss_signature_group_type sss_signature_group_type;

                typedef typename scheme_public_key_type::sss_public_key_no_key_ops_type sss_public_key_no_key_ops_type;
                typedef typename scheme_public_key_type::sss_signature_no_key_ops_type sss_signature_no_key_ops_type;

                typedef typename scheme_public_key_type::private_key_type private_key_type;
                typedef typename scheme_public_key_type::public_key_type public_key_type;
                typedef typename scheme_public_key_type::part_signature_type part_signature_type;
                typedef typename scheme_public_key_type::signature_type signature_type;

                typedef typename scheme_public_key_type::pubkey_id_type pubkey_id_type;

                typedef std::vector<part_signature_type> input_block_type;
                constexpr static const std::size_t input_block_bits = 0;    // non-restricted length

                typedef typename input_block_type::value_type input_value_type;
                constexpr static const std::size_t input_value_bits = 0;    // non-integral objects

                template<typename Signatures>
                static inline signature_type aggregate(const Signatures &signatures) {
                    return sss_signature_no_key_ops_type::reduce_public_elements(signatures);
                }
            };

            template<typename Scheme, typename Number1, typename Number2>
            inline typename std::enable_if<
                std::is_same<
                    shamir_sss<typename private_key<Scheme>::base_scheme_public_key_type::public_key_type::group_type>,
                    typename private_key<Scheme>::sss_public_key_group_type>::value,
                std::pair<public_key<Scheme>, std::vector<private_key<Scheme>>>>::type
                key_gen(Number1 t, Number2 n) {
                using privkeys_type = std::vector<private_key<Scheme>>;
                using sss_no_key_ops_type = typename private_key<Scheme>::sss_public_key_no_key_ops_type;
                using sss_scheme_type = typename sss_no_key_ops_type::scheme_type;

                auto coeffs = sss_no_key_ops_type::get_poly(t, n);
                typename sss_no_key_ops_type::shares_type shares =
                    nil::crypto3::deal_shares<sss_scheme_type>(coeffs, n, t);
                privkeys_type privkeys;
                for (const auto &s : shares) {
                    privkeys.emplace_back(s);
                }
                auto PK = public_key<Scheme>(sss_no_key_ops_type::get_public_coeffs(coeffs).front());
                return std::make_pair(PK, privkeys);
            }

            template<typename Scheme, typename Number1, typename Number2, typename Weights>
            inline typename std::enable_if<
                std::is_same<weighted_shamir_sss<typename private_key<
                                 Scheme>::base_scheme_public_key_type::public_key_type::group_type>,
                             typename private_key<Scheme>::sss_public_key_group_type>::value,
                std::pair<public_key<Scheme>, std::vector<private_key<Scheme>>>>::type
                key_gen(Number1 t, Number2 n, const Weights &weights) {
                using privkeys_type = std::vector<private_key<Scheme>>;
                using sss_no_key_ops_type = typename private_key<Scheme>::sss_public_key_no_key_ops_type;
                using sss_scheme_type = typename sss_no_key_ops_type::scheme_type;
                using shares_dealing_acc_set_type = shares_dealing_accumulator_set<typename modes::isomorphic<
                    sss_scheme_type, nop_padding>::template bind<shares_dealing_policy<sss_scheme_type>>::type>;
                using shares_dealing_acc =
                    typename boost::mpl::front<typename shares_dealing_acc_set_type::features_type>::type;

                auto coeffs = sss_no_key_ops_type::get_poly(t, n);
                shares_dealing_acc_set_type deal_shares_acc(n, nil::crypto3::accumulators::threshold_value = t);
                nil::crypto3::deal_shares<sss_scheme_type>(coeffs, deal_shares_acc);
                for (const auto &w : weights) {
                    deal_shares_acc(w);
                }
                typename sss_no_key_ops_type::shares_type shares =
                    boost::accumulators::extract_result<shares_dealing_acc>(deal_shares_acc);
                privkeys_type privkeys;
                for (const auto &s : shares) {
                    privkeys.emplace_back(s, t);
                }
                auto PK = public_key<Scheme>(sss_no_key_ops_type::get_public_coeffs(coeffs).front());
                return std::make_pair(PK, privkeys);
            }

            template<typename Key, typename Shares>
            inline typename std::enable_if<
                std::is_same<pedersen_dkg<typename Key::base_scheme_public_key_type::public_key_type::group_type>,
                             typename Key::sss_public_key_group_type>::type,
                Key>
                key_gen() {
                using result_type = Key;
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_THRESHOLD_BLS_HPP
