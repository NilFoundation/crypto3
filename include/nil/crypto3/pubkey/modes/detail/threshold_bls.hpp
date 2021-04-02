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
                typedef no_key_ops<sss_signature_group_type> sss_signature_no_key_ops_ops;

                typedef std::pair<typename sss_public_key_no_key_ops_type::share_type::first_type,
                                  base_scheme_private_key_type>
                    private_key_type;
                typedef std::pair<typename sss_public_key_no_key_ops_type::public_share_type::first_type,
                                  base_scheme_public_key_type>
                    public_key_type;
                typedef typename sss_signature_no_key_ops_ops::public_share_type part_signature_type;
                typedef typename base_scheme_public_key_type::signature_type signature_type;

                typedef typename base_scheme_public_key_type::public_params_type public_params_type;
                typedef typename base_scheme_public_key_type::pubkey_id_type pubkey_id_type;

                typedef std::vector<std::uint8_t> input_block_type;
                constexpr static const std::size_t input_block_bits = 0;    // non-restricted length

                typedef typename input_block_type::value_type input_value_type;
                constexpr static const std::size_t input_value_bits = 8;

                public_key() {
                }

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
                    return pubkey.second.verify(msg, sig);
                }

                template<typename MsgRange,
                         typename std::enable_if<
                             std::is_same<input_value_type, typename std::iterator_traits<
                                                                typename MsgRange::iterator>::value_type>::value,
                             bool>::type = true>
                inline bool verify(const MsgRange &msg, const part_signature_type &part_sig) const {
                    assert(pubkey.first == part_sig.first);
                    return pubkey.second.verify(msg, part_sig.second);
                }

            protected:
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
                typedef private_key<base_scheme_type> base_scheme_private_key_type;

                typedef typename base_type::sss_public_key_group_type sss_public_key_group_type;
                typedef typename base_type::sss_signature_group_type sss_signature_group_type;

                typedef typename base_type::sss_public_key_no_key_ops_type sss_public_key_no_key_ops_type;
                typedef typename base_type::sss_signature_no_key_ops_ops sss_signature_no_key_ops_ops;

                typedef typename base_type::private_key_type private_key_type;
                typedef typename base_type::public_key_type public_key_type;
                typedef typename base_type::part_signature_type part_signature_type;
                typedef typename base_type::signature_type signature_type;

                typedef typename base_type::public_params_type public_params_type;
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
                typedef typename scheme_type::base_scheme_type base_scheme_type;
                typedef private_key<base_scheme_type> base_scheme_private_key_type;
                typedef public_key<base_scheme_type> base_scheme_public_key_type;
                typedef no_key_ops<base_scheme_type> base_scheme_no_key_ops_type;

                typedef public_key<scheme_type> scheme_public_key_type;

                typedef typename scheme_public_key_type::sss_public_key_group_type sss_public_key_group_type;
                typedef typename scheme_public_key_type::sss_signature_group_type sss_signature_group_type;

                typedef typename scheme_public_key_type::sss_public_key_ops sss_public_key_no_key_ops_type;
                typedef typename scheme_public_key_type::sss_signature_ops sss_signature_no_key_ops_ops;

                typedef typename scheme_public_key_type::private_key_type private_key_type;
                typedef typename scheme_public_key_type::public_key_type public_key_type;
                typedef typename scheme_public_key_type::part_signature_type part_signature_type;
                typedef typename scheme_public_key_type::signature_type signature_type;

                typedef typename scheme_public_key_type::public_params_type public_params_type;
                typedef typename scheme_public_key_type::pubkey_id_type pubkey_id_type;

                typedef std::vector<part_signature_type> input_block_type;
                constexpr static const std::size_t input_block_bits = 0;    // non-restricted length

                typedef typename input_block_type::value_type input_value_type;
                constexpr static const std::size_t input_value_bits = 0;    // non-integral objects

                template<typename Signatures,
                         typename sss_signature_no_key_ops_ops::template check_public_shares_type<Signatures> = true>
                static inline signature_type aggregate(const Signatures &signatures) {
                    return sss_signature_no_key_ops_ops::reconstruct_public_element(signatures);
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
                typedef no_key_ops<sss_signature_group_type> sss_signature_no_key_ops_ops;

                typedef std::pair<typename sss_public_key_no_key_ops_type::share_type::first_type,
                                  std::unordered_map<typename sss_public_key_no_key_ops_type::share_type::first_type,
                                                     base_scheme_private_key_type>>
                    private_key_type;
                typedef std::pair<typename sss_public_key_no_key_ops_type::share_type::first_type,
                                  std::unordered_map<typename sss_public_key_no_key_ops_type::share_type::first_type,
                                                     base_scheme_private_key_type>>
                    public_key_type;
                typedef typename sss_signature_no_key_ops_ops::public_share_type part_signature_type;
                typedef typename base_scheme_public_key_type::signature_type signature_type;

                typedef typename base_scheme_public_key_type::public_params_type public_params_type;
                typedef typename base_scheme_public_key_type::pubkey_id_type pubkey_id_type;

                typedef std::vector<std::uint8_t> input_block_type;
                constexpr static const std::size_t input_block_bits = 0;    // non-restricted length

                typedef typename input_block_type::value_type input_value_type;
                constexpr static const std::size_t input_value_bits = 8;

                public_key() {
                }

                public_key(const public_key_type &pubkey) {
                }

            protected:
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
                typedef private_key<base_scheme_type> base_scheme_private_key_type;

                typedef typename base_type::sss_public_key_group_type sss_public_key_group_type;
                typedef typename base_type::sss_signature_group_type sss_signature_group_type;

                typedef typename base_type::sss_public_key_no_key_ops_type sss_public_key_no_key_ops_type;
                typedef typename base_type::sss_signature_no_key_ops_ops sss_signature_no_key_ops_ops;

                typedef typename base_type::private_key_type private_key_type;
                typedef typename base_type::public_key_type public_key_type;
                typedef typename base_type::part_signature_type part_signature_type;
                typedef typename base_type::signature_type signature_type;

                typedef typename base_type::public_params_type public_params_type;
                typedef typename base_type::pubkey_id_type pubkey_id_type;

                typedef std::vector<std::uint8_t> input_block_type;
                constexpr static const std::size_t input_block_bits = 0;    // non-restricted length

                typedef typename input_block_type::value_type input_value_type;
                constexpr static const std::size_t input_value_bits = 8;
            };

            template<typename Scheme, template<typename> class SecretSharingScheme>
            struct no_key_ops<
                detail::threshold_bls<Scheme, SecretSharingScheme>,
                typename std::enable_if<std::is_same<
                    weighted_shamir_sss<typename public_key<Scheme>::public_key_type::group_type>,
                    SecretSharingScheme<typename public_key<Scheme>::public_key_type::group_type>>::value>::type> {
                typedef detail::threshold_bls<Scheme, SecretSharingScheme> scheme_type;
                typedef typename scheme_type::base_scheme_type base_scheme_type;
                typedef private_key<base_scheme_type> base_scheme_private_key_type;
                typedef public_key<base_scheme_type> base_scheme_public_key_type;
                typedef no_key_ops<base_scheme_type> base_scheme_no_key_ops_type;

                typedef public_key<scheme_type> scheme_public_key_type;

                typedef typename scheme_public_key_type::sss_public_key_group_type sss_public_key_group_type;
                typedef typename scheme_public_key_type::sss_signature_group_type sss_signature_group_type;

                typedef typename scheme_public_key_type::sss_public_key_ops sss_public_key_no_key_ops_type;
                typedef typename scheme_public_key_type::sss_signature_ops sss_signature_no_key_ops_ops;

                typedef typename scheme_public_key_type::private_key_type private_key_type;
                typedef typename scheme_public_key_type::public_key_type public_key_type;
                typedef typename scheme_public_key_type::part_signature_type part_signature_type;
                typedef typename scheme_public_key_type::signature_type signature_type;

                typedef typename scheme_public_key_type::public_params_type public_params_type;
                typedef typename scheme_public_key_type::pubkey_id_type pubkey_id_type;

                typedef std::vector<part_signature_type> input_block_type;
                constexpr static const std::size_t input_block_bits = 0;    // non-restricted length

                typedef typename input_block_type::value_type input_value_type;
                constexpr static const std::size_t input_value_bits = 0;    // non-integral objects
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_THRESHOLD_BLS_HPP
