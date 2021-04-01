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
                typedef public_key<base_scheme_type> base_scheme_public_key_type;

                template<typename Group>
                using secret_sharing_scheme_type = typename scheme_type::template secret_sharing_scheme_type<Group>;

                typedef secret_sharing_scheme_type<typename base_scheme_public_key_type::public_key_type::group_type>
                    sss_public_key_group_type;
                typedef secret_sharing_scheme_type<typename base_scheme_public_key_type::signature_type::group_type>
                    sss_signature_group_type;

                typedef typename sss_public_key_group_type::share_type private_key_type;
                typedef typename sss_public_key_group_type::public_share_type public_key_type;
                typedef typename sss_signature_group_type::public_share_type signature_type;

                typedef typename base_scheme_public_key_type::public_params_type public_params_type;
                typedef typename base_scheme_public_key_type::pubkey_id_type pubkey_id_type;

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

                typedef typename base_type::private_key_type private_key_type;
                typedef typename base_type::public_key_type public_key_type;
                typedef typename base_type::signature_type signature_type;

                typedef typename base_type::public_params_type public_params_type;
                typedef typename base_type::pubkey_id_type pubkey_id_type;
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
                typedef public_key<scheme_type> scheme_public_key_type;

                typedef typename scheme_public_key_type::sss_public_key_group_type sss_public_key_group_type;
                typedef typename scheme_public_key_type::sss_signature_group_type sss_signature_group_type;

                typedef typename scheme_public_key_type::private_key_type private_key_type;
                typedef typename scheme_public_key_type::public_key_type public_key_type;
                typedef typename scheme_public_key_type::signature_type signature_type;

                typedef typename scheme_public_key_type::public_params_type public_params_type;
                typedef typename scheme_public_key_type::pubkey_id_type pubkey_id_type;
            };



            template<typename Scheme, template<typename> class SecretSharingScheme>
            struct public_key<
                detail::threshold_bls<Scheme, SecretSharingScheme>,
                typename std::enable_if<
                    std::is_same<
                        weighted_shamir_sss<typename public_key<Scheme>::public_key_type::group_type>,
                        SecretSharingScheme<typename public_key<Scheme>::public_key_type::group_type>>::value>::type> {
                typedef detail::threshold_bls<Scheme, SecretSharingScheme> scheme_type;
                typedef typename scheme_type::base_scheme_type base_scheme_type;
                typedef public_key<base_scheme_type> base_scheme_public_key_type;

                template<typename Group>
                using secret_sharing_scheme_type = typename scheme_type::template secret_sharing_scheme_type<Group>;

                typedef secret_sharing_scheme_type<typename base_scheme_public_key_type::public_key_type::group_type>
                    sss_public_key_group_type;
                typedef secret_sharing_scheme_type<typename base_scheme_public_key_type::signature_type::group_type>
                    sss_signature_group_type;

                typedef typename sss_public_key_group_type::share_type private_key_type;
                typedef typename sss_public_key_group_type::public_share_type public_key_type;
                typedef typename sss_signature_group_type::public_share_type signature_type;

                typedef typename base_scheme_public_key_type::public_params_type public_params_type;
                typedef typename base_scheme_public_key_type::pubkey_id_type pubkey_id_type;

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
                typename std::enable_if<
                    std::is_same<
                        weighted_shamir_sss<typename public_key<Scheme>::public_key_type::group_type>,
                        SecretSharingScheme<typename public_key<Scheme>::public_key_type::group_type>>::value>::type>
                : public_key<detail::threshold_bls<Scheme, SecretSharingScheme>> {
                typedef public_key<detail::threshold_bls<Scheme, SecretSharingScheme>> base_type;
                typedef typename base_type::scheme_type scheme_type;
                typedef typename base_type::base_scheme_type base_scheme_type;
                typedef private_key<base_scheme_type> base_scheme_private_key_type;

                typedef typename base_type::sss_public_key_group_type sss_public_key_group_type;
                typedef typename base_type::sss_signature_group_type sss_signature_group_type;

                typedef typename base_type::private_key_type private_key_type;
                typedef typename base_type::public_key_type public_key_type;
                typedef typename base_type::signature_type signature_type;

                typedef typename base_type::public_params_type public_params_type;
                typedef typename base_type::pubkey_id_type pubkey_id_type;
            };

            template<typename Scheme, template<typename> class SecretSharingScheme>
            struct no_key_ops<
                detail::threshold_bls<Scheme, SecretSharingScheme>,
                typename std::enable_if<
                    std::is_same<
                        weighted_shamir_sss<typename public_key<Scheme>::public_key_type::group_type>,
                        SecretSharingScheme<typename public_key<Scheme>::public_key_type::group_type>>::value>::type> {
                typedef detail::threshold_bls<Scheme, SecretSharingScheme> scheme_type;
                typedef typename scheme_type::base_scheme_type base_scheme_type;
                typedef public_key<scheme_type> scheme_public_key_type;

                typedef typename scheme_public_key_type::sss_public_key_group_type sss_public_key_group_type;
                typedef typename scheme_public_key_type::sss_signature_group_type sss_signature_group_type;

                typedef typename scheme_public_key_type::private_key_type private_key_type;
                typedef typename scheme_public_key_type::public_key_type public_key_type;
                typedef typename scheme_public_key_type::signature_type signature_type;

                typedef typename scheme_public_key_type::public_params_type public_params_type;
                typedef typename scheme_public_key_type::pubkey_id_type pubkey_id_type;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_THRESHOLD_BLS_HPP
