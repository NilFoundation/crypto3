//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_BLS_HPP
#define CRYPTO3_PUBKEY_BLS_HPP

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/pubkey/private_key.hpp>
#include <nil/crypto3/pubkey/detail/bls/bls_basic_policy.hpp>
#include <nil/crypto3/pubkey/detail/bls/bls_core_functions.hpp>
#include <nil/crypto3/pubkey/detail/stream_processor.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                //
                // Basic scheme
                // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-3.1
                //
                template<typename SignatureVariant>
                struct bls_basic_scheme {
                    typedef SignatureVariant signature_variant;
                    typedef typename signature_variant::policy_type policy_type;
                    typedef typename signature_variant::core_functions core_functions;
                    typedef typename signature_variant::public_params public_params;

                    typedef typename policy_type::private_key_type private_key_type;
                    typedef typename policy_type::public_key_type public_key_type;
                    typedef typename policy_type::signature_type signature_type;

                    template<typename MsgType>
                    static inline signature_type sign(const private_key_type &privkey, const MsgType &message,
                                                      const public_params &pp) {
                        return sign(privkey, message, pp.dst);
                    }

                    template<typename MsgType>
                    static inline bool verify(const public_key_type &pubkey, const MsgType &message,
                                              const signature_type &signature, const public_params &pp) {
                        return verify(pubkey, message, pp.dst, signature);
                    }

                    template<typename SignatureRangeType>
                    static inline signature_type aggregate(const SignatureRangeType &signatures,
                                                           const public_params &pp) {
                        return aggregate(signatures);
                    }

                    template<typename PubkeyRangeType, typename MsgRangeType>
                    static inline bool aggregate_verify(const PubkeyRangeType &pubkeys, const MsgRangeType &messages,
                                                        const signature_type &signature, const public_params &pp) {
                        // TODO: add check - If any two input messages are equal, return INVALID.
                        return aggregate_verify(pubkeys, messages, pp.dst, signature);
                    }

                    // TODO: generate_private_key

                    static inline public_key_type generate_public_key(const private_key_type &privkey) {
                        return core_functions::sk_to_pk(privkey);
                    }

                // protected:
                    template<typename MsgType, typename DstType>
                    static inline signature_type sign(const private_key_type &privkey, const MsgType &message,
                                                      const DstType &dst) {
                        return core_functions::core_sign(privkey, message, dst);
                    }

                    template<typename MsgType, typename DstType>
                    static inline bool verify(const public_key_type &pubkey, const MsgType &message, const DstType &dst,
                                              const signature_type &signature) {
                        return core_functions::core_verify(pubkey, message, dst, signature);
                    }

                    template<typename SignatureRangeType>
                    static inline signature_type aggregate(const SignatureRangeType &signatures) {
                        return core_functions::core_aggregate(signatures);
                    }

                    template<typename PubkeyRangeType, typename MsgRangeType, typename DstType>
                    static inline bool aggregate_verify(const PubkeyRangeType &pubkeys, const MsgRangeType &messages,
                                                        const DstType &dst, const signature_type &signature) {
                        // TODO: add check - If any two input messages are equal, return INVALID.
                        return core_functions::core_aggregate_verify(pubkeys, messages, dst, signature);
                    }
                };

                //
                // Message augmentation
                // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-3.2
                //
                template<typename SignatureVariant>
                struct bls_aug_scheme {
                    typedef SignatureVariant signature_variant;
                    typedef typename signature_variant::policy_type policy_type;
                    typedef typename signature_variant::core_functions core_functions;

                    typedef typename policy_type::private_key_type private_key_type;
                    typedef typename policy_type::public_key_type public_key_type;
                    typedef typename policy_type::signature_type signature_type;

                    static inline public_key_type generate_public_key(const private_key_type &privkey) {
                        return core_functions::sk_to_pk(privkey);
                    }

                    // TODO: implement an interface that takes the public key as input
                    template<typename MsgType, typename DstType>
                    static inline signature_type sign(const private_key_type &privkey, const MsgType &message,
                                                      const DstType &dst) {
                        public_key_type pubkey = generate_public_key(privkey);
                        return core_functions::core_sign(privkey, core_functions::pk_conc_msg(pubkey, message), dst);
                    }

                    template<typename MsgType, typename DstType>
                    static inline bool verify(const public_key_type &pubkey, const MsgType &message, const DstType &dst,
                                              const signature_type &signature) {
                        return core_functions::core_verify(pubkey, core_functions::pk_conc_msg(pubkey, message), dst,
                                                           signature);
                    }

                    template<typename SignatureRangeType>
                    static inline signature_type aggregate(const SignatureRangeType &signatures) {
                        return core_functions::core_aggregate(signatures);
                    }

                    template<typename PubkeyRangeType, typename MsgRangeType, typename DstType>
                    static inline bool aggregate_verify(const PubkeyRangeType &pubkeys, const MsgRangeType &messages,
                                                        const DstType &dst, const signature_type &signature) {
                        return core_functions::aug_aggregate_verify(pubkeys, messages, dst, signature);
                    }
                };

                //
                // Proof of possession
                // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-3.3
                //
                template<typename SignatureVariant>
                struct bls_pop_scheme {
                    typedef SignatureVariant signature_variant;
                    typedef typename signature_variant::policy_type policy_type;
                    typedef typename signature_variant::core_functions core_functions;

                    typedef typename policy_type::private_key_type private_key_type;
                    typedef typename policy_type::public_key_type public_key_type;
                    typedef typename policy_type::signature_type signature_type;

                    static inline public_key_type generate_public_key(const private_key_type &privkey) {
                        return core_functions::sk_to_pk(privkey);
                    }

                    template<typename MsgType, typename DstType>
                    static inline signature_type sign(const private_key_type &privkey, const MsgType &message,
                                                      const DstType &dst) {
                        return core_functions::core_sign(privkey, message, dst);
                    }

                    template<typename MsgType, typename DstType>
                    static inline bool verify(const public_key_type &pubkey, const MsgType &message, const DstType &dst,
                                              const signature_type &signature) {
                        return core_functions::core_verify(pubkey, message, dst, signature);
                    }

                    template<typename SignatureRangeType>
                    static inline signature_type aggregate(const SignatureRangeType &signatures) {
                        return core_functions::core_aggregate(signatures);
                    }

                    template<typename PubkeyRangeType, typename MsgRangeType, typename DstType>
                    static inline bool aggregate_verify(const PubkeyRangeType &pubkeys, const MsgRangeType &messages,
                                                        const DstType &dst, const signature_type &signature) {
                        return core_functions::core_aggregate_verify(pubkeys, messages, dst, signature);
                    }

                    // TODO: implement an interface that takes the public key as input
                    template<typename PopDstType>
                    static inline signature_type pop_prove(const private_key_type &privkey, const PopDstType &dst) {
                        return core_functions::pop_prove(privkey, dst);
                    }

                    template<typename PopDstType>
                    static inline bool pop_verify(const public_key_type &pubkey, const PopDstType &dst,
                                                  const signature_type &proof) {
                        return core_functions::pop_verify(pubkey, dst, proof);
                    }

                    template<typename PubkeyRangeType, typename MsgType, typename DstType>
                    static inline bool fast_aggregate_verify(const PubkeyRangeType &pubkeys, const MsgType &message,
                                                             const DstType &dst, const signature_type &signature) {
                        return core_functions::fast_aggregate_verify(pubkeys, message, dst, signature);
                    }
                };
            }    // namespace detail

            struct bls_public_params {
                typedef std::vector<std::uint8_t> dst_type;

                dst_type dst;
            };

            //
            // Minimal-signature-size
            // Random oracle version of hash-to-point
            //
            template<typename CurveType = algebra::curves::bls12_381, typename HashType = hashes::sha2<256>>
            struct bls_mss_ro_variant {
                typedef CurveType curve_type;
                typedef HashType hash_type;

                typedef detail::bls_mss_ro_policy<curve_type, hash_type> policy_type;
                typedef detail::bls_core_functions<policy_type> core_functions;
                typedef bls_public_params public_params;
            };

            //
            // Minimal-pubkey-size
            // Random oracle version of hash-to-point
            //
            template<typename CurveType = algebra::curves::bls12_381, typename HashType = hashes::sha2<256>>
            struct bls_mps_ro_variant {
                typedef CurveType curve_type;
                typedef HashType hash_type;

                typedef detail::bls_mps_ro_policy<curve_type, hash_type> policy_type;
                typedef detail::bls_core_functions<policy_type> core_functions;
                typedef bls_public_params public_params;
            };

            enum class bls_scheme_type { basic, aug, pop };

            template<bls_scheme_type, typename SignatureVariant>
            struct bls_scheme_trait { };

            template<typename SignatureVariant>
            struct bls_scheme_trait<bls_scheme_type::basic, SignatureVariant> {
                typedef detail::bls_basic_scheme<SignatureVariant> scheme_type;
            };

            template<typename SignatureVariant>
            struct bls_scheme_trait<bls_scheme_type::aug, SignatureVariant> {
                typedef detail::bls_aug_scheme<SignatureVariant> scheme_type;
            };

            template<typename SignatureVariant>
            struct bls_scheme_trait<bls_scheme_type::pop, SignatureVariant> {
                typedef detail::bls_pop_scheme<SignatureVariant> scheme_type;
            };

            // TODO: add specialization for pop scheme
            template<typename SchemeType>
            struct bls_private_key {
                typedef SchemeType scheme_type;

                typedef typename scheme_type::private_key_type private_key_type;
                typedef typename scheme_type::public_key_type public_key_type;
                typedef typename scheme_type::signature_type signature_type;
                typedef typename scheme_type::public_params public_params;

                typedef private_key_type key_type;

                template<typename MsgType>
                static inline signature_type sign(const private_key_type &privkey, const MsgType &message,
                                                  const public_params &pp) {
                    return scheme_type::sign(privkey, message, pp);
                }

                template<typename SignatureRangeType>
                static inline signature_type aggregate(const SignatureRangeType &signatures,
                                                       const public_params &pp) {
                    return scheme_type::aggregate(signatures, pp);
                }
            };

            // TODO: add specialization for pop scheme
            template<typename SchemeType>
            struct bls_public_key {
                typedef SchemeType scheme_type;

                typedef typename scheme_type::private_key_type private_key_type;
                typedef typename scheme_type::public_key_type public_key_type;
                typedef typename scheme_type::signature_type signature_type;
                typedef typename scheme_type::public_params public_params;

                typedef public_key_type key_type;

                static inline public_key_type key_gen(const private_key_type &privkey) {
                    return scheme_type::generate_public_key(privkey);
                }

                template<typename MsgType>
                static inline bool verify(const public_key_type &pubkey, const MsgType &message,
                                          const signature_type &signature, const public_params &pp) {
                    return scheme_type::verify(pubkey, message, signature, pp);
                }

                template<typename PubkeyRangeType, typename MsgRangeType>
                static inline bool aggregate_verify(const PubkeyRangeType &pubkeys, const MsgRangeType &messages,
                                                    const signature_type &signature, const public_params &pp) {
                    return scheme_type::aggregate_verify(pubkeys, messages, signature, pp);
                }
            };

            template<typename SignatureVariant, bls_scheme_type bls_scheme = bls_scheme_type::basic>
            class bls {
                typedef typename bls_scheme_trait<bls_scheme, SignatureVariant>::scheme_type scheme_type;

            public:
                typedef bls_private_key<scheme_type> private_key_type;
                typedef bls_public_key<scheme_type> public_key_type;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_BLS_HPP
