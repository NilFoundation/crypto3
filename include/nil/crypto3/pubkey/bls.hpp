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

#include <nil/crypto3/pubkey/detail/bls/bls_basic_policy.hpp>
#include <nil/crypto3/pubkey/detail/bls/bls_core_functions.hpp>
// #include <nil/crypto3/pubkey/detail/bls/bls_key_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            //
            // Minimal-signature-size
            // Random oracle version of hash-to-point
            //
            template<typename CurveType = algebra::curves::bls12_381, typename HashType = hashes::sha2<256>>
            struct bls_signature_mss_ro_variant {
                typedef CurveType curve_type;
                typedef HashType hash_type;

                typedef detail::bls_mss_ro_policy<curve_type, hash_type> policy_type;
                typedef detail::bls_core_functions<policy_type> bls_functions;
            };

            //
            // Minimal-pubkey-size
            // Random oracle version of hash-to-point
            //
            template<typename CurveType = algebra::curves::bls12_381, typename HashType = hashes::sha2<256>>
            struct bls_signature_mps_ro_variant {
                typedef CurveType curve_type;
                typedef HashType hash_type;

                typedef detail::bls_mps_ro_policy<curve_type, hash_type> policy_type;
                typedef detail::bls_core_functions<policy_type> bls_functions;
            };

            namespace modes {
                //
                // Basic scheme
                // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-3.1
                //
                template<typename SignatureVariant>
                struct bls_basic_scheme {
                    typedef SignatureVariant signature_variant;
                    typedef typename signature_variant::policy_type policy_type;
                    typedef typename signature_variant::bls_functions bls_functions;

                    typedef typename policy_type::private_key_type private_key_type;
                    typedef typename policy_type::public_key_type public_key_type;
                    typedef typename policy_type::signature_type signature_type;

                    static inline public_key_type generate_public_key(const private_key_type &private_key) {
                        return bls_functions::sk_to_pk(private_key);
                    }

                    template<typename MsgType, typename DstType>
                    static inline signature_type sign(const private_key_type &private_key, const MsgType &message,
                                                      const DstType &dst) {
                        return bls_functions::core_sign(private_key, message, dst);
                    }

                    template<typename MsgType, typename DstType>
                    static inline bool verify(const public_key_type &public_key, const MsgType &message,
                                              const DstType &dst, const signature_type &signature) {
                        return bls_functions::core_verify(public_key, message, dst, signature);
                    }

                    template<typename SignatureRangeType>
                    static inline signature_type aggregate(const SignatureRangeType &signatures) {
                        return bls_functions::core_aggregate(signatures);
                    }

                    template<typename PubkeyRangeType, typename MsgRangeType, typename DstType>
                    static inline bool aggregate_verify(const PubkeyRangeType &public_keys,
                                                        const MsgRangeType &messages, const DstType &dst,
                                                        const signature_type &signature) {
                        // TODO: add check - If any two input messages are equal, return INVALID.
                        return bls_functions::core_aggregate_verify(public_keys, messages, dst, signature);
                    }
                };

                //
                // Message augmentation
                // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-3.2
                //
                template<typename SignatureVariant>
                struct bls_augmentation_scheme {
                    typedef SignatureVariant signature_variant;
                    typedef typename signature_variant::policy_type policy_type;
                    typedef typename signature_variant::bls_functions bls_functions;

                    typedef typename policy_type::private_key_type private_key_type;
                    typedef typename policy_type::public_key_type public_key_type;
                    typedef typename policy_type::signature_type signature_type;
                };

                //
                // Proof of possession
                // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-3.3
                //
                template<typename SignatureVariant>
                struct bls_pop_scheme {
                    typedef SignatureVariant signature_variant;
                    typedef typename signature_variant::policy_type policy_type;
                    typedef typename signature_variant::bls_functions bls_functions;

                    typedef typename policy_type::private_key_type private_key_type;
                    typedef typename policy_type::public_key_type public_key_type;
                    typedef typename policy_type::signature_type signature_type;

                    static inline public_key_type generate_public_key(const private_key_type &private_key) {
                        return bls_functions::sk_to_pk(private_key);
                    }

                    template<typename MsgType, typename DstType>
                    static inline signature_type sign(const private_key_type &private_key, const MsgType &message,
                                                      const DstType &dst) {
                        return bls_functions::core_sign(private_key, message, dst);
                    }

                    template<typename MsgType, typename DstType>
                    static inline bool verify(const public_key_type &public_key, const MsgType &message,
                                              const DstType &dst, const signature_type &signature) {
                        return bls_functions::core_verify(public_key, message, dst, signature);
                    }

                    template<typename SignatureRangeType>
                    static inline signature_type aggregate(const SignatureRangeType &signatures) {
                        return bls_functions::core_aggregate(signatures);
                    }

                    template<typename PubkeyRangeType, typename MsgRangeType, typename DstType>
                    static inline bool aggregate_verify(const PubkeyRangeType &public_keys,
                                                        const MsgRangeType &messages, const DstType &dst,
                                                        const signature_type &signature) {
                        return bls_functions::core_aggregate_verify(public_keys, messages, dst, signature);
                    }

                    template<typename PopDstType>
                    static inline signature_type pop_prove(const private_key_type &private_key, const PopDstType &dst) {
                        return bls_functions::pop_prove(private_key, dst);
                    }

                    template<typename PopDstType>
                    static inline bool pop_verify(const public_key_type &public_key, const PopDstType &dst,
                                                  const signature_type &signature) {
                        return bls_functions::pop_verify(public_key, dst, signature);
                    }

                    template<typename PubkeyRangeType, typename MsgType, typename DstType>
                    static inline bool fast_aggregate_verify(const PubkeyRangeType &public_keys, const MsgType &message,
                                                             const DstType &dst, const signature_type &signature) {
                        return bls_functions::fast_aggregate_verify(public_keys, message, dst, signature);
                    }
                };
            }    // namespace modes
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_BLS_HPP
