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
#include <nil/crypto3/pubkey/detail/bls/bls_key_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            //
            // Minimal-signature-size
            // Random oracle version of hash-to-point
            //
            template<typename CurveType = algebra::curves::bls12_381, typename HashType = hashes::sha2<256>>
            struct bls_signature_mss_ro_policy {
                typedef CurveType curve_type;
                typedef HashType hash_type;

                typedef detail::bls_policy_mss_ro<curve_type, hash_type> policy_type;

                typedef detail::bls_public_key_policy<policy_type> public_key_policy_type;
                typedef detail::bls_private_key_policy<policy_type> private_key_policy_type;
            };

            //
            // Minimal-pubkey-size
            // Random oracle version of hash-to-point
            //
            template<typename CurveType = algebra::curves::bls12_381, typename HashType = hashes::sha2<256>>
            struct bls_signature_mps_ro_policy {
                typedef CurveType curve_type;
                typedef HashType hash_type;

                typedef detail::bls_policy_mps_ro<curve_type, hash_type> policy_type;

                typedef detail::bls_public_key_policy<policy_type> public_key_policy_type;
                typedef detail::bls_private_key_policy<policy_type> private_key_policy_type;
            };

            namespace modes {
                template<typename bls_signature_policy>
                struct bls_basic_scheme {
                    typedef typename bls_signature_policy::private_key_policy_type private_key_policy_type;
                    typedef typename bls_signature_policy::public_key_policy_type public_key_policy_type;

                    typedef typename private_key_policy_type::private_key_type private_key_type;
                    typedef typename public_key_policy_type::public_key_type public_key_type;
                    typedef typename public_key_policy_type::signature_type signature_type;

                    template<typename MsgType, typename DstType>
                    static inline signature_type sign(const private_key_type &private_key, const MsgType &message,
                                                      const DstType &dst) {
                        return private_key_policy_type::sign(private_key, message, dst);
                    }

                    template<typename MsgType, typename DstType>
                    static inline bool verify(const public_key_type &public_key, const MsgType &message,
                                              const DstType &dst, const signature_type &signature) {
                        return public_key_policy_type::verify(public_key, message, dst, signature);
                    }

                    template<typename SignatureRangeType>
                    static inline signature_type aggregate(const SignatureRangeType &signatures) {
                        return private_key_policy_type::aggregate(signatures);
                    }

                    template<typename PubkeyRangeType, typename MsgRangeType, typename DstType>
                    static inline bool aggregate_verify(const PubkeyRangeType &public_keys,
                                                        const MsgRangeType &messages, const DstType &dst,
                                                        const signature_type &signature) {
                        // TODO: add check - If any two input messages are equal, return INVALID.
                        return public_key_policy_type::aggregate_verify(public_keys, messages, dst, signature);
                    }
                };

                // Message augmentation
                // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-3.2
                template<typename bls_signature_policy>
                struct bls_augmentation_scheme {
                    typedef typename bls_signature_policy::public_key_policy_type public_key_policy_type;
                    typedef typename bls_signature_policy::private_key_policy_type private_key_policy_type;

                    typedef typename private_key_policy_type::private_key_type private_key_type;
                    typedef typename public_key_policy_type::public_key_type public_key_type;
                    typedef typename public_key_policy_type::signature_type signature_type;
                };

                // Proof of possession
                // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-3.3
                template<typename bls_signature_policy>
                struct bls_pop_scheme {
                    typedef typename bls_signature_policy::public_key_policy_type public_key_policy_type;
                    typedef typename bls_signature_policy::private_key_policy_type private_key_policy_type;

                    typedef typename private_key_policy_type::private_key_type private_key_type;
                    typedef typename public_key_policy_type::public_key_type public_key_type;
                    typedef typename public_key_policy_type::signature_type signature_type;

                    template<typename MsgType, typename DstType>
                    static inline signature_type sign(const private_key_type &private_key, const MsgType &message,
                                                      const DstType &dst) {
                        return private_key_policy_type::sign(private_key, message, dst);
                    }

                    template<typename MsgType, typename DstType>
                    static inline bool verify(const public_key_type &public_key, const MsgType &message,
                                              const DstType &dst, const signature_type &signature) {
                        return public_key_policy_type::verify(public_key, message, dst, signature);
                    }

                    template<typename SignatureRangeType>
                    static inline signature_type aggregate(const SignatureRangeType &signatures) {
                        return private_key_policy_type::aggregate(signatures);
                    }

                    template<typename PubkeyRangeType, typename MsgRangeType, typename DstType>
                    static inline bool aggregate_verify(const PubkeyRangeType &public_keys,
                                                        const MsgRangeType &messages, const DstType &dst,
                                                        const signature_type &signature) {
                        return public_key_policy_type::aggregate_verify(public_keys, messages, dst, signature);
                    }

                    template<typename DstType>
                    static inline signature_type pop_prove(const private_key_type &private_key, const DstType &dst) {
                        public_key_type public_key = public_key_policy_type::key_gen(private_key);


                    }

                };
            }    // namespace modes
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_BLS_HPP
