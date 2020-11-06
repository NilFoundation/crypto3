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

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/pubkey/detail/bls/bls_basic_key_policy.hpp>
#include <nil/crypto3/pubkey/detail/bls/bls_functions.hpp>

#include <cstdint>
#include <array>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename bls_key_policy>
            class bls_private_key_policy {
                typedef detail::bls_functions<bls_key_policy> bls_functions;

            public:
                typedef typename bls_functions::private_key_type private_key_type;
                typedef typename bls_functions::public_key_type public_key_type;
                typedef typename bls_functions::signature_type signature_type;

                // template<typename SeedType, typename KeyInfoType>
                // static inline private_key_type key_gen(const SeedType &seed,
                //                                        const KeyInfoType &key_info = std::array<std::uint8_t, 0> {}) {
                //     return bls_functions::key_gen(seed, key_info);
                // }

                static inline bool key_validate(const private_key_type &private_key) {
                    return bls_functions::private_key_validate(private_key);
                }

                template<typename MsgType, typename DstType>
                static inline signature_type sign(const private_key_type &private_key, const MsgType &message,
                                                  const DstType &dst) {
                    return bls_functions::core_sign(private_key, message, dst);
                }

                template<typename SignatureRangeType>
                static inline signature_type aggregate(const SignatureRangeType &signatures) {
                    return bls_functions::aggregate(signatures);
                }
            };

            template<typename bls_key_policy>
            struct bls_public_key_policy {
                typedef detail::bls_functions<bls_key_policy> bls_functions;

            public:
                typedef typename bls_functions::private_key_type private_key_type;
                typedef typename bls_functions::public_key_type public_key_type;
                typedef typename bls_functions::signature_type signature_type;

                static inline public_key_type key_gen(const private_key_type &private_key) {
                    return bls_functions::sk_to_pk();
                }

                static inline bool key_validate(const public_key_type &public_key) {
                    return bls_functions::public_key_validate(public_key);
                }

                template<typename MsgType, typename DstType>
                static inline bool verify(const public_key_type &public_key, const MsgType &message,
                                          const DstType &dst, const signature_type &signature) {
                    return bls_functions::core_verify(public_key, message, dst, signature);
                }

                template<typename PubkeyRangeType, typename MsgRangeType, typename DstType>
                static inline bool aggregate_verify(const PubkeyRangeType &public_keys, const MsgRangeType &messages,
                                                    const DstType &dst, const signature_type &signature) {
                    return bls_functions::core_aggregate_verify(public_keys, messages, dst, signature);
                }
            };

            template<typename CurveType = algebra::curves::bls12_381, typename HashType = hashes::sha2<256>>
            struct bls_signature_mss_ro {
                typedef CurveType curve_type;
                typedef HashType hash_type;

                typedef detail::bls_key_policy_mss_ro<curve_type, hash_type> bls_key_policy;

                typedef bls_public_key_policy<bls_key_policy> public_key_policy_type;
                typedef bls_private_key_policy<bls_key_policy> private_key_policy_type;
            };

            template<typename CurveType = algebra::curves::bls12_381, typename HashType = hashes::sha2<256>>
            struct bls_signature_mps_ro {
                typedef CurveType curve_type;
                typedef HashType hash_type;

                typedef detail::bls_key_policy_mps_ro<curve_type, hash_type> bls_key_policy;

                typedef bls_public_key_policy<bls_key_policy> public_key_policy_type;
                typedef bls_private_key_policy<bls_key_policy> private_key_policy_type;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif // CRYPTO3_PUBKEY_BLS_HPP
