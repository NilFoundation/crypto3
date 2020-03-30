//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_STREEBOG_FUNCTIONS_HPP
#define CRYPTO3_STREEBOG_FUNCTIONS_HPP

#include <nil/crypto3/hash/detail/streebog/streebog_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                template<std::size_t DigestBits>
                struct streebog_functions : public streebog_policy<DigestBits> {
                    typedef streebog_policy<DigestBits> policy_type;
                    typedef typename policy_type::block_cipher_type block_cipher_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_words = policy_type::block_words;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t state_bits = policy_type::state_bits;
                    constexpr static const std::size_t state_words = policy_type::state_words;
                    typedef typename policy_type::state_type state_type;

                    inline static void addm(const uint8_t *m, word_type *h) {
                        word_type carry = 0;
                        for (int i = 0; i < block_words; i++) {
                            const word_type m64 = boost::endian::native_to_little(m[i]);
                            const word_type hi = boost::endian::native_to_little(reinterpret_cast<uint8_t *>(h)[i]);
                            const word_type t = hi + m64;

                            const word_type overflow = (t < hi ? 1 : 0) | (t < m64 ? 1 : 0);
                            store_le(t + carry, reinterpret_cast<uint8_t *>(&h[i]));
                            carry = overflow;
                        }
                    }

                    inline static void g(state_type &state, const uint8_t *m, word_type N) {
                        block_type hN = state;

                        hN[0] ^= boost::endian::native_to_little(N);
                        lps(hN);
                        const word_type *m64 = reinterpret_cast<const word_type *>(m);

                        block_cipher_type::encrypt(hN, m64);

                        for (size_t i = 0; i != block_words; ++i) {
                            state[i] ^= hN[i] ^ m64[i];
                        }
                    }
                };
            }    // namespace detail
        }        // namespace hash
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_STREEBOG_FUNCTIONS_HPP
