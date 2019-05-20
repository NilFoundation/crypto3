//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_STREEBOG_FUNCTIONS_HPP
#define CRYPTO3_STREEBOG_FUNCTIONS_HPP

#include <nil/crypto3/hash/detail/streebog/basic_streebog_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                template<std::size_t DigestBits>
                struct streebog_functions : public basic_streebog_policy<DigestBits> {
                    typedef basic_streebog_policy<DigestBits> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_words = policy_type::block_words;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t state_bits = block_bits;
                    constexpr static const std::size_t state_words = block_words;
                    typedef block_type state_type;

                    inline static void addm(const uint8_t *m, word_type *h) {
                        word_type carry = 0;
                        for (int i = 0; i < 8; i++) {
                            const word_type m64 = load_le<word_type>(m, i);
                            const word_type hi = load_le<word_type>(reinterpret_cast<uint8_t *>(h), i);
                            const word_type t = hi + m64;

                            const word_type overflow = (t < hi ? 1 : 0) | (t < m64 ? 1 : 0);
                            store_le(t + carry, reinterpret_cast<uint8_t *>(&h[i]));
                            carry = overflow;
                        }
                    }

                    inline static void lps(const block_type &block) {
                        std::array<typename policy_type::byte_type, block_bits / 512> r;
                        pack(block, r);

                        for (int i = 0; i < 8; ++i) {
                            block[i] = load_le<word_type>(reinterpret_cast<const uint8_t *>
                            (&policy_type::substitution[0 * policy_type::substitution_words + r[i]]), 0) ^
                                       load_le<word_type>(reinterpret_cast<const uint8_t *>(&policy_type::substitution[
                                               1 * policy_type::substitution_words + r[i + 8]]), 0) ^
                                       load_le<word_type>(reinterpret_cast<const uint8_t *>(&policy_type::substitution[
                                               2 * policy_type::substitution_words + r[i + 16]]), 0) ^
                                       load_le<word_type>(reinterpret_cast<const uint8_t *>(&policy_type::substitution[
                                               3 * policy_type::substitution_words + r[i + 24]]), 0) ^
                                       load_le<word_type>(reinterpret_cast<const uint8_t *>(&policy_type::substitution[
                                               4 * policy_type::substitution_words + r[i + 32]]), 0) ^
                                       load_le<word_type>(reinterpret_cast<const uint8_t *>(&policy_type::substitution[
                                               5 * policy_type::substitution_words + r[i + 40]]), 0) ^
                                       load_le<word_type>(reinterpret_cast<const uint8_t *>(&policy_type::substitution[
                                               6 * policy_type::substitution_words + r[i + 48]]), 0) ^
                                       load_le<word_type>(reinterpret_cast<const uint8_t *>(&policy_type::substitution[
                                               7 * policy_type::substitution_words + r[i + 56]]), 0);
                        }
                    }

                    inline static void e(word_type *K, const word_type *m) {
                        word_type A[8];
                        word_type C[8];

                        copy_mem(A, K, 8);

                        for (size_t i = 0; i != 8; ++i) {
                            K[i] ^= m[i];
                        }

                        for (size_t i = 0; i < 12; ++i) {
                            lps(K);
                            load_le(C, reinterpret_cast<const uint8_t *>(&policy_type::round_constants[i *
                                                                                                       policy_type::substitutions_amount]),
                                    8);

                            for (size_t j = 0; j != 8; ++j) {
                                A[j] ^= C[j];
                            }
                            lps(A);
                            for (size_t j = 0; j != 8; ++j) {
                                K[j] ^= A[j];
                            }
                        }
                    }

                    inline static void g(state_type &state, const uint8_t *m, word_type N) {
                        word_type hN[8];

                        // force N to little-endian
                        store_le(N, reinterpret_cast<uint8_t *>(&N));

                        copy_mem(hN, state, 8);
                        hN[0] ^= N;
                        lps(hN);
                        const word_type *m64 = reinterpret_cast<const word_type *>(m);

                        e(hN, m64);

                        for (size_t i = 0; i != 8; ++i) {
                            state[i] ^= hN[i] ^ m64[i];
                        }
                    }
                };
            }
        }
    }
}

#endif //CRYPTO3_STREEBOG_FUNCTIONS_HPP
