//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_TIGER_FUNCTIONS_HPP
#define CRYPTO3_TIGER_FUNCTIONS_HPP

#include <nil/crypto3/hash/detail/tiger/basic_tiger_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                template<std::size_t DigestBits>
                struct tiger_functions : public basic_tiger_policy<DigestBits> {
                    typedef basic_tiger_policy<DigestBits> policy_type;

                    typedef typename policy_type::byte_type byte_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t block_bits = basic_tiger_policy<DigestBits>::block_bits;
                    constexpr static const std::size_t block_words = basic_tiger_policy<DigestBits>::block_words;
                    typedef typename basic_tiger_policy<DigestBits>::block_type block_type;

                    inline static void mix(block_type &X) {
                        X[0] -= X[7] ^ 0xA5A5A5A5A5A5A5A5;
                        X[1] ^= X[0];
                        X[2] += X[1];
                        X[3] -= X[2] ^ ((~X[1]) << 19);
                        X[4] ^= X[3];
                        X[5] += X[4];
                        X[6] -= X[5] ^ ((~X[4]) >> 23);
                        X[7] ^= X[6];

                        X[0] += X[7];
                        X[1] -= X[0] ^ ((~X[7]) << 19);
                        X[2] ^= X[1];
                        X[3] += X[2];
                        X[4] -= X[3] ^ ((~X[2]) >> 23);
                        X[5] ^= X[4];
                        X[6] += X[5];
                        X[7] -= X[6] ^ 0x0123456789ABCDEF;
                    }

                    inline static void pass(word_type &A, word_type &B, word_type &C, block_type &X, byte_type mul) {
                        C ^= X[0];
                        A -= policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(C, 7)] ^
                             policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(C, 5)] ^
                             policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(C, 3)] ^
                             policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(C, 1)];
                        B += policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(C, 0)] ^
                             policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(C, 2)] ^
                             policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(C, 4)] ^
                             policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(C, 6)];
                        B *= mul;

                        A ^= X[1];
                        B -= policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(A, 7)] ^
                             policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(A, 5)] ^
                             policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(A, 3)] ^
                             policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(A, 1)];
                        C += policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(A, 0)] ^
                             policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(A, 2)] ^
                             policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(A, 4)] ^
                             policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(A, 6)];
                        C *= mul;

                        B ^= X[2];
                        C -= policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(B, 7)] ^
                             policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(B, 5)] ^
                             policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(B, 3)] ^
                             policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(B, 1)];
                        A += policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(B, 0)] ^
                             policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(B, 2)] ^
                             policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(B, 4)] ^
                             policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(B, 6)];
                        A *= mul;

                        C ^= X[3];
                        A -= policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(C, 7)] ^
                             policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(C, 5)] ^
                             policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(C, 3)] ^
                             policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(C, 1)];
                        B += policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(C, 0)] ^
                             policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(C, 2)] ^
                             policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(C, 4)] ^
                             policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(C, 6)];
                        B *= mul;

                        A ^= X[4];
                        B -= policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(A, 7)] ^
                             policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(A, 5)] ^
                             policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(A, 3)] ^
                             policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(A, 1)];
                        C += policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(A, 0)] ^
                             policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(A, 2)] ^
                             policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(A, 4)] ^
                             policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(A, 6)];
                        C *= mul;

                        B ^= X[5];
                        C -= policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(B, 7)] ^
                             policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(B, 5)] ^
                             policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(B, 3)] ^
                             policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(B, 1)];
                        A += policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(B, 0)] ^
                             policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(B, 2)] ^
                             policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(B, 4)] ^
                             policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(B, 6)];
                        A *= mul;

                        C ^= X[6];
                        A -= policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(C, 7)] ^
                             policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(C, 5)] ^
                             policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(C, 3)] ^
                             policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(C, 1)];
                        B += policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(C, 0)] ^
                             policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(C, 2)] ^
                             policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(C, 4)] ^
                             policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(C, 6)];
                        B *= mul;

                        A ^= X[7];
                        B -= policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(A, 7)] ^
                             policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(A, 5)] ^
                             policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(A, 3)] ^
                             policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(A, 1)];
                        C += policy_type::sbox1[policy_type::template extract_uint_t<CHAR_BIT>(A, 0)] ^
                             policy_type::sbox2[policy_type::template extract_uint_t<CHAR_BIT>(A, 2)] ^
                             policy_type::sbox3[policy_type::template extract_uint_t<CHAR_BIT>(A, 4)] ^
                             policy_type::sbox4[policy_type::template extract_uint_t<CHAR_BIT>(A, 6)];
                        C *= mul;
                    }
                };
            }
        }
    }
}

#endif //CRYPTO3_TIGER_FUNCTIONS_HPP
