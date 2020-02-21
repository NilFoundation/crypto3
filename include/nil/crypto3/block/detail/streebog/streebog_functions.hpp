//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_STREEBOG_CIPHER_FUNCTIONS_HPP
#define CRYPTO3_STREEBOG_CIPHER_FUNCTIONS_HPP

#include <boost/endian/arithmetic.hpp>
#include <boost/endian/conversion.hpp>

#include <nil/crypto3/block/detail/streebog/streebog_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<std::size_t BlockBits, std::size_t KeyBits>
                struct streebog_functions : public streebog_policy<BlockBits, KeyBits> {
                    typedef streebog_policy<BlockBits, KeyBits> policy_type;

                    constexpr static const std::size_t rounds = policy_type::rounds;

                    typedef typename policy_type::byte_type byte_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_words = policy_type::block_words;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t state_bits = block_bits;
                    constexpr static const std::size_t state_words = block_words;
                    typedef block_type state_type;

                    inline static void lps(block_type &block) {
                        using boost::endian::native_to_little;

                        std::array<byte_type, block_bits / CHAR_BIT> r;
                        pack(block, r);

                        for (int i = 0; i < block_words; ++i) {
                            block[i] = native_to_little(&policy_type::substitution[0 * policy_type::substitution_words +
                                                                                   r[i + 0 * block_words]]) ^
                                       native_to_little(policy_type::substitution[1 * policy_type::substitution_words +
                                                                                  r[i + 1 * block_words]]) ^
                                       native_to_little(policy_type::substitution[2 * policy_type::substitution_words +
                                                                                  r[i + 2 * block_words]]) ^
                                       native_to_little(policy_type::substitution[3 * policy_type::substitution_words +
                                                                                  r[i + 3 * block_words]]) ^
                                       native_to_little(policy_type::substitution[4 * policy_type::substitution_words +
                                                                                  r[i + 4 * block_words]]) ^
                                       native_to_little(policy_type::substitution[5 * policy_type::substitution_words +
                                                                                  r[i + 5 * block_words]]) ^
                                       native_to_little(policy_type::substitution[6 * policy_type::substitution_words +
                                                                                  r[i + 6 * block_words]]) ^
                                       native_to_little(policy_type::substitution[7 * policy_type::substitution_words +
                                                                                  r[i + 7 * block_words]]);
                        }

                        r.fill(0);
                    }
                };
            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_STREEBOG_FUNCTIONS_HPP
