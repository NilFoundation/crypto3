//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_THREEFISH_POLICY_HPP
#define CRYPTO3_THREEFISH_POLICY_HPP

#include <array>

#include <nil/crypto3/block/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {

                template<std::size_t KeyBits>
                struct basic_threefish_policy : public basic_functions<64> {

                    constexpr static const std::size_t block_bits = KeyBits;
                    constexpr static const std::size_t block_words = block_bits / word_bits;
                    typedef std::array<word_type, block_words> block_type;

                    constexpr static const std::size_t key_bits = KeyBits;
                    constexpr static const std::size_t key_words = key_bits / word_bits;
                    typedef std::array<word_type, key_words> key_type;
                    typedef std::array<word_type, key_words + 1> key_schedule_type;

                    constexpr static const std::size_t tweak_bits = 128;
                    constexpr static const std::size_t tweak_words = tweak_bits / word_bits;
                    typedef std::array<word_type, tweak_words> tweak_type;
                    typedef std::array<word_type, tweak_words + 1> tweak_schedule_type;

                    typedef std::array<unsigned, block_words> permutations_type;
                    typedef std::array<std::array<std::size_t, block_words / 2>, 8> rotations_type;

                };

                template<std::size_t KeyBits>
                struct threefish_policy;

                template<>
                struct threefish_policy<256> : basic_threefish_policy<256> {

                    constexpr static const std::size_t rounds = 72;
                    typedef std::array<word_type, rounds> constants_type;

                    constexpr static const permutations_type permutation = {{0, 3, 2, 1}};

                    constexpr static const rotations_type rotations = {{
#ifdef CRYPTO3_BLOCK_THREEFISH_OLD_ROTATION_CONSTANTS
                                                                       {{ 5, 56}},
                                                                       {{36, 28}},
                                                                       {{13, 46}},
                                                                       {{58, 44}},
                                                                       {{26, 20}},
                                                                       {{53, 35}},
                                                                       {{11, 42}},
                                                                       {{59, 50}},
#else
                                                                               {{14, 16}}, {{52, 57}}, {{23, 40}}, {{5, 37}}, {{25, 33}}, {{46, 12}}, {{58, 22}}, {{32, 32}},
#endif
                                                                       }};
                };

                constexpr threefish_policy<256>::permutations_type const threefish_policy<256>::permutation;
                constexpr threefish_policy<256>::rotations_type const threefish_policy<256>::rotations;

                template<>
                struct threefish_policy<512> : basic_threefish_policy<512> {

                    constexpr static const std::size_t rounds = 72;
                    typedef std::array<word_type, rounds> constants_type;

                    constexpr static permutations_type const permutation = {{2, 1, 4, 7, 6, 5, 0, 3}};

                    constexpr static rotations_type const rotations = {{
#ifdef CRYPTO3_BLOCK_THREEFISH_OLD_ROTATION_CONSTANTS
                                                                       {{38, 30, 50, 53}},
                                                                       {{48, 20, 43, 31}},
                                                                       {{34, 14, 15, 27}},
                                                                       {{26, 12, 58,  7}},
                                                                       {{33, 49,  8, 42}},
                                                                       {{39, 27, 41, 14}},
                                                                       {{29, 26, 11,  9}},
                                                                       {{33, 51, 39, 35}},
#else
                                                                               {{46, 36, 19, 37}}, {{33, 27, 14, 42}}, {{17, 49, 36, 39}}, {{44, 9, 54, 56}}, {{39, 30, 34, 24}}, {{13, 50, 10, 17}}, {{25, 29, 39, 43}}, {{8, 35, 56, 22}}
#endif
                                                                       }};
                };

                constexpr threefish_policy<512>::permutations_type const threefish_policy<512>::permutation;
                constexpr threefish_policy<512>::rotations_type const threefish_policy<512>::rotations;

                template<>
                struct threefish_policy<1024> : basic_threefish_policy<1024> {

                    constexpr static const std::size_t rounds = 80;
                    typedef std::array<word_type, rounds> constants_type;

                    constexpr static permutations_type const permutation = {{0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1}};

                    constexpr static rotations_type const rotations = {{
#ifdef CRYPTO3_BLOCK_THREEFISH_OLD_ROTATION_CONSTANTS
                                                                       {{55, 43, 37, 40, 16, 22, 38, 12}},
                                                                       {{25, 25, 46, 13, 14, 13, 52, 57}},
                                                                       {{33,  8, 18, 57, 21, 12, 32, 54}},
                                                                       {{34, 43, 25, 60, 44,  9, 59, 34}},
                                                                       {{28,  7, 47, 48, 51,  9, 35, 41}},
                                                                       {{17,  6, 18, 25, 43, 42, 40, 15}},
                                                                       {{58,  7, 32, 45, 19, 18,  2, 56}},
                                                                       {{47, 49, 27, 58, 37, 48, 53, 56}},
#else
                                                                               {{24, 13, 8, 47, 8, 17, 22, 37}}, {{38, 19, 10, 55, 49, 18, 23, 52}}, {{33, 4, 51, 13, 34, 41, 59, 17}}, {{5, 20, 48, 41, 47, 28, 16, 25}}, {{41, 9, 37, 31, 12, 47, 44, 30}}, {{16, 34, 56, 51, 4, 53, 42, 41}}, {{31, 44, 47, 46, 19, 42, 44, 25}}, {{9, 48, 35, 52, 23, 31, 37, 20}}
#endif
                                                                       }};
                };

                constexpr threefish_policy<1024>::permutations_type const threefish_policy<1024>::permutation;
                constexpr threefish_policy<1024>::rotations_type const threefish_policy<1024>::rotations;

            } // namespace detail
        }
    }
} // namespace nil

#endif // CRYPTO3_THREEFISH_POLICY_HPP
