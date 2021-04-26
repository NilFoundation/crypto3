//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_HASH_RIPEMD_HPP
#define CRYPTO3_HASH_RIPEMD_HPP

#include <nil/crypto3/hash/detail/ripemd/ripemd_policy.hpp>
#include <nil/crypto3/hash/detail/ripemd/ripemd_functions.hpp>

#include <nil/crypto3/hash/detail/merkle_damgard_construction.hpp>
#include <nil/crypto3/hash/detail/block_stream_processor.hpp>
#include <nil/crypto3/hash/detail/merkle_damgard_padding.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            template<std::size_t DigestBits>
            struct basic_ripemd_compressor {
                typedef detail::ripemd_functions<DigestBits> policy_type;

                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t state_bits = policy_type::state_bits;
                constexpr static const std::size_t state_words = policy_type::state_words;
                typedef typename policy_type::state_type state_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;
            };

            template<std::size_t DigestBits>
            struct ripemd_compressor : public basic_ripemd_compressor<DigestBits> { };

            template<>
            struct ripemd_compressor<128> : public basic_ripemd_compressor<128> {
                static void process_block(state_type &state, const block_type &block) {
                    // ripemd works on two 'lines' in parallel
                    // all variables worked on by line 1 are suffixed with 1
                    // all variables for line 2 with 2

                    word_type A1 = state[0], B1 = state[1], C1 = state[2], D1 = state[3];
                    word_type A2 = state[0], B2 = state[1], C2 = state[2], D2 = state[3];

                    // round 1

                    for (int j = 0; j < 16; ++j) {
                        policy_type::transform<policy_type::f1>(A1, B1, C1, D1, block[policy_type::r1[j]], 0x00000000,
                                                                policy_type::s1[j]);
                        policy_type::transform<policy_type::f4>(A2, B2, C2, D2, block[policy_type::r2[j]], 0x50a28be6,
                                                                policy_type::s2[j]);
                    }
                    // round 2

                    for (int j = 16; j < 32; ++j) {
                        policy_type::transform<policy_type::f2>(A1, B1, C1, D1, block[policy_type::r1[j]], 0x5a827999,
                                                                policy_type::s1[j]);
                        policy_type::transform<policy_type::f3>(A2, B2, C2, D2, block[policy_type::r2[j]], 0x5c4dd124,
                                                                policy_type::s2[j]);
                    }
                    // round 3

                    for (int j = 32; j < 48; ++j) {
                        policy_type::transform<policy_type::f3>(A1, B1, C1, D1, block[policy_type::r1[j]], 0x6ed9eba1,
                                                                policy_type::s1[j]);
                        policy_type::transform<policy_type::f2>(A2, B2, C2, D2, block[policy_type::r2[j]], 0x6d703ef3,
                                                                policy_type::s2[j]);
                    }
                    // round 4

                    for (int j = 48; j < 64; ++j) {
                        policy_type::transform<policy_type::f4>(A1, B1, C1, D1, block[policy_type::r1[j]], 0x8f1bbcdc,
                                                                policy_type::s1[j]);
                        policy_type::transform<policy_type::f1>(A2, B2, C2, D2, block[policy_type::r2[j]], 0x00000000,
                                                                policy_type::s2[j]);
                    }

                    word_type T = state[1] + C1 + D2;
                    state[1] = state[2] + D1 + A2;
                    state[2] = state[3] + A1 + B2;
                    state[3] = state[0] + B1 + C2;
                    state[0] = T;
                }
            };

            template<>
            struct ripemd_compressor<160> : public basic_ripemd_compressor<160> {
                static void process_block(state_type &state, const block_type &block) {
                    word_type A1 = state[0], B1 = state[1], C1 = state[2], D1 = state[3], E1 = state[4];
                    word_type A2 = state[0], B2 = state[1], C2 = state[2], D2 = state[3], E2 = state[4];

                    // round 1

                    for (int j = 0; j < 16; ++j) {
                        policy_type::transform<policy_type::f1>(A1, B1, C1, D1, E1, block[policy_type::r1[j]],
                                                                0x00000000, policy_type::s1[j]);
                        policy_type::transform<policy_type::f5>(A2, B2, C2, D2, E2, block[policy_type::r2[j]],
                                                                0x50a28be6, policy_type::s2[j]);
                    }
                    // round 2

                    for (int j = 16; j < 32; ++j) {
                        policy_type::transform<policy_type::f2>(A1, B1, C1, D1, E1, block[policy_type::r1[j]],
                                                                0x5a827999, policy_type::s1[j]);
                        policy_type::transform<policy_type::f4>(A2, B2, C2, D2, E2, block[policy_type::r2[j]],
                                                                0x5c4dd124, policy_type::s2[j]);
                    }
                    // round 3

                    for (int j = 32; j < 48; ++j) {
                        policy_type::transform<policy_type::f3>(A1, B1, C1, D1, E1, block[policy_type::r1[j]],
                                                                0x6ed9eba1, policy_type::s1[j]);
                        policy_type::transform<policy_type::f3>(A2, B2, C2, D2, E2, block[policy_type::r2[j]],
                                                                0x6d703ef3, policy_type::s2[j]);
                    }
                    // round 4

                    for (int j = 48; j < 64; ++j) {
                        policy_type::transform<policy_type::f4>(A1, B1, C1, D1, E1, block[policy_type::r1[j]],
                                                                0x8f1bbcdc, policy_type::s1[j]);
                        policy_type::transform<policy_type::f2>(A2, B2, C2, D2, E2, block[policy_type::r2[j]],
                                                                0x7a6d76e9, policy_type::s2[j]);
                    }
                    // round 5

                    for (int j = 64; j < 80; ++j) {
                        policy_type::transform<policy_type::f5>(A1, B1, C1, D1, E1, block[policy_type::r1[j]],
                                                                0xa953fd4e, policy_type::s1[j]);
                        policy_type::transform<policy_type::f1>(A2, B2, C2, D2, E2, block[policy_type::r2[j]],
                                                                0x00000000, policy_type::s2[j]);
                    }

                    word_type T = state[1] + C1 + D2;
                    state[1] = state[2] + D1 + E2;
                    state[2] = state[3] + E1 + A2;
                    state[3] = state[4] + A1 + B2;
                    state[4] = state[0] + B1 + C2;
                    state[0] = T;
                }
            };

            template<>
            struct ripemd_compressor<256> : public basic_ripemd_compressor<256> {
                static void process_block(state_type &state, const block_type &block) {
                    state_type Y = {0};
                    std::copy(state.begin(), state.end(), Y.begin());

                    // round 1

                    for (int j = 0; j < 16; ++j) {
                        policy_type::transform<policy_type::f1>(Y[0], Y[1], Y[2], Y[3], block[policy_type::r1[j]],
                                                                0x00000000, policy_type::s1[j]);
                        policy_type::transform<policy_type::f4>(Y[4], Y[5], Y[6], Y[7], block[policy_type::r2[j]],
                                                                0x50a28be6, policy_type::s2[j]);
                    }
                    std::swap(Y[0], Y[4]);
                    // round 2

                    for (int j = 16; j < 32; ++j) {
                        policy_type::transform<policy_type::f2>(Y[0], Y[1], Y[2], Y[3], block[policy_type::r1[j]],
                                                                0x5a827999, policy_type::s1[j]);
                        policy_type::transform<policy_type::f3>(Y[4], Y[5], Y[6], Y[7], block[policy_type::r2[j]],
                                                                0x5c4dd124, policy_type::s2[j]);
                    }
                    std::swap(Y[1], Y[5]);
                    // round 3

                    for (int j = 32; j < 48; ++j) {
                        policy_type::transform<policy_type::f3>(Y[0], Y[1], Y[2], Y[3], block[policy_type::r1[j]],
                                                                0x6ed9eba1, policy_type::s1[j]);
                        policy_type::transform<policy_type::f2>(Y[4], Y[5], Y[6], Y[7], block[policy_type::r2[j]],
                                                                0x6d703ef3, policy_type::s2[j]);
                    }
                    std::swap(Y[2], Y[6]);
                    // round 4

                    for (int j = 48; j < 64; ++j) {
                        policy_type::transform<policy_type::f4>(Y[0], Y[1], Y[2], Y[3], block[policy_type::r1[j]],
                                                                0x8f1bbcdc, policy_type::s1[j]);
                        policy_type::transform<policy_type::f1>(Y[4], Y[5], Y[6], Y[7], block[policy_type::r2[j]],
                                                                0x00000000, policy_type::s2[j]);
                    }
                    std::swap(Y[3], Y[7]);


                    for (std::size_t i = 0; i < policy_type::state_words; ++i) {
                        state[i] += Y[i];
                    }
                }
            };

            template<>
            struct ripemd_compressor<320> : public basic_ripemd_compressor<320> {
                static void process_block(state_type &state, const block_type &block) {
                    state_type Y = {0};
                    std::copy(state.begin(), state.end(), Y.begin());

                    // round 1

                    for (int j = 0; j < 16; ++j) {
                        policy_type::transform<policy_type::f1>(Y[0], Y[1], Y[2], Y[3], Y[4], block[policy_type::r1[j]],
                                                                0x00000000, policy_type::s1[j]);
                        policy_type::transform<policy_type::f5>(Y[5], Y[6], Y[7], Y[8], Y[9], block[policy_type::r2[j]],
                                                                0x50a28be6, policy_type::s2[j]);
                    }
                    std::swap(Y[1], Y[6]);
                    // round 2

                    for (int j = 16; j < 32; ++j) {
                        policy_type::transform<policy_type::f2>(Y[0], Y[1], Y[2], Y[3], Y[4], block[policy_type::r1[j]],
                                                                0x5a827999, policy_type::s1[j]);
                        policy_type::transform<policy_type::f4>(Y[5], Y[6], Y[7], Y[8], Y[9], block[policy_type::r2[j]],
                                                                0x5c4dd124, policy_type::s2[j]);
                    }
                    std::swap(Y[3], Y[8]);
                    // round 3

                    for (int j = 32; j < 48; ++j) {
                        policy_type::transform<policy_type::f3>(Y[0], Y[1], Y[2], Y[3], Y[4], block[policy_type::r1[j]],
                                                                0x6ed9eba1, policy_type::s1[j]);
                        policy_type::transform<policy_type::f3>(Y[5], Y[6], Y[7], Y[8], Y[9], block[policy_type::r2[j]],
                                                                0x6d703ef3, policy_type::s2[j]);
                    }
                    std::swap(Y[0], Y[5]);
                    // round 4

                    for (int j = 48; j < 64; ++j) {
                        policy_type::transform<policy_type::f4>(Y[0], Y[1], Y[2], Y[3], Y[4], block[policy_type::r1[j]],
                                                                0x8f1bbcdc, policy_type::s1[j]);
                        policy_type::transform<policy_type::f2>(Y[5], Y[6], Y[7], Y[8], Y[9], block[policy_type::r2[j]],
                                                                0x7a6d76e9, policy_type::s2[j]);
                    }
                    std::swap(Y[2], Y[7]);
                    // round 5

                    for (int j = 64; j < 80; ++j) {
                        policy_type::transform<policy_type::f5>(Y[0], Y[1], Y[2], Y[3], Y[4], block[policy_type::r1[j]],
                                                                0xa953fd4e, policy_type::s1[j]);
                        policy_type::transform<policy_type::f1>(Y[5], Y[6], Y[7], Y[8], Y[9], block[policy_type::r2[j]],
                                                                0x00000000, policy_type::s2[j]);
                    }
                    std::swap(Y[4], Y[9]);


                    for (std::size_t i = 0; i < policy_type::state_words; ++i) {
                        state[i] += Y[i];
                    }
                }
            };

            /*!
             * @brief Ripemd. Family of configurable hashes, developed as an open alternative to SHA.
             *
             * @ingroup hashes
             *
             * @tparam DigestBits
             */
            template<std::size_t DigestBits>
            class ripemd {
                typedef detail::ripemd_policy<DigestBits> policy_type;

            public:
                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t digest_bits = DigestBits;
                typedef typename policy_type::digest_type digest_type;

                constexpr static const std::size_t pkcs_id_size = policy_type::pkcs_id_size;
                constexpr static const std::size_t pkcs_id_bits = policy_type::pkcs_id_bits;
                typedef typename policy_type::pkcs_id_type pkcs_id_type;

                constexpr static const pkcs_id_type pkcs_id = policy_type::pkcs_id;
                constexpr static const std::uint8_t ieee1363_hash_id = policy_type::ieee1363_hash_id;

                struct construction {
                    struct params_type {
                        typedef typename policy_type::digest_endian digest_endian;

                        constexpr static const std::size_t length_bits = policy_type::length_bits;
                        constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                    };

                    typedef merkle_damgard_construction<params_type, typename policy_type::iv_generator,
                                                        ripemd_compressor<DigestBits>,
                                                        detail::merkle_damgard_padding<policy_type>>
                        type;
                };

                template<typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {
                        typedef typename policy_type::digest_endian digest_endian;

                        constexpr static const std::size_t value_bits = ValueBits;
                    };

                    typedef block_stream_processor<construction, StateAccumulator, params_type> type;
                };
            };

            typedef ripemd<128> ripemd128;
            typedef ripemd<160> ripemd160;
            typedef ripemd<256> ripemd256;
            typedef ripemd<320> ripemd320;
        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif
