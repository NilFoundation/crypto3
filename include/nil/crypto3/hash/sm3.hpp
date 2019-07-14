//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SM3_HPP_
#define CRYPTO3_SM3_HPP_

#include <nil/crypto3/hash/detail/merkle_damgard_stream_processor.hpp>
#include <nil/crypto3/hash/detail/merkle_damgard_construction.hpp>
#include <nil/crypto3/hash/detail/state_adder.hpp>

#include <nil/crypto3/hash/detail/sm3/sm3_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            /*!
             * @brief SM3 hash compressor
             *
             * @note Custom compressor is highly likely possible to be converted to Davies-Meyer compressor
             */
            class sm3_compressor {
                typedef detail::sm3_policy policy_type;

            public:
                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t state_bits = policy_type::state_bits;
                constexpr static const std::size_t state_words = policy_type::state_words;
                typedef typename policy_type::state_type state_type;

                void operator()(state_type &state, const block_type &block) {
                    word_type A = state[0], B = state[1], C = state[2], D = state[3], E = state[4], F = state[5],
                              G = state[6], H = state[7];

                    word_type W00 = block[0];
                    word_type W01 = block[1];
                    word_type W02 = block[2];
                    word_type W03 = block[3];
                    word_type W04 = block[4];
                    word_type W05 = block[5];
                    word_type W06 = block[6];
                    word_type W07 = block[7];
                    word_type W08 = block[8];
                    word_type W09 = block[9];
                    word_type W10 = block[10];
                    word_type W11 = block[11];
                    word_type W12 = block[12];
                    word_type W13 = block[13];
                    word_type W14 = block[14];
                    word_type W15 = block[15];

                    policy_type::r1(A, B, C, D, E, F, G, H, 0x79CC4519, W00, W00 ^ W04);
                    W00 = policy_type::sm3_e(W00, W07, W13, W03, W10);
                    policy_type::r1(D, A, B, C, H, E, F, G, 0xF3988A32, W01, W01 ^ W05);
                    W01 = policy_type::sm3_e(W01, W08, W14, W04, W11);
                    policy_type::r1(C, D, A, B, G, H, E, F, 0xE7311465, W02, W02 ^ W06);
                    W02 = policy_type::sm3_e(W02, W09, W15, W05, W12);
                    policy_type::r1(B, C, D, A, F, G, H, E, 0xCE6228CB, W03, W03 ^ W07);
                    W03 = policy_type::sm3_e(W03, W10, W00, W06, W13);
                    policy_type::r1(A, B, C, D, E, F, G, H, 0x9CC45197, W04, W04 ^ W08);
                    W04 = policy_type::sm3_e(W04, W11, W01, W07, W14);
                    policy_type::r1(D, A, B, C, H, E, F, G, 0x3988A32F, W05, W05 ^ W09);
                    W05 = policy_type::sm3_e(W05, W12, W02, W08, W15);
                    policy_type::r1(C, D, A, B, G, H, E, F, 0x7311465E, W06, W06 ^ W10);
                    W06 = policy_type::sm3_e(W06, W13, W03, W09, W00);
                    policy_type::r1(B, C, D, A, F, G, H, E, 0xE6228CBC, W07, W07 ^ W11);
                    W07 = policy_type::sm3_e(W07, W14, W04, W10, W01);
                    policy_type::r1(A, B, C, D, E, F, G, H, 0xCC451979, W08, W08 ^ W12);
                    W08 = policy_type::sm3_e(W08, W15, W05, W11, W02);
                    policy_type::r1(D, A, B, C, H, E, F, G, 0x988A32F3, W09, W09 ^ W13);
                    W09 = policy_type::sm3_e(W09, W00, W06, W12, W03);
                    policy_type::r1(C, D, A, B, G, H, E, F, 0x311465E7, W10, W10 ^ W14);
                    W10 = policy_type::sm3_e(W10, W01, W07, W13, W04);
                    policy_type::r1(B, C, D, A, F, G, H, E, 0x6228CBCE, W11, W11 ^ W15);
                    W11 = policy_type::sm3_e(W11, W02, W08, W14, W05);
                    policy_type::r1(A, B, C, D, E, F, G, H, 0xC451979C, W12, W12 ^ W00);
                    W12 = policy_type::sm3_e(W12, W03, W09, W15, W06);
                    policy_type::r1(D, A, B, C, H, E, F, G, 0x88A32F39, W13, W13 ^ W01);
                    W13 = policy_type::sm3_e(W13, W04, W10, W00, W07);
                    policy_type::r1(C, D, A, B, G, H, E, F, 0x11465E73, W14, W14 ^ W02);
                    W14 = policy_type::sm3_e(W14, W05, W11, W01, W08);
                    policy_type::r1(B, C, D, A, F, G, H, E, 0x228CBCE6, W15, W15 ^ W03);
                    W15 = policy_type::sm3_e(W15, W06, W12, W02, W09);
                    policy_type::r2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W00, W00 ^ W04);
                    W00 = policy_type::sm3_e(W00, W07, W13, W03, W10);
                    policy_type::r2(D, A, B, C, H, E, F, G, 0x3B14F50F, W01, W01 ^ W05);
                    W01 = policy_type::sm3_e(W01, W08, W14, W04, W11);
                    policy_type::r2(C, D, A, B, G, H, E, F, 0x7629EA1E, W02, W02 ^ W06);
                    W02 = policy_type::sm3_e(W02, W09, W15, W05, W12);
                    policy_type::r2(B, C, D, A, F, G, H, E, 0xEC53D43C, W03, W03 ^ W07);
                    W03 = policy_type::sm3_e(W03, W10, W00, W06, W13);
                    policy_type::r2(A, B, C, D, E, F, G, H, 0xD8A7A879, W04, W04 ^ W08);
                    W04 = policy_type::sm3_e(W04, W11, W01, W07, W14);
                    policy_type::r2(D, A, B, C, H, E, F, G, 0xB14F50F3, W05, W05 ^ W09);
                    W05 = policy_type::sm3_e(W05, W12, W02, W08, W15);
                    policy_type::r2(C, D, A, B, G, H, E, F, 0x629EA1E7, W06, W06 ^ W10);
                    W06 = policy_type::sm3_e(W06, W13, W03, W09, W00);
                    policy_type::r2(B, C, D, A, F, G, H, E, 0xC53D43CE, W07, W07 ^ W11);
                    W07 = policy_type::sm3_e(W07, W14, W04, W10, W01);
                    policy_type::r2(A, B, C, D, E, F, G, H, 0x8A7A879D, W08, W08 ^ W12);
                    W08 = policy_type::sm3_e(W08, W15, W05, W11, W02);
                    policy_type::r2(D, A, B, C, H, E, F, G, 0x14F50F3B, W09, W09 ^ W13);
                    W09 = policy_type::sm3_e(W09, W00, W06, W12, W03);
                    policy_type::r2(C, D, A, B, G, H, E, F, 0x29EA1E76, W10, W10 ^ W14);
                    W10 = policy_type::sm3_e(W10, W01, W07, W13, W04);
                    policy_type::r2(B, C, D, A, F, G, H, E, 0x53D43CEC, W11, W11 ^ W15);
                    W11 = policy_type::sm3_e(W11, W02, W08, W14, W05);
                    policy_type::r2(A, B, C, D, E, F, G, H, 0xA7A879D8, W12, W12 ^ W00);
                    W12 = policy_type::sm3_e(W12, W03, W09, W15, W06);
                    policy_type::r2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W13, W13 ^ W01);
                    W13 = policy_type::sm3_e(W13, W04, W10, W00, W07);
                    policy_type::r2(C, D, A, B, G, H, E, F, 0x9EA1E762, W14, W14 ^ W02);
                    W14 = policy_type::sm3_e(W14, W05, W11, W01, W08);
                    policy_type::r2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W15, W15 ^ W03);
                    W15 = policy_type::sm3_e(W15, W06, W12, W02, W09);
                    policy_type::r2(A, B, C, D, E, F, G, H, 0x7A879D8A, W00, W00 ^ W04);
                    W00 = policy_type::sm3_e(W00, W07, W13, W03, W10);
                    policy_type::r2(D, A, B, C, H, E, F, G, 0xF50F3B14, W01, W01 ^ W05);
                    W01 = policy_type::sm3_e(W01, W08, W14, W04, W11);
                    policy_type::r2(C, D, A, B, G, H, E, F, 0xEA1E7629, W02, W02 ^ W06);
                    W02 = policy_type::sm3_e(W02, W09, W15, W05, W12);
                    policy_type::r2(B, C, D, A, F, G, H, E, 0xD43CEC53, W03, W03 ^ W07);
                    W03 = policy_type::sm3_e(W03, W10, W00, W06, W13);
                    policy_type::r2(A, B, C, D, E, F, G, H, 0xA879D8A7, W04, W04 ^ W08);
                    W04 = policy_type::sm3_e(W04, W11, W01, W07, W14);
                    policy_type::r2(D, A, B, C, H, E, F, G, 0x50F3B14F, W05, W05 ^ W09);
                    W05 = policy_type::sm3_e(W05, W12, W02, W08, W15);
                    policy_type::r2(C, D, A, B, G, H, E, F, 0xA1E7629E, W06, W06 ^ W10);
                    W06 = policy_type::sm3_e(W06, W13, W03, W09, W00);
                    policy_type::r2(B, C, D, A, F, G, H, E, 0x43CEC53D, W07, W07 ^ W11);
                    W07 = policy_type::sm3_e(W07, W14, W04, W10, W01);
                    policy_type::r2(A, B, C, D, E, F, G, H, 0x879D8A7A, W08, W08 ^ W12);
                    W08 = policy_type::sm3_e(W08, W15, W05, W11, W02);
                    policy_type::r2(D, A, B, C, H, E, F, G, 0x0F3B14F5, W09, W09 ^ W13);
                    W09 = policy_type::sm3_e(W09, W00, W06, W12, W03);
                    policy_type::r2(C, D, A, B, G, H, E, F, 0x1E7629EA, W10, W10 ^ W14);
                    W10 = policy_type::sm3_e(W10, W01, W07, W13, W04);
                    policy_type::r2(B, C, D, A, F, G, H, E, 0x3CEC53D4, W11, W11 ^ W15);
                    W11 = policy_type::sm3_e(W11, W02, W08, W14, W05);
                    policy_type::r2(A, B, C, D, E, F, G, H, 0x79D8A7A8, W12, W12 ^ W00);
                    W12 = policy_type::sm3_e(W12, W03, W09, W15, W06);
                    policy_type::r2(D, A, B, C, H, E, F, G, 0xF3B14F50, W13, W13 ^ W01);
                    W13 = policy_type::sm3_e(W13, W04, W10, W00, W07);
                    policy_type::r2(C, D, A, B, G, H, E, F, 0xE7629EA1, W14, W14 ^ W02);
                    W14 = policy_type::sm3_e(W14, W05, W11, W01, W08);
                    policy_type::r2(B, C, D, A, F, G, H, E, 0xCEC53D43, W15, W15 ^ W03);
                    W15 = policy_type::sm3_e(W15, W06, W12, W02, W09);
                    policy_type::r2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W00, W00 ^ W04);
                    W00 = policy_type::sm3_e(W00, W07, W13, W03, W10);
                    policy_type::r2(D, A, B, C, H, E, F, G, 0x3B14F50F, W01, W01 ^ W05);
                    W01 = policy_type::sm3_e(W01, W08, W14, W04, W11);
                    policy_type::r2(C, D, A, B, G, H, E, F, 0x7629EA1E, W02, W02 ^ W06);
                    W02 = policy_type::sm3_e(W02, W09, W15, W05, W12);
                    policy_type::r2(B, C, D, A, F, G, H, E, 0xEC53D43C, W03, W03 ^ W07);
                    W03 = policy_type::sm3_e(W03, W10, W00, W06, W13);

                    policy_type::r2(A, B, C, D, E, F, G, H, 0xD8A7A879, W04, W04 ^ W08);
                    policy_type::r2(D, A, B, C, H, E, F, G, 0xB14F50F3, W05, W05 ^ W09);
                    policy_type::r2(C, D, A, B, G, H, E, F, 0x629EA1E7, W06, W06 ^ W10);
                    policy_type::r2(B, C, D, A, F, G, H, E, 0xC53D43CE, W07, W07 ^ W11);
                    policy_type::r2(A, B, C, D, E, F, G, H, 0x8A7A879D, W08, W08 ^ W12);
                    policy_type::r2(D, A, B, C, H, E, F, G, 0x14F50F3B, W09, W09 ^ W13);
                    policy_type::r2(C, D, A, B, G, H, E, F, 0x29EA1E76, W10, W10 ^ W14);
                    policy_type::r2(B, C, D, A, F, G, H, E, 0x53D43CEC, W11, W11 ^ W15);
                    policy_type::r2(A, B, C, D, E, F, G, H, 0xA7A879D8, W12, W12 ^ W00);
                    policy_type::r2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W13, W13 ^ W01);
                    policy_type::r2(C, D, A, B, G, H, E, F, 0x9EA1E762, W14, W14 ^ W02);
                    policy_type::r2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W15, W15 ^ W03);

                    state[0] ^= A;
                    state[1] ^= B;
                    state[2] ^= C;
                    state[3] ^= D;
                    state[4] ^= E;
                    state[5] ^= F;
                    state[6] ^= G;
                    state[7] ^= H;
                }
            };

            class sm3 {
                typedef detail::sm3_policy policy_type;

            public:
                typedef merkle_damgard_construction<stream_endian::little_octet_big_bit, policy_type::digest_bits,
                                                    typename policy_type::iv_generator, sm3_compressor>
                    construction_type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                typedef construction_type_ construction_type;
#else
                struct construction_type : construction_type_ {};
#endif
                template<typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {
                        typedef typename stream_endian::little_octet_big_bit endian;

                        constexpr static const std::size_t value_bits = ValueBits;
                        constexpr static const std::size_t length_bits = 0;
                    };

                    typedef merkle_damgard_stream_processor<construction_type, StateAccumulator, params_type> type;
                };

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename construction_type::digest_type digest_type;
            };
        }    // namespace hash
    }        // namespace crypto3
}    // namespace nil

#endif
