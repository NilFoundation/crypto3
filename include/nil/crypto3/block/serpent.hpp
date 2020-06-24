//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_SERPENT_HPP
#define CRYPTO3_BLOCK_SERPENT_HPP

#include <boost/endian/arithmetic.hpp>
#include <boost/endian/conversion.hpp>

#include <nil/crypto3/block/detail/serpent/serpent_policy.hpp>

#include <nil/crypto3/block/detail/block_stream_processor.hpp>
#include <nil/crypto3/block/detail/cipher_modes.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief Serpent. The most conservative of the AES finalists
             * https://www.cl.cam.ac.uk/~rja14/serpent.html. An AES contender.
             * Widely considered the most conservative design. Fairly slow,
             * especially if no SIMD instruction set is available.
             *
             * @ingroup block
             * @tparam KeyBits Block cipher key bits. Available values are: 128, 192, 256
             */
            template<std::size_t KeyBits>
            class serpent {
            protected:
                typedef detail::serpent_policy<KeyBits> policy_type;

                constexpr static const std::size_t key_schedule_size = policy_type::key_schedule_size;
                typedef typename policy_type::key_schedule_type key_schedule_type;

            public:
                constexpr static const std::size_t rounds = policy_type::rounds;

                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t key_bits = policy_type::key_bits;
                constexpr static const std::size_t key_words = policy_type::key_words;
                typedef typename policy_type::key_type key_type;

                serpent(const key_type &key) {
                    schedule_key(key);
                }

                ~serpent() {
                    key_schedule.fill(0);
                }

                inline block_type encrypt(const block_type &plaintext) const {
                    return encrypt_block(plaintext);
                }

                inline block_type decrypt(const block_type &ciphertext) const {
                    return decrypt_block(ciphertext);
                }

                template<class Mode, typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {

                        constexpr static const std::size_t value_bits = ValueBits;
                        constexpr static const std::size_t length_bits = policy_type::word_bits * 2;
                    };

                    typedef block_stream_processor<Mode, StateAccumulator, params_type> type;
                };

                typedef typename stream_endian::little_octet_big_bit endian_type;
            protected:
                key_schedule_type key_schedule;

                inline block_type encrypt_block(const block_type &plaintext) const {
                    word_type B0 = boost::endian::native_to_little(plaintext[0]);
                    word_type B1 = boost::endian::native_to_little(plaintext[1]);
                    word_type B2 = boost::endian::native_to_little(plaintext[2]);
                    word_type B3 = boost::endian::native_to_little(plaintext[3]);

                    key_xor(0, B0, B1, B2, B3);
                    SBoxE1(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(1, B0, B1, B2, B3);
                    SBoxE2(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(2, B0, B1, B2, B3);
                    SBoxE3(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(3, B0, B1, B2, B3);
                    SBoxE4(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(4, B0, B1, B2, B3);
                    SBoxE5(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(5, B0, B1, B2, B3);
                    SBoxE6(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(6, B0, B1, B2, B3);
                    SBoxE7(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(7, B0, B1, B2, B3);
                    SBoxE8(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(8, B0, B1, B2, B3);
                    SBoxE1(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(9, B0, B1, B2, B3);
                    SBoxE2(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(10, B0, B1, B2, B3);
                    SBoxE3(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(11, B0, B1, B2, B3);
                    SBoxE4(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(12, B0, B1, B2, B3);
                    SBoxE5(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(13, B0, B1, B2, B3);
                    SBoxE6(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(14, B0, B1, B2, B3);
                    SBoxE7(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(15, B0, B1, B2, B3);
                    SBoxE8(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(16, B0, B1, B2, B3);
                    SBoxE1(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(17, B0, B1, B2, B3);
                    SBoxE2(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(18, B0, B1, B2, B3);
                    SBoxE3(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(19, B0, B1, B2, B3);
                    SBoxE4(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(20, B0, B1, B2, B3);
                    SBoxE5(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(21, B0, B1, B2, B3);
                    SBoxE6(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(22, B0, B1, B2, B3);
                    SBoxE7(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(23, B0, B1, B2, B3);
                    SBoxE8(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(24, B0, B1, B2, B3);
                    SBoxE1(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(25, B0, B1, B2, B3);
                    SBoxE2(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(26, B0, B1, B2, B3);
                    SBoxE3(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(27, B0, B1, B2, B3);
                    SBoxE4(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(28, B0, B1, B2, B3);
                    SBoxE5(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(29, B0, B1, B2, B3);
                    SBoxE6(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(30, B0, B1, B2, B3);
                    SBoxE7(B0, B1, B2, B3);
                    policy_type::transform(B0, B1, B2, B3);
                    key_xor(31, B0, B1, B2, B3);
                    SBoxE8(B0, B1, B2, B3);
                    key_xor(32, B0, B1, B2, B3);

                    return {boost::endian::little_to_native(B0), boost::endian::little_to_native(B1),
                            boost::endian::little_to_native(B2), boost::endian::little_to_native(B3)};
                }

                inline block_type decrypt_block(const block_type &ciphertext) const {
                    word_type B0 = ciphertext[0];
                    word_type B1 = ciphertext[1];
                    word_type B2 = ciphertext[2];
                    word_type B3 = ciphertext[3];

                    key_xor(32, B0, B1, B2, B3);
                    SBoxD8(B0, B1, B2, B3);
                    key_xor(31, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD7(B0, B1, B2, B3);
                    key_xor(30, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD6(B0, B1, B2, B3);
                    key_xor(29, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD5(B0, B1, B2, B3);
                    key_xor(28, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD4(B0, B1, B2, B3);
                    key_xor(27, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD3(B0, B1, B2, B3);
                    key_xor(26, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD2(B0, B1, B2, B3);
                    key_xor(25, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD1(B0, B1, B2, B3);
                    key_xor(24, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD8(B0, B1, B2, B3);
                    key_xor(23, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD7(B0, B1, B2, B3);
                    key_xor(22, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD6(B0, B1, B2, B3);
                    key_xor(21, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD5(B0, B1, B2, B3);
                    key_xor(20, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD4(B0, B1, B2, B3);
                    key_xor(19, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD3(B0, B1, B2, B3);
                    key_xor(18, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD2(B0, B1, B2, B3);
                    key_xor(17, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD1(B0, B1, B2, B3);
                    key_xor(16, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD8(B0, B1, B2, B3);
                    key_xor(15, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD7(B0, B1, B2, B3);
                    key_xor(14, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD6(B0, B1, B2, B3);
                    key_xor(13, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD5(B0, B1, B2, B3);
                    key_xor(12, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD4(B0, B1, B2, B3);
                    key_xor(11, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD3(B0, B1, B2, B3);
                    key_xor(10, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD2(B0, B1, B2, B3);
                    key_xor(9, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD1(B0, B1, B2, B3);
                    key_xor(8, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD8(B0, B1, B2, B3);
                    key_xor(7, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD7(B0, B1, B2, B3);
                    key_xor(6, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD6(B0, B1, B2, B3);
                    key_xor(5, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD5(B0, B1, B2, B3);
                    key_xor(4, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD4(B0, B1, B2, B3);
                    key_xor(3, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD3(B0, B1, B2, B3);
                    key_xor(2, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD2(B0, B1, B2, B3);
                    key_xor(1, B0, B1, B2, B3);
                    policy_type::i_transform(B0, B1, B2, B3);
                    SBoxD1(B0, B1, B2, B3);
                    key_xor(0, B0, B1, B2, B3);

                    return {boost::endian::little_to_native(B0), boost::endian::little_to_native(B1),
                            boost::endian::little_to_native(B2), boost::endian::little_to_native(B3)};
                }

                void schedule_key(const key_type &key) {
                    std::array<word_type, 140> W = {0};
                    for (size_t i = 0; i != key.size() / 4; ++i) {
                        W[i] = boost::endian::native_to_little(key[i]);
                    }

                    W[key.size() / 4] |= word_type(1) << ((key.size() % 4) * 8);

                    for (size_t i = 8; i != 140; ++i) {
                        word_type wi = W[i - 8] ^ W[i - 5] ^ W[i - 3] ^ W[i - 1] ^ policy_type::phi ^ word_type(i - 8);
                        W[i] = policy_type::template rotl<11>(wi);
                    }

                    SBoxE1(W[20], W[21], W[22], W[23]);
                    SBoxE1(W[52], W[53], W[54], W[55]);
                    SBoxE1(W[84], W[85], W[86], W[87]);
                    SBoxE1(W[116], W[117], W[118], W[119]);

                    SBoxE2(W[16], W[17], W[18], W[19]);
                    SBoxE2(W[48], W[49], W[50], W[51]);
                    SBoxE2(W[80], W[81], W[82], W[83]);
                    SBoxE2(W[112], W[113], W[114], W[115]);

                    SBoxE3(W[12], W[13], W[14], W[15]);
                    SBoxE3(W[44], W[45], W[46], W[47]);
                    SBoxE3(W[76], W[77], W[78], W[79]);
                    SBoxE3(W[108], W[109], W[110], W[111]);

                    SBoxE4(W[8], W[9], W[10], W[11]);
                    SBoxE4(W[40], W[41], W[42], W[43]);
                    SBoxE4(W[72], W[73], W[74], W[75]);
                    SBoxE4(W[104], W[105], W[106], W[107]);
                    SBoxE4(W[136], W[137], W[138], W[139]);

                    SBoxE5(W[36], W[37], W[38], W[39]);
                    SBoxE5(W[68], W[69], W[70], W[71]);
                    SBoxE5(W[100], W[101], W[102], W[103]);
                    SBoxE5(W[132], W[133], W[134], W[135]);

                    SBoxE6(W[32], W[33], W[34], W[35]);
                    SBoxE6(W[64], W[65], W[66], W[67]);
                    SBoxE6(W[96], W[97], W[98], W[99]);
                    SBoxE6(W[128], W[129], W[130], W[131]);

                    SBoxE7(W[28], W[29], W[30], W[31]);
                    SBoxE7(W[60], W[61], W[62], W[63]);
                    SBoxE7(W[92], W[93], W[94], W[95]);
                    SBoxE7(W[124], W[125], W[126], W[127]);

                    SBoxE8(W[24], W[25], W[26], W[27]);
                    SBoxE8(W[56], W[57], W[58], W[59]);
                    SBoxE8(W[88], W[89], W[90], W[91]);
                    SBoxE8(W[120], W[121], W[122], W[123]);

                    key_schedule.assign(W.begin() + 8, W.end());

                    W.fill(0);
                }
            };
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil
#endif
