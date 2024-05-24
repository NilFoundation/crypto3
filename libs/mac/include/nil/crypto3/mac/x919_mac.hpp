//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ANSI_X919_MAC_HPP
#define CRYPTO3_ANSI_X919_MAC_HPP

#include <nil/crypto3/block/des.hpp>

#include <nil/crypto3/mac/detail/x919_mac/x919_mac_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            /*!
             * @brief DES/3DES-based MAC from ANSI X9.19
             * @tparam BlockCipher
             * @ingroup mac
             */
            template<typename BlockCipher = block::des>
            class ansi_x919_mac {
                typedef detail::x919_mac_policy<BlockCipher> policy_type;

            public:
                typedef BlockCipher cipher_type;

                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t key_words = policy_type::key_words;
                constexpr static const std::size_t key_bits = policy_type::key_bits;
                typedef typename policy_type::key_type key_type;

                constexpr static const std::size_t key_schedule_bits = policy_type::key_schedule_bits;
                constexpr static const std::size_t key_schedule_words = policy_type::key_schedule_words;
                typedef typename policy_type::key_schedule_type key_schedule_type;

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename policy_type::digest_type digest_type;

                ansi_x919_mac(const key_type &key) :
                    c1(key.size() == key_words ? key : make_array(key.begin(), key.begin() + key_words)),
                    c2(key.size() == key_words ? key : make_array(key.begin() + key_words, key.end())) {
                }

                ansi_x919_mac(const cipher_type &c_1, const cipher_type &c_2) : c1(c_1), c2(c_2) {
                }

                void process(digest_type &state, const block_type &block) {
                    size_t xored = std::min(8 - m_position, length);
                    xor_buf(&state[m_position], input, xored);
                    m_position += xored;

                    if (m_position < 8) {
                        return;
                    }

                    c1.encrypt_block(state);
                    input += xored;
                    length -= xored;
                    while (length >= 8) {
                        xor_buf(state, input, 8);
                        c1.encrypt_block(state);
                        input += 8;
                        length -= 8;
                    }

                    xor_buf(state, input, length);
                    m_position = length;
                }

                void end_message(digest_type &state, const block_type &block) {
                    if (m_position) {
                        c1.encrypt_block(state);
                    }
                    c2.decrypt_block(state.data(), mac);
                    c1.encrypt_block(mac);
                    zeroise(state);
                    m_position = 0;
                }

            protected:
                cipher_type c1, c2;
            };
        }    // namespace mac
    }        // namespace crypto3
}    // namespace nil

#endif
