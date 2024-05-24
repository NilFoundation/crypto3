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

#ifndef CRYPTO3_MAC_POLY1305_HPP
#define CRYPTO3_MAC_POLY1305_HPP

#include <memory>

#include <nil/crypto3/mac/detail/poly1305/poly1305_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            /*!
             * @brief DJB's Poly1305
             * @note Each key can only be used once
             * @ingroup mac
             */
            class poly_1305 {
                typedef detail::poly1305_functions policy_type;

            public:
                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t key_words = policy_type::key_words;
                constexpr static const std::size_t key_bits = policy_type::key_bits;
                typedef typename policy_type::key_type key_type;

                constexpr static const std::size_t key_schedule_bits = policy_type::key_schedule_bits;
                constexpr static const std::size_t key_schedule_words = policy_type::key_schedule_words;
                typedef typename policy_type::key_schedule_type key_schedule_type;

                poly_1305(const key_type &key) {
                    schedule_key(key);
                }

                void process_block(const block_type &block) {
                    if (m_buf_pos) {
                        buffer_insert(m_buf, m_buf_pos, input, length);

                        if (m_buf_pos + length >= m_buf.size()) {
                            poly1305_blocks(m_poly, m_buf.data(), 1);
                            input += (m_buf.size() - m_buf_pos);
                            length -= (m_buf.size() - m_buf_pos);
                            m_buf_pos = 0;
                        }
                    }

                    const size_t full_blocks = length / m_buf.size();
                    const size_t remaining = length % m_buf.size();

                    if (full_blocks) {
                        poly1305_blocks(m_poly, input, full_blocks);
                    }

                    buffer_insert(m_buf, m_buf_pos, input + full_blocks * m_buf.size(), remaining);
                    m_buf_pos += remaining;
                }

                void end_message(const block_type &block) {
                    if (m_buf_pos != 0) {
                        m_buf[m_buf_pos] = 1;
                        const size_t len = m_buf.size() - m_buf_pos - 1;
                        if (len > 0) {
                            clear_mem(&m_buf[m_buf_pos + 1], len);
                        }
                        poly1305_blocks(m_poly, m_buf.data(), 1, true);
                    }

                    poly1305_finish(m_poly, out);

                    m_poly.clear();
                    m_buf_pos = 0;
                }

            protected:
                inline void schedule_key(const key_type &key) {
                    policy_type::poly1305_init(schedule, key);
                }

                key_schedule_type schedule;
            };
        }    // namespace mac
    }        // namespace crypto3
}    // namespace nil

#endif