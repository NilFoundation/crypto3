//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_STREAM_CTR_FUNCTIONS_HPP
#define CRYPTO3_STREAM_CTR_FUNCTIONS_HPP

#include <nil/crypto3/stream/detail/ctr/ctr_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace stream {
            namespace detail {
                template<typename BlockCipher, std::size_t CtrBits>
                struct ctr_functions : public ctr_policy<BlockCipher, CtrBits> {
                    typedef ctr_policy<BlockCipher, CtrBits> policy_type;

                    typedef typename policy_type::cipher_type cipher_type;

                    constexpr static const std::size_t rounds = policy_type::rounds;

                    constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                    constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                    constexpr static const std::size_t key_bits = policy_type::key_bits;
                    typedef typename policy_type::key_type key_type;

                    constexpr static const std::size_t iv_bits = policy_type::iv_bits;
                    typedef typename policy_type::iv_type iv_type;

                    static void add_counter(const uint64_t counter) {
                        const size_t ctr_size = m_ctr_size;
                        const size_t ctr_blocks = m_ctr_blocks;
                        const size_t BS = m_block_size;

                        if (ctr_size == 4) {
                            const size_t off = (BS - 4);
                            const uint32_t low32 =
                                static_cast<uint32_t>(counter + load_be<uint32_t>(&m_counter[off], 0));

                            for (size_t i = 0; i != ctr_blocks; ++i) {
                                store_be(uint32_t(low32 + i), &m_counter[i * BS + off]);
                            }
                        } else if (ctr_size == 8) {
                            const size_t off = (BS - 8);
                            const uint64_t low64 = counter + load_be<uint64_t>(&m_counter[off], 0);

                            for (size_t i = 0; i != ctr_blocks; ++i) {
                                store_be(uint64_t(low64 + i), &m_counter[i * BS + off]);
                            }
                        } else if (ctr_size == 16) {
                            const size_t off = (BS - 16);
                            uint64_t b0 = load_be<uint64_t>(&m_counter[off], 0);
                            uint64_t b1 = load_be<uint64_t>(&m_counter[off], 1);
                            b1 += counter;
                            b0 += (b1 < counter) ? 1 : 0;    // carry

                            for (size_t i = 0; i != ctr_blocks; ++i) {
                                store_be(b0, &m_counter[i * BS + off]);
                                store_be(b1, &m_counter[i * BS + off + 8]);
                                b1 += 1;
                                b0 += (b1 == 0);    // carry
                            }
                        } else {
                            for (size_t i = 0; i != ctr_blocks; ++i) {
                                uint64_t local_counter = counter;
                                uint16_t carry = static_cast<uint8_t>(local_counter);
                                for (size_t j = 0; (carry || local_counter) && j != ctr_size; ++j) {
                                    const size_t off = i * BS + (BS - 1 - j);
                                    const uint16_t cnt = static_cast<uint16_t>(m_counter[off]) + carry;
                                    m_counter[off] = static_cast<uint8_t>(cnt);
                                    local_counter = (local_counter >> 8);
                                    carry = (cnt >> 8) + static_cast<uint8_t>(local_counter);
                                }
                            }
                        }
                    }
                };
            }    // namespace detail
        }        // namespace stream
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CTR_FUNCTIONS_HPP
