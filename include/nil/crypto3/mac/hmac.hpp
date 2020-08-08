//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MAC_HMAC_HPP
#define CRYPTO3_MAC_HMAC_HPP

#include <nil/crypto3/detail/pack.hpp>

#include <nil/crypto3/mac/detail/hmac/accumulator.hpp>
#include <nil/crypto3/mac/detail/hmac/hmac_policy.hpp>

#include <nil/crypto3/hash/hash_state.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            /*!
             * @brief
             * @tparam Hash
             * @ingroup mac
             */
            template<typename Hash>
            class hmac {
                typedef detail::hmac_policy<Hash> policy_type;

                typedef typename policy_type::byte_type byte_type;
                typedef typename policy_type::word_type word_type;

                typedef typename policy_type::construction_type construction_type;
                typedef typename construction_type::endian_type endian_type;

                constexpr static const std::size_t block_bytes = policy_type::block_bits / CHAR_BIT;

            public:
                typedef Hash hash_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t key_bits = policy_type::key_bits;
                constexpr static const std::size_t key_words = policy_type::key_words;
                typedef typename policy_type::key_type key_type;

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename policy_type::digest_type digest_type;

                hmac(const key_type &key) {
                    schedule_key(key);
                }

                virtual ~hmac() {
                    ikey.fill(0);
                    okey.fill(0);
                }

                void begin_message(const block_type &block) {
                    process_block(block);
                }

                void process_block(const block_type &block) {
                    m_hash->update(input, length);
                }

                void end_message(const block_type &block) {
                    verify_key_set(!m_okey.empty());
                    m_hash->final(mac);
                    m_hash->update(m_okey);
                    m_hash->update(mac, output_length());
                    m_hash->final(mac);
                    m_hash->update(m_ikey);
                }

            protected:
                void schedule_key(const key_type &key) {
                    m_hash->clear();

                    const uint8_t ipad = 0x36;
                    const uint8_t opad = 0x5C;

                    std::fill(ikey.begin(), ikey.end(), ipad);
                    std::fill(okey.begin(), okey.end(), opad);

                    if (length > m_hash->hash_block_size()) {
                        secure_vector<uint8_t> hmac_key = m_hash->process(key, length);
                        xor_buf(ikey, hmac_key, hmac_key.size());
                        xor_buf(okey, hmac_key, hmac_key.size());
                    } else {
                        xor_buf(ikey, key, length);
                        xor_buf(okey, key, length);
                    }

                    m_hash->update(m_ikey);
                }

            private:
                std::array<byte_type, block_bytes> ikey, okey;
            };
        }    // namespace mac
    }    // namespace crypto3
}    // namespace nil

#endif