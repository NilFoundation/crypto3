//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_MAC_HMAC_HPP
#define CRYPTO3_MAC_HMAC_HPP

#include <array>

#include <nil/crypto3/detail/strxor.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/mac/mac_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            /*!
             * @brief
             * @tparam Hash
             * @ingroup mac
             */
            template<typename Hash>
            struct hmac {
                typedef Hash hash_type;

                constexpr static const std::size_t block_bits = hash_type::block_bits;
                constexpr static const std::size_t block_words = hash_type::block_words;
                constexpr static const std::size_t block_octets = block_bits / 8;
                typedef typename hash_type::block_type block_type;

                constexpr static const std::size_t digest_bits = hash_type::digest_bits;
                typedef typename hash_type::digest_type digest_type;

                template<typename InputRange,
                         typename ValueType = typename std::iterator_traits<typename InputRange::iterator>::value_type>
                using is_key_type = typename std::enable_if<std::is_same<std::uint8_t, ValueType>::value, bool>::type;

                /*!
                 * std::pair<i_key_pad, o_key_pad>
                 */
                typedef std::pair<std::array<std::uint8_t, block_octets>, std::array<std::uint8_t, block_octets>>
                    schedule_key_type;
            };

            template<typename Hash>
            struct mac_key<hmac<Hash>> {
                typedef hmac<Hash> policy_type;

                typedef typename policy_type::hash_type hash_type;
                typedef typename policy_type::digest_type digest_type;
                typedef typename policy_type::schedule_key_type schedule_key_type;

                typedef accumulator_set<hash_type> internal_accumulator_type;

                constexpr static const std::size_t block_octets = policy_type::block_octets;

                template<typename KeyRange>
                mac_key(const KeyRange &key) : schedule_key(process_schedule_key(key)) {
                }

                inline void init_accumulator(internal_accumulator_type &i_acc) const {
                    hash<hash_type>(schedule_key.first, i_acc);
                }

                template<typename InputRange>
                inline void update(internal_accumulator_type &i_acc, InputRange range) const {
                    hash<hash_type>(range, i_acc);
                }

                template<typename InputIterator>
                inline void update(internal_accumulator_type &i_acc, InputIterator first, InputIterator last) const {
                    hash<hash_type>(first, last, i_acc);
                }

                inline digest_type compute(internal_accumulator_type &i_acc) const {
                    digest_type i_digest = ::nil::crypto3::accumulators::extract::hash<hash_type>(i_acc);

                    internal_accumulator_type o_acc;
                    hash<hash_type>(schedule_key.second, o_acc);
                    hash<hash_type>(i_digest, o_acc);
                    return ::nil::crypto3::accumulators::extract::hash<hash_type>(o_acc);
                }

            protected:
                template<typename KeyRange, typename policy_type::template is_key_type<KeyRange> = true>
                inline static schedule_key_type process_schedule_key(const KeyRange &key) {
                    constexpr std::uint8_t ipad = 0x36;
                    constexpr std::uint8_t opad = 0x5C;

                    schedule_key_type schedule_key;
                    std::fill(schedule_key.first.begin(), schedule_key.first.end(), ipad);
                    std::fill(schedule_key.second.begin(), schedule_key.second.end(), opad);

                    if (key.size() > block_octets) {
                        digest_type hashed_key = hash<hash_type>(key);
                        ::nil::crypto3::detail::strxor(
                            hashed_key.cbegin(), hashed_key.cend(), schedule_key.first.cbegin(),
                            schedule_key.first.cbegin() + hashed_key.size(), schedule_key.first.begin());
                        ::nil::crypto3::detail::strxor(
                            hashed_key.cbegin(), hashed_key.cend(), schedule_key.second.cbegin(),
                            schedule_key.second.cbegin() + hashed_key.size(), schedule_key.second.begin());
                    } else {
                        ::nil::crypto3::detail::strxor(key.cbegin(), key.cend(), schedule_key.first.cbegin(),
                                                       schedule_key.first.cbegin() + key.size(),
                                                       schedule_key.first.begin());
                        ::nil::crypto3::detail::strxor(key.cbegin(), key.cend(), schedule_key.second.cbegin(),
                                                       schedule_key.second.cbegin() + key.size(),
                                                       schedule_key.second.begin());
                    }

                    return schedule_key;
                }

                schedule_key_type schedule_key;
            };
        }    // namespace mac
    }        // namespace crypto3
}    // namespace nil

#endif