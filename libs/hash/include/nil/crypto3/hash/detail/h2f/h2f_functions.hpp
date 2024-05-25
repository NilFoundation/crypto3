//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_HASH_DETAIL_H2F_FUNCTIONS_HPP
#define CRYPTO3_HASH_DETAIL_H2F_FUNCTIONS_HPP

#include <cstdint>
#include <array>
#include <vector>
#include <iterator>
#include <type_traits>

#include <boost/assert.hpp>
#include <boost/static_assert.hpp>
#include <boost/concept/assert.hpp>

#include <nil/marshalling/endianness.hpp>
#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/crypto3/marshalling/multiprecision/types/integral.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/detail/strxor.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/hash/detail/h2c/h2c_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<std::size_t k, std::size_t len_in_bytes, typename Hash,
                         /// Hash::digest_type is required to be uint8_t[]
                         typename = typename std::enable_if<std::is_same<
                             std::uint8_t,
                             typename std::iterator_traits<typename Hash::digest_type>::value_type>::value>::type>
                class expand_message_xmd {
                    // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-5.4.1
                    static_assert(Hash::block_bits % 8 == 0, "r_in_bytes is not a multiple of 8");
                    static_assert(Hash::digest_bits % 8 == 0, "b_in_bytes is not a multiple of 8");
                    static_assert(Hash::digest_bits >= 2 * k, "k-bit collision resistance is not fulfilled");
                    static_assert(len_in_bytes < 0x10000, "len_in_bytes should be less than 0x10000");

                    constexpr static std::size_t b_in_bytes = Hash::digest_bits / 8;
                    constexpr static std::size_t r_in_bytes = Hash::block_bits / 8;
                    constexpr static std::array<std::uint8_t, 2> l_i_b_str = {
                        static_cast<std::uint8_t>(len_in_bytes >> 8u), static_cast<std::uint8_t>(len_in_bytes % 0x100)};
                    constexpr static std::size_t ell = static_cast<std::size_t>(len_in_bytes / b_in_bytes) +
                                                       static_cast<std::size_t>(len_in_bytes % b_in_bytes != 0);
                    constexpr static const std::array<std::uint8_t, r_in_bytes> Z_pad {0};

                    // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-5.4.1
                    static_assert(ell <= 255, "ell should be less than 256");

                public:
                    typedef std::array<std::uint8_t, len_in_bytes> result_type;
                    typedef accumulator_set<Hash> internal_accumulator_type;

                    static inline void init_accumulator(internal_accumulator_type &acc) {
                        hash<Hash>(Z_pad, acc);
                    }

                    template<typename InputRange>
                    static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                        BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<InputRange>));

                        hash<Hash>(range, acc);
                    }

                    template<typename InputIterator>
                    static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                        hash<Hash>(first, last, acc);
                    }

                    template<typename DstRange>
                    static inline typename std::enable_if<
                        std::is_same<std::uint8_t,
                                     typename std::iterator_traits<typename DstRange::iterator>::value_type>::value,
                        result_type>::type
                        process(internal_accumulator_type &b0_acc, const DstRange &dst) {

                        auto dst_size = std::distance(std::cbegin(dst), std::cend(dst));
                        assert(dst_size >= 16 && dst_size <= 255);

                        hash<Hash>(l_i_b_str, b0_acc);
                        hash<Hash>(std::array<std::uint8_t, 1> {0}, b0_acc);
                        hash<Hash>(dst, b0_acc);
                        hash<Hash>(std::array<std::uint8_t, 1> {static_cast<std::uint8_t>(dst_size)}, b0_acc);
                        typename Hash::digest_type b0 = ::nil::crypto3::accumulators::extract::hash<Hash>(b0_acc);

                        result_type uniform_bytes;
                        internal_accumulator_type bi_acc;
                        hash<Hash>(b0, bi_acc);
                        hash<Hash>(std::array<std::uint8_t, 1> {1}, bi_acc);
                        hash<Hash>(dst, bi_acc);
                        hash<Hash>(std::array<std::uint8_t, 1> {static_cast<std::uint8_t>(dst_size)}, bi_acc);
                        typename Hash::digest_type bi = ::nil::crypto3::accumulators::extract::hash<Hash>(bi_acc);
                        std::copy(bi.begin(), bi.end(), uniform_bytes.begin());

                        typename Hash::digest_type xored_b;
                        for (std::size_t i = 2; i <= ell; i++) {
                            internal_accumulator_type bi_acc;
                            ::nil::crypto3::detail::strxor(b0, bi, xored_b.begin());
                            hash<Hash>(xored_b, bi_acc);
                            hash<Hash>(std::array<std::uint8_t, 1> {static_cast<std::uint8_t>(i)}, bi_acc);
                            hash<Hash>(dst, bi_acc);
                            hash<Hash>(std::array<std::uint8_t, 1> {static_cast<std::uint8_t>(dst_size)}, bi_acc);
                            bi = ::nil::crypto3::accumulators::extract::hash<Hash>(bi_acc);
                            std::copy(bi.begin(), bi.end(), uniform_bytes.begin() + (i - 1) * b_in_bytes);
                        }
                        return uniform_bytes;
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_DETAIL_H2F_FUNCTIONS_HPP
