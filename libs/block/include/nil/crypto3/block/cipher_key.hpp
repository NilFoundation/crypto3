//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_BLOCK_CIPHER_KEY_HPP
#define CRYPTO3_BLOCK_CIPHER_KEY_HPP

#include <boost/accumulators/framework/accumulator_set.hpp>
#include <boost/accumulators/framework/features.hpp>

#include <nil/crypto3/block/accumulators/block.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            template<typename BlockCipher>
            struct cipher_key {
                typedef BlockCipher cipher_type;

                typedef typename cipher_type::endian_type endian_type;

                constexpr static const std::size_t key_bits = cipher_type::key_bits;
                constexpr static const std::size_t key_value_bits =
                    sizeof(typename cipher_type::key_type::value_type) * CHAR_BIT;
                typedef typename cipher_type::key_type key_type;

                template<typename SinglePassRange>
                explicit cipher_key(const SinglePassRange &r) {
                    using namespace nil::crypto3::detail;

                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                    typedef typename std::iterator_traits<typename SinglePassRange::iterator>::value_type value_type;

                    BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                    constexpr static const std::size_t value_bits =
                        std::numeric_limits<value_type>::digits + std::numeric_limits<value_type>::is_signed;

                    pack_to<endian_type, value_bits, key_value_bits>(r.begin(), r.end(), key.begin());
                }

                template<typename InputIterator>
                explicit cipher_key(InputIterator first, InputIterator last) {
                    using namespace nil::crypto3::detail;

                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                    typedef typename std::iterator_traits<InputIterator>::value_type value_type;

                    BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                    constexpr static const std::size_t value_bits =
                        std::numeric_limits<value_type>::digits + std::numeric_limits<value_type>::is_signed;

                    pack_to<endian_type, value_bits, key_value_bits>(first, last, key.begin());
                }

                key_type key;
            };
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_CIPHER_KEY_HPP
