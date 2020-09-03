//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
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
                cipher_key(const SinglePassRange &r) {
                    using namespace nil::crypto3::detail;

                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                    typedef typename std::iterator_traits<typename SinglePassRange::iterator>::value_type value_type;

                    BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                    constexpr static const std::size_t value_bits =
                        std::numeric_limits<value_type>::digits + std::numeric_limits<value_type>::is_signed;

                    pack_to<endian_type, value_bits, key_value_bits>(r.begin(), r.end(), key.begin());
                }

                template<typename InputIterator>
                cipher_key(InputIterator first, InputIterator last) {
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
