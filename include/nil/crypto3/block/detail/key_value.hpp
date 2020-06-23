//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_CIPHER_KEY_HPP
#define CRYPTO3_BLOCK_CIPHER_KEY_HPP

//#include <type_traits>
#include <iterator>

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>

#include <boost/range/concepts.hpp>

#include <nil/crypto3/detail/pack.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                
                template<typename Cipher, typename SinglePassRange>
                typename Cipher::key_type key_value(const SinglePassRange &range){

                    typedef Cipher policy_type;
                    typedef typename policy_type::key_type result_type;
                    typedef typename policy_type::endian_type endian_type;

                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                    typedef typename std::iterator_traits<typename SinglePassRange::iterator>::value_type value_type;
                    BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);


                    constexpr static std::size_t const value_bits = std::numeric_limits<value_type>::digits + 
                        std::numeric_limits<value_type>::is_signed;

                    constexpr static std::size_t const key_value_bits = sizeof(typename result_type::value_type) * CHAR_BIT; 

                    result_type key;

                    nil::crypto3::detail::pack_to<endian_type, value_bits, key_value_bits>(range.begin(), range.end(), key.begin());

                    return key;

                }

                template<typename Cipher, typename InputIterator>
                typename Cipher::key_type key_value(InputIterator first, InputIterator last){

                    typedef Cipher policy_type;
                    typedef typename policy_type::key_type result_type;
                    typedef typename policy_type::endian_type endian_type;

                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                    typedef typename std::iterator_traits<InputIterator>::value_type value_type;

                    constexpr static std::size_t const value_bits = std::numeric_limits<value_type>::digits + 
                        std::numeric_limits<value_type>::is_signed;

                    constexpr static std::size_t const key_value_bits = sizeof(typename result_type::value_type) * CHAR_BIT; 

                    result_type key;

                    nil::crypto3::detail::pack_to<endian_type, value_bits, key_value_bits>(first, last, key.begin());

                    return key;

                }

            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_CIPHER_KEY_HPP
