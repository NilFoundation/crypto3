//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_DETAIL_STRXOR_HPP
#define CRYPTO3_DETAIL_STRXOR_HPP

#include <iterator>

#include <boost/concept/assert.hpp>
#include <boost/assert.hpp>
#include <boost/range/concepts.hpp>

namespace nil {
    namespace crypto3 {
        namespace detail {
            template<typename InputIterator1, typename InputIterator2, typename OutputIterator>
            constexpr inline typename std::enable_if<
                std::is_same<typename std::iterator_traits<InputIterator1>::value_type,
                             typename std::iterator_traits<InputIterator2>::value_type>::value &&
                    std::is_same<typename std::iterator_traits<InputIterator1>::value_type,
                                 typename std::iterator_traits<OutputIterator>::value_type>::value,
                OutputIterator>::type
                strxor(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2, InputIterator2 last2,
                       OutputIterator out) {
                BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator1>));
                BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator2>));
                BOOST_CONCEPT_ASSERT(
                    (boost::OutputIteratorConcept<OutputIterator,
                                                  typename std::iterator_traits<OutputIterator>::value_type>));

                assert(std::distance(first1, last1) == std::distance(first2, last2));

                for (; first1 != last1 && first2 != last2; first1++, first2++, out++) {
                    *out = *first1 ^ *first2;
                }

                return out;
            }

            template<typename InputRange1, typename InputRange2, typename OutputIterator>
            constexpr inline OutputIterator strxor(const InputRange1 &in1, const InputRange2 &in2, OutputIterator out) {
                BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<InputRange1>));
                BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<InputRange2>));

                return strxor(in1.cbegin(), in1.cend(), in2.cbegin(), in2.cend(), out);
            }
        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_DETAIL_STRXOR_HPP
