//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
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

#ifndef MARSHALLING_MARSHALL_NEW_HPP
#define MARSHALLING_MARSHALL_NEW_HPP

#include <type_traits>

#include <nil/marshalling/type_traits.hpp>
#include <nil/marshalling/inference.hpp>
#include <nil/detail/pack_value.hpp>
#include <nil/detail/type_traits.hpp>

#include <boost/container/static_vector.hpp>
#include <boost/concept/requires.hpp>
#include <boost/range/concepts.hpp>

namespace nil {
    namespace marshalling {
        /*!
         * @defgroup marshalling Marshalling
         *
         * @brief Marshalling between two or more defined types
         *
         * @defgroup marshalling_algorithms Algorithms
         * @ingroup marshalling
         * @brief Algorithms are meant to provide marshalling interface similar to STL algorithms' one.
         */


        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TEndian
         * @tparam SinglePassRange
         *
         * @param r
         *
         * @return
         */
        template<typename TEndian, typename SinglePassRange>
        typename std::enable_if<std::is_integral<typename SinglePassRange::value_type>::value,
                                nil::detail::range_pack_impl<TEndian, typename SinglePassRange::const_iterator>>::type
            pack(const SinglePassRange &r) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
            status_type s;
            return nil::detail::range_pack_impl<TEndian, typename SinglePassRange::const_iterator>(r, s);
        }

        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TEndian
         * @tparam SinglePassRange
         *
         * @param r
         * @param status
         *
         * @return
         */
        template<typename TEndian, typename SinglePassRange>
        typename std::enable_if<std::is_integral<typename SinglePassRange::value_type>::value,
                                nil::detail::range_pack_impl<TEndian, typename SinglePassRange::const_iterator>>::type
            pack(const SinglePassRange &r, status_type &status) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
            return nil::detail::range_pack_impl<TEndian, typename SinglePassRange::const_iterator>(r, status);
        }
        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TEndian
         * @tparam SinglePassRange
         *
         * @param r
         *
         * @return
         */
        template<typename TEndian, typename SinglePassRange>
        typename std::enable_if<nil::detail::is_range<SinglePassRange>::value
                                    && std::is_integral<typename SinglePassRange::value_type>::value,
                                nil::detail::range_pack_impl<TEndian, typename SinglePassRange::const_iterator>>::type
            pack(const SinglePassRange &r) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
            status_type s;
            return nil::detail::range_pack_impl<TEndian, typename SinglePassRange::const_iterator>(r, s);
        }

        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TEndian
         * @tparam InputIterator
         *
         * @param first
         * @param last
         * @param status
         *
         * @return
         */

        template<typename TEndian, typename InputIterator>
        typename std::enable_if<
            nil::detail::is_iterator<InputIterator>::value
                && std::is_integral<typename std::iterator_traits<InputIterator>::value_type>::value,
            nil::detail::range_pack_impl<TEndian, InputIterator>>::type
            pack(InputIterator first, InputIterator last, status_type &status) {
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));
            return nil::detail::range_pack_impl<TEndian, InputIterator>(first, last, status);
        }

        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TEndian
         * @tparam InputIterator
         *
         * @param first
         * @param last
         * @param status
         *
         * @return
         */

        template<typename TEndian, typename InputIterator>
        typename std::enable_if<
            nil::detail::is_iterator<InputIterator>::value
                && std::is_integral<typename std::iterator_traits<InputIterator>::value_type>::value,
            nil::detail::range_pack_impl<TEndian, InputIterator>>::type
            pack(InputIterator first, InputIterator last) {
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));
            status_type s;
            return nil::detail::range_pack_impl<TEndian, InputIterator>(first, last, s);
        }

        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TEndian
         * @tparam SinglePassRange
         * @tparam OutputIterator
         *
         * @param r
         * @param out
         * @param status
         *
         * @return
         */
        template<typename TEndian, typename SinglePassRange, typename OutputIterator>
        typename std::enable_if<
            nil::detail::is_range<SinglePassRange>::value
                && std::is_integral<typename SinglePassRange::value_type>::value
                && nil::detail::is_iterator<OutputIterator>::value,
            nil::detail::itr_pack_impl<TEndian, typename SinglePassRange::const_iterator, OutputIterator>>::type
            pack(const SinglePassRange &r, OutputIterator out, status_type &status) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
            return nil::detail::itr_pack_impl<TEndian, typename SinglePassRange::const_iterator, OutputIterator>(
                r, std::move(out), status);
        }

        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TEndian
         * @tparam SinglePassRange
         * @tparam OutputIterator
         *
         * @param r
         * @param out
         * @param status
         *
         * @return
         */
        template<typename TEndian, typename SinglePassRange, typename OutputIterator>
        typename std::enable_if<
            nil::detail::is_iterator<OutputIterator>::value && nil::detail::is_range<SinglePassRange>::value
                && std::is_integral<typename SinglePassRange::value_type>::value
                && nil::detail::is_iterator<OutputIterator>::value,
            nil::detail::itr_pack_impl<TEndian, typename SinglePassRange::const_iterator, OutputIterator>>::type
            pack(const SinglePassRange &r, OutputIterator out) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
            status_type s;
            return nil::detail::itr_pack_impl<TEndian, typename SinglePassRange::const_iterator, OutputIterator>(r, std::move(out),
                                                                                                                 s);
        }

        /*!
         * @brief
         * @tparam TEndian
         * @tparam InputIterator
         * @tparam OutputIterator
         * @param first
         * @param last
         * @param out
         * @param status
         * @return
         */
        template<typename TEndian, typename InputIterator, typename OutputIterator>
        typename std::enable_if<nil::detail::is_iterator<InputIterator>::value
                                    && std::is_integral<typename std::iterator_traits<InputIterator>::value_type>::value
                                    && nil::detail::is_iterator<OutputIterator>::value,
                                nil::detail::itr_pack_impl<TEndian, InputIterator, OutputIterator>>::type
            pack(InputIterator first, InputIterator last, OutputIterator out, status_type &status) {
            return nil::detail::itr_pack_impl<TEndian, InputIterator, OutputIterator>(first, last, std::move(out), status);
        }

        /*!
         * @brief
         * @tparam TEndian
         * @tparam InputIterator
         * @tparam OutputIterator
         * @param first
         * @param last
         * @param out
         * @return
         */
        template<typename TEndian, typename InputIterator, typename OutputIterator>
        typename std::enable_if<nil::detail::is_iterator<InputIterator>::value
                                    && std::is_integral<typename std::iterator_traits<InputIterator>::value_type>::value
                                    && nil::detail::is_iterator<OutputIterator>::value,
                                status_type>::type
            pack(InputIterator first, InputIterator last, OutputIterator out) {
            BOOST_CONCEPT_ASSERT(
                (boost::OutputIteratorConcept<OutputIterator,
                                              typename std::iterator_traits<OutputIterator>::value_type>));
            status_type status;
            status = nil::detail::itr_pack_impl<TEndian, InputIterator, OutputIterator>(first, last, std::move(out), status);
            return status;
        }

        /*!
         * @brief
         * @tparam TEndian
         * @tparam SinglePassRange1
         * @tparam SinglePassRange2
         * @param rng_input
         * @param rng_output
         * @return
         */
        template<typename TEndian, typename SinglePassRange1, typename SinglePassRange2>
        typename std::enable_if<nil::detail::is_range<SinglePassRange1>::value
                                    && nil::detail::is_range<SinglePassRange2>::value
                                    && !nil::detail::is_similar_std_array<SinglePassRange2>::value,
                                status_type>::type
            pack(const SinglePassRange1 &rng_input, SinglePassRange2 &rng_output) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange1>));
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange2>));
            status_type status;
            std::vector<typename SinglePassRange2::value_type> v = pack<TEndian>(rng_input, status);
            rng_output = SinglePassRange2(v.begin(), v.end());
            return status;
        }

        /*!
         * @brief
         * @tparam TEndian
         * @tparam SinglePassRange
         * @tparam TOutput
         * @param rng_input
         * @param rng_output
         * @return
         */
        template<typename TEndian, typename SinglePassRange, typename TOutput>
        typename std::enable_if<!(nil::detail::is_range<TOutput>::value || nil::detail::is_iterator<TOutput>::value)
                                    || nil::detail::is_similar_std_array<TOutput>::value,
                                status_type>::type
            pack(const SinglePassRange &rng_input, TOutput &rng_output) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
            status_type status;
            rng_output = pack<TEndian>(rng_input, status);
            return status;
        }

        /*!
         * @brief
         * @tparam TEndian
         * @tparam InputIterator
         * @tparam SinglePassRange
         * @param first
         * @param last
         * @param rng_output
         * @return
         */
        template<typename TEndian, typename InputIterator, typename SinglePassRange>
        typename std::enable_if<nil::detail::is_iterator<InputIterator>::value
                                    && nil::detail::is_range<SinglePassRange>::value
                                    && !(nil::detail::is_similar_std_array<SinglePassRange>::value),
                                status_type>::type
            pack(InputIterator first, InputIterator last, SinglePassRange &rng_output) {
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
            status_type status;
            std::vector<typename SinglePassRange::value_type> v = pack<TEndian>(first, last, status);
            rng_output = SinglePassRange(v.begin(), v.end());
            return status;
        }

        /*!
         * @brief
         * @tparam TEndian
         * @tparam InputIterator
         * @tparam TOutput
         * @param first
         * @param last
         * @param rng_output
         * @return
         */
        template<typename TEndian, typename InputIterator, typename TOutput>
        typename std::enable_if<nil::detail::is_iterator<InputIterator>::value && !nil::detail::is_range<TOutput>::value
                                    || nil::detail::is_similar_std_array<TOutput>::value,
                                status_type>::type
            pack(InputIterator first, InputIterator last, TOutput &rng_output) {
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));
            status_type status;
            rng_output = pack<TEndian>(first, last, status);
            return status;
        }
    }    // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_MARSHALL_NEW_HPP
