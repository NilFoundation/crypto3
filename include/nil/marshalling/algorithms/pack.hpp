//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef MARSHALLING_REPACK_NEW_HPP
#define MARSHALLING_REPACK_NEW_HPP

#include <nil/marshalling/detail/repack_value.hpp>

namespace nil {
    namespace marshalling {
        /*!
         * @defgroup marshalling Marshalling
         *
         * @brief Marshalling between one type, different endianness
         *
         * @defgroup marshalling_algorithms Algorithms
         * @ingroup marshalling
         * @brief Algorithms are meant to provide marshalling interface similar to STL algorithms' one.
         */

        /*!
         * @brief Repack converting between arbitrary types, arbitrary endiannesses.
         * In case, if one type (inpur nor output) is byte container and there is no
         * need to change the endianness, it's better to use pack or unpack algorithm
         * respectively. The repack algorithm would work less effective in that case.
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TInputEndian
         * @tparam TOutputEndian
         * @tparam SinglePassRange
         *
         * @param val
         * @param status
         *
         * @return TOutput
         */
        template<typename TOutputEndian = option::big_endian, typename TInputEndian = option::big_endian, typename SinglePassRange>
        typename std::enable_if<
            nil::detail::is_range<SinglePassRange>::value,
            detail::range_repack_impl<TInputEndian, TOutputEndian, typename SinglePassRange::const_iterator>>::type

            pack(const SinglePassRange &val, status_type &status) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
            return detail::range_repack_impl<TInputEndian, TOutputEndian, typename SinglePassRange::const_iterator>(val, status);
        }

        template<typename TOutputEndian = option::big_endian, typename TInputEndian = option::big_endian, typename TInput>
        typename std::enable_if<!nil::detail::is_range<TInput>::value,
                                detail::value_repack_impl<TInputEndian, TOutputEndian, TInput>>::type

            pack(const TInput &val, status_type &status) {
            return detail::value_repack_impl<TInputEndian, TOutputEndian, TInput>(val, status);
        }

        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TInputEndian
         * @tparam TOutputEndian
         * @tparam InputIterator
         *
         * @param first
         * @param last
         * @param status
         *
         * @return
         */
        template<typename TOutputEndian = option::big_endian, typename TInputEndian = option::big_endian, typename InputIterator>
        typename std::enable_if<
            nil::detail::is_iterator<InputIterator>::value
                && std::is_integral<typename std::iterator_traits<InputIterator>::value_type>::value,
            detail::range_repack_impl<TInputEndian, TOutputEndian, InputIterator>>::type
            pack(InputIterator first, InputIterator last, status_type &status) {
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));
            return detail::range_repack_impl<TInputEndian, TOutputEndian, InputIterator>(first, last, status);
        }

        template<typename TOutputEndian = option::big_endian, typename TInputEndian = option::big_endian, typename TInput, typename TOutputIterator>
        typename std::enable_if<!nil::detail::is_range<TInput>::value && nil::detail::is_iterator<TOutputIterator>::value,
                                TOutputIterator>::type
            pack(const TInput &val, TOutputIterator out, status_type &status) {
            using T = typename std::iterator_traits<TOutputIterator>::value_type;
            std::vector<T> result  = pack<TInputEndian, TOutputEndian>(val, status);
            return std::move(result.cbegin(), result.cend(), out);
        }

        template<typename TOutputEndian = option::big_endian, typename TInputEndian = option::big_endian, typename SinglePassRange, typename TOutputIterator>
        typename std::enable_if<nil::detail::is_range<SinglePassRange>::value
                                    && nil::detail::is_iterator<TOutputIterator>::value,
                                TOutputIterator>::type
            pack(const SinglePassRange &rng_input, TOutputIterator out, status_type &status) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
            using T = typename std::iterator_traits<TOutputIterator>::value_type;
            std::vector<T> result = pack<TOutputEndian, TInputEndian>(rng_input, status);
            return std::move(result.cbegin(), result.cend(), out);
        }

        template<typename TOutputEndian = option::big_endian, typename TInputEndian = option::big_endian, typename InputIterator, typename TOutputIterator>
        typename std::enable_if<nil::detail::is_iterator<InputIterator>::value
                                    && nil::detail::is_iterator<TOutputIterator>::value,
                                TOutputIterator>::type
            pack(InputIterator first, InputIterator last, TOutputIterator out, status_type &status) {
            using T = typename std::iterator_traits<TOutputIterator>::value_type;
            std::vector<T> result = pack<TOutputEndian, TInputEndian>(first, last, status);
            return std::move(result.cbegin(), result.cend(), out);
        }

        template<typename TOutputEndian = option::big_endian, typename TInputEndian = option::big_endian, typename TInput, typename SinglePassRange>
        typename std::enable_if<!nil::detail::is_range<TInput>::value && nil::detail::is_range<SinglePassRange>::value
                                    && std::is_constructible<SinglePassRange,
                                                            typename std::vector<typename SinglePassRange::value_type>::const_iterator,
                                                            typename std::vector<typename SinglePassRange::value_type>::const_iterator>::value,
                                status_type>::type

            pack(const TInput &val, SinglePassRange &rng_output) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
            status_type status;
            std::vector<typename SinglePassRange::value_type> result  = pack<TOutputEndian, TInputEndian>(val, status);
            rng_output = SinglePassRange(result.begin(), result.end());
            return status;
        }

        template<typename TOutputEndian = option::big_endian, typename TInputEndian = option::big_endian, typename TInput, typename SinglePassRange>
        typename std::enable_if<!nil::detail::is_range<TInput>::value && nil::detail::is_range<SinglePassRange>::value
                                    && !std::is_constructible<SinglePassRange,
                                                             typename std::vector<typename SinglePassRange::value_type>::const_iterator,
                                                             typename std::vector<typename SinglePassRange::value_type>::const_iterator>::value,
                                status_type>::type

            pack(const TInput &val, SinglePassRange &rng_output) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
            status_type status;
            rng_output  = pack<TOutputEndian, TInputEndian>(val, status);
            return status;
        }

        template<typename TOutputEndian = option::big_endian, typename TInputEndian = option::big_endian, typename SinglePassRange1, typename SinglePassRange2>
        typename std::enable_if<nil::detail::is_range<SinglePassRange1>::value
                                    && nil::detail::is_range<SinglePassRange2>::value
                                    && std::is_constructible<SinglePassRange2,
                                                             typename SinglePassRange2::const_iterator,
                                                             typename SinglePassRange2::const_iterator>::value,
                                status_type>::type
            pack(const SinglePassRange1 &rng_input, SinglePassRange2 &rng_output) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange1>));
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange2>));
            status_type status;
            std::vector<typename SinglePassRange2::value_type> result
                = pack<TOutputEndian, TInputEndian>(rng_input, status);
            rng_output = SinglePassRange2(result.begin(), result.end());
            return status;
        }

        template<typename TOutputEndian = option::big_endian, typename TInputEndian = option::big_endian, typename SinglePassRange1, typename SinglePassRange2>
        typename std::enable_if<
            nil::detail::is_range<SinglePassRange1>::value && nil::detail::is_range<SinglePassRange2>::value
                && !std::is_constructible<
                    SinglePassRange2,
                    typename std::vector<typename SinglePassRange2::value_type>::const_iterator,
                    typename std::vector<typename SinglePassRange2::value_type>::const_iterator>::value,
            status_type>::type
            pack(const SinglePassRange1 &rng_input, SinglePassRange2 &rng_output) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange1>));
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange2>));
            status_type status;
            rng_output = pack<TOutputEndian, TInputEndian>(rng_input, status);
            return status;
        }

        template<typename TOutputEndian = option::big_endian, typename TInputEndian = option::big_endian, typename InputIterator, typename SinglePassRange>
        typename std::enable_if<
            nil::detail::is_iterator<InputIterator>::value && nil::detail::is_range<SinglePassRange>::value
                && std::is_constructible<
                    SinglePassRange,
                    typename std::vector<typename SinglePassRange::value_type>::const_iterator,
                    typename std::vector<typename SinglePassRange::value_type>::const_iterator>::value,
            status_type>::type
            pack(InputIterator first, InputIterator last, SinglePassRange &rng_output) {
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));
            status_type status;
            std::vector<typename SinglePassRange::value_type> result
                = pack<TOutputEndian, TInputEndian>(first, last, status);
            rng_output = SinglePassRange(result.begin(), result.end());
            return status;
        }

        template<typename TOutputEndian = option::big_endian, typename TInputEndian = option::big_endian, typename InputIterator, typename SinglePassRange>
        typename std::enable_if<nil::detail::is_iterator<InputIterator>::value
                                    && nil::detail::is_range<SinglePassRange>::value
                                    && !std::is_constructible<SinglePassRange,
                                                              typename SinglePassRange::const_iterator,
                                                              typename SinglePassRange::const_iterator>::value,
                                status_type>::type
            pack(InputIterator first, InputIterator last, SinglePassRange &rng_output) {
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));
            status_type status;
            rng_output = pack<TOutputEndian, TInputEndian>(first, last, status);
            return status;
        }

        template<typename TOutputEndian = option::big_endian, typename TInputEndian = option::big_endian, typename InputIterator, typename TOutput>
        typename std::enable_if<nil::detail::is_iterator<InputIterator>::value
                                    && !(nil::detail::is_range<TOutput>::value || nil::detail::is_array<TOutput>::value)
                                    && !std::is_same<TOutput, status_type>::value,
                                status_type>::type
            pack(InputIterator first, InputIterator last, TOutput &rng_output) {
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));
            status_type status;
            rng_output = pack<TOutputEndian, TInputEndian>(first, last, status);
            return status;
        }

        template<typename TOutputEndian = option::big_endian, typename TInputEndian = option::big_endian, typename SinglePassRange, typename TOutput>
        typename std::enable_if<nil::detail::is_range<SinglePassRange>::value
                                    && !(nil::detail::is_range<TOutput>::value || nil::detail::is_array<TOutput>::value)
                                    && !std::is_same<TOutput, status_type>::value,
                                status_type>::type
            pack(const SinglePassRange &rng_input, TOutput &rng_output) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
            status_type status;
            rng_output = pack<TOutputEndian, TInputEndian>(rng_input, status);
            return status;
        }

        template<typename TOutputEndian = option::big_endian, typename TInputEndian = option::big_endian, typename TInput, typename TOutputIterator>
        typename std::enable_if<!nil::detail::is_range<TInput>::value && nil::detail::is_iterator<TOutputIterator>::value,
                                status_type>::type

            pack(const TInput &val, TOutputIterator out) {
            status_type status;
            using T = typename std::iterator_traits<TOutputIterator>::value_type;
            std::vector<T> result = pack<TOutputEndian, TInputEndian>(val, status);
            std::move(result.cbegin(), result.cend(), out);
            return status;
        }

        template<typename TOutputEndian = option::big_endian, typename TInputEndian = option::big_endian, typename SinglePassRange, typename TOutputIterator>
        typename std::enable_if<nil::detail::is_range<SinglePassRange>::value
                                    && nil::detail::is_iterator<TOutputIterator>::value,
                                status_type>::type
            pack(const SinglePassRange &rng_input, TOutputIterator out) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
            status_type status;
            using T = typename std::iterator_traits<TOutputIterator>::value_type;
            std::vector<T> result = pack<TOutputEndian, TInputEndian>(rng_input, status);
            std::move(result.cbegin(), result.cend(), out);
            return status;
        }

        template<typename TOutputEndian = option::big_endian, typename TInputEndian = option::big_endian, typename InputIterator, typename TOutputIterator>
        typename std::enable_if<nil::detail::is_iterator<InputIterator>::value
                                    && nil::detail::is_iterator<TOutputIterator>::value,
                                status_type>::type
            pack(InputIterator first, InputIterator last, TOutputIterator out) {
            using T = typename std::iterator_traits<TOutputIterator>::value_type;
            status_type status;
            std::vector<T> result = pack<TOutputEndian, TInputEndian>(first, last, status);
            std::move(result.cbegin(), result.cend(), out);
            return status;
        }
    }    // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_REPACK_NEW_HPP
