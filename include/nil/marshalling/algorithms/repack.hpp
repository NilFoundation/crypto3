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

#include <nil/detail/repack_value.hpp>

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
        template<typename TInputEndian, typename TOutputEndian, typename SinglePassRange>
        nil::detail::range_repack_impl<TInputEndian, TOutputEndian, typename SinglePassRange::const_iterator>
            repack(const SinglePassRange &val, status_type &status) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
            return nil::detail::
                range_repack_impl<TInputEndian, TOutputEndian, typename SinglePassRange::const_iterator>(val, status);
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
        template<typename TInputEndian, typename TOutputEndian, typename InputIterator>
        typename std::enable_if<std::is_integral<typename InputIterator::value_type>::value,
                                nil::detail::range_repack_impl<TInputEndian, TOutputEndian, InputIterator>>::type
            repack(InputIterator first, InputIterator last, status_type &status) {
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));
            return nil::detail::range_repack_impl<TInputEndian, TOutputEndian, InputIterator>(first, last, status);
        }

        template<typename TInputEndian, typename TOutputEndian, typename InputIterator, typename SinglePassRange>
        status_type repack(InputIterator first, InputIterator last, SinglePassRange &rng_output) {
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));
            status_type status;
            std::vector<typename SinglePassRange::value_type> result
                = repack<TInputEndian, TOutputEndian>(first, last, status);
            rng_output = SinglePassRange(result.begin(), result.end());
            return status;
        }

        template<typename TInputEndian, typename TOutputEndian, typename SinglePassRange1, typename SinglePassRange2>
        typename std::enable_if<nil::detail::is_range<SinglePassRange2>::value, status_type>::type
            repack(const SinglePassRange1 &rng_input, SinglePassRange2 &rng_output) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange1>));
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange2>));
            status_type status;
            std::vector<typename SinglePassRange2::value_type> result
                = repack<TInputEndian, TOutputEndian>(rng_input, status);
            rng_output = SinglePassRange2(result.begin(), result.end());
            return status;
        }

        template<typename TInputEndian, typename TOutputEndian, typename SinglePassRange, typename TOutput>
        typename std::enable_if<!(nil::detail::is_range<TOutput>::value
                                  || nil::detail::is_array<TOutput>::value),
                                status_type>::type
            repack(const SinglePassRange &rng_input, TOutput &rng_output) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
            status_type status;
            rng_output = repack<TInputEndian, TOutputEndian>(rng_input, status);
            return status;
        }

        template<typename TInputEndian, typename TOutputEndian, typename SinglePassRange, typename TOutputIterator>
        TOutputIterator repack(const SinglePassRange &rng_input, TOutputIterator out, status_type &status) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
            std::vector<typename SinglePassRange::value_type> result
                = repack<TInputEndian, TOutputEndian>(rng_input, status);
            return std::move(result.cbegin(), result.cend(), out);
            ;
        }

        template<typename TInputEndian, typename TOutputEndian, typename SinglePassRange, typename TOutputIterator>
        typename std::enable_if<!nil::detail::is_range<TOutputIterator>::value, status_type>::type
            repack(const SinglePassRange &rng_input, TOutputIterator out) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
            status_type status;
            std::vector<typename SinglePassRange::value_type> result
                = repack<TInputEndian, TOutputEndian>(rng_input, status);
            std::move(result.cbegin(), result.cend(), out);
            return status;
        }

        template<typename TInputEndian, typename TOutputEndian, typename InputIterator, typename TOutputIterator>
        TOutputIterator repack(InputIterator first, InputIterator last, TOutputIterator out, status_type &status) {
            std::vector<typename InputIterator::value_type> result
                = repack<TInputEndian, TOutputEndian>(first, last, status);
            return std::move(result.cbegin(), result.cend(), out);
        }

        template<typename TInputEndian, typename TOutputEndian, typename InputIterator, typename TOutputIterator>
        typename std::enable_if<!nil::detail::is_range<TOutputIterator>::value, status_type>::type
            repack(InputIterator first, InputIterator last, TOutputIterator out) {
            status_type status;
            std::vector<typename InputIterator::value_type> result
                = repack<TInputEndian, TOutputEndian>(first, last, status);
            std::move(result.cbegin(), result.cend(), out);
            return status;
        }

    }    // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_REPACK_NEW_HPP
