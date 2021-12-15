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

#ifndef MARSHALLING_MARSHALL_UNPACK_NEW_HPP
#define MARSHALLING_MARSHALL_UNPACK_NEW_HPP

#include <type_traits>

#include <boost/spirit/home/support/container.hpp>

#include <nil/marshalling/type_traits.hpp>
#include <nil/marshalling/inference.hpp>
#include <nil/detail/unpack_value.hpp>
#include <nil/detail/type_traits.hpp>

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

        /*
         * Marshalling with both input and output types, which are marshalling types, not a std
         * iterator of elements with a marshalling type
         */

        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TInput
         *
         * @param input
         * @param status
         *
         * @return
         */
        template<typename TMarshallingInput>
        typename std::enable_if<is_marshalling_type<TMarshallingInput>::value,
                                nil::detail::value_unpack_impl<TMarshallingInput>>::type
            unpack(const TMarshallingInput &input, status_type &status) {

            return nil::detail::value_unpack_impl<TMarshallingInput>(input, status);
        }

        template<typename TMarshallingInput>
        typename std::enable_if<is_marshalling_type<TMarshallingInput>::value,
                                nil::detail::value_unpack_impl<TMarshallingInput>>::type
            unpack(const TMarshallingInput &input) {
            status_type status;
            return nil::detail::value_unpack_impl<TMarshallingInput>(input, status);
        }

        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TEndian
         * @tparam TInput
         *
         * @param input
         * @param status
         *
         * @return
         */

        template<typename TEndian, typename TInput>
        typename std::enable_if<
            is_compatible<TInput>::value
                && !nil::marshalling::is_container<typename is_compatible<TInput>::template type<>>::value,
            nil::detail::value_unpack_impl<typename is_compatible<TInput>::template type<TEndian>>>::type
            unpack(const TInput &input, status_type &status) {

            using marshalling_type = typename is_compatible<TInput>::template type<TEndian>;
            return unpack(marshalling_type(input), status);
        }

        template<typename TEndian, typename TInput>
        typename std::enable_if<
            is_compatible<TInput>::value
                && !nil::marshalling::is_container<typename is_compatible<TInput>::template type<>>::value,
            nil::detail::value_unpack_impl<typename is_compatible<TInput>::template type<TEndian>>>::type
            unpack(const TInput &input) {

            using marshalling_type = typename is_compatible<TInput>::template type<TEndian>;

            return unpack(marshalling_type(input));
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
        typename std::enable_if<nil::detail::is_range<SinglePassRange>::value,
                                nil::detail::range_unpack_impl<TEndian, typename SinglePassRange::const_iterator>>::type
            unpack(const SinglePassRange &r, status_type &status) {

            return nil::detail::range_unpack_impl<TEndian, typename SinglePassRange::const_iterator>(r, status);
        }

        template<typename TEndian, typename InputIterator>
        typename std::enable_if<nil::detail::is_iterator<InputIterator>::value,
                                nil::detail::range_unpack_impl<TEndian, InputIterator>>::type
            unpack(InputIterator first, InputIterator last, status_type &status) {

            return nil::detail::range_unpack_impl<TEndian, InputIterator>(first, last, status);
        }
        // all with outputiterator begin
        template<typename TInput, typename OutputIterator>
        typename std::enable_if<nil::detail::is_iterator<OutputIterator>::value, OutputIterator>::type
            unpack(const TInput &r, OutputIterator out, status_type &status) {
            using T = typename std::iterator_traits<OutputIterator>::value_type;
            std::vector<T> result = unpack(r, status);
            return std::move(result.cbegin(), result.cend(), out);
        }

        template<typename InputIterator, typename OutputIterator>
        typename std::enable_if<nil::detail::is_iterator<InputIterator>::value
                                    && nil::detail::is_iterator<OutputIterator>::value,
                                OutputIterator>::type
            unpack(InputIterator first, InputIterator last, OutputIterator out, status_type &status) {
            using T = typename std::iterator_traits<OutputIterator>::value_type;
            std::vector<T> result = unpack(first, last, status);
            return std::move(result.cbegin(), result.cend(), out);
        }

        template<typename TInput, typename OutputIterator>
        typename std::enable_if<nil::detail::is_iterator<OutputIterator>::value, status_type>::type
            unpack(const TInput &r, OutputIterator out) {
            using T = typename std::iterator_traits<OutputIterator>::value_type;
            status_type status;
            std::vector<T> result = unpack(r, status);
            std::move(result.cbegin(), result.cend(), out);
            return status;
        }

        template<typename InputIterator, typename OutputIterator>
        typename std::enable_if<nil::detail::is_iterator<InputIterator>::value
                                    && nil::detail::is_iterator<OutputIterator>::value,
                                status_type>::type
            unpack(InputIterator first, InputIterator last, OutputIterator out) {
            using T = typename std::iterator_traits<OutputIterator>::value_type;
            status_type status;
            std::vector<T> result = unpack(first, last, status);
            std::move(result.cbegin(), result.cend(), out);
            return status;
        }

        template<typename TEndian, typename TInput, typename OutputIterator>
        typename std::enable_if<nil::detail::is_iterator<OutputIterator>::value, OutputIterator>::type
            unpack(const TInput &r, OutputIterator out, status_type &status) {
            using T = typename std::iterator_traits<OutputIterator>::value_type;
            std::vector<T> result = unpack<TEndian>(r, status);
            return std::move(result.cbegin(), result.cend(), out);
        }

        template<typename TEndian, typename TInput, typename OutputIterator>
        typename std::enable_if<nil::detail::is_iterator<OutputIterator>::value
                                    && !nil::detail::is_array<OutputIterator>::value,
                                status_type>::type
            unpack(const TInput &r, OutputIterator out) {
            using T = typename std::iterator_traits<OutputIterator>::value_type;
            status_type status;
            std::vector<T> result = unpack<TEndian>(r, status);
            std::move(result.cbegin(), result.cend(), out);
            return status;
        }

        template<typename TEndian, typename InputIterator, typename OutputIterator>
        typename std::enable_if<nil::detail::is_iterator<InputIterator>::value
                                    && nil::detail::is_iterator<OutputIterator>::value,
                                OutputIterator>::type
            unpack(InputIterator first, InputIterator last, OutputIterator out, status_type &status) {
            using T = typename std::iterator_traits<OutputIterator>::value_type;
            std::vector<T> result = unpack<TEndian>(first, last, status);
            return std::move(result.cbegin(), result.cend(), out);
        }

        template<typename TEndian, typename InputIterator, typename OutputIterator>
        typename std::enable_if<nil::detail::is_iterator<InputIterator>::value
                                    && nil::detail::is_iterator<OutputIterator>::value
                                    && !nil::detail::is_array<OutputIterator>::value,
                                status_type>::type
            unpack(InputIterator first, InputIterator last, OutputIterator out) {
            using T = typename std::iterator_traits<OutputIterator>::value_type;
            status_type status;
            std::vector<T> result = unpack<TEndian>(first, last, status);
            std::move(result.cbegin(), result.cend(), out);
            return status;
        }
        // all with outputiterator end

        template<typename TInput, typename SinglePassRange>
        typename std::enable_if<nil::detail::is_range<SinglePassRange>::value
                                    && !(nil::detail::is_array<SinglePassRange>::value),
                                status_type>::type
            unpack(const TInput &input, SinglePassRange &result) {
            status_type status;
            std::vector<typename SinglePassRange::value_type> v = unpack(input, status);
            result = SinglePassRange(v.begin(), v.end());
            return status;
        }

        template<typename TInput, typename TOutput>
        typename std::enable_if<!nil::detail::is_range<TOutput>::value
                                    || nil::detail::is_array<TOutput>::value,
                                status_type>::type
            unpack(const TInput &input, TOutput &result) {
            status_type status;
            result = unpack(input, status);
            return status;
        }

        template<typename TEndian, typename TInput, typename SinglePassRange>
        typename std::enable_if<nil::detail::is_range<SinglePassRange>::value
                                    && !(nil::detail::is_array<SinglePassRange>::value),
                                status_type>::type
            unpack(const TInput &input, SinglePassRange &result) {
            status_type status;
            std::vector<typename SinglePassRange::value_type> v = unpack<TEndian>(input, status);
            result = SinglePassRange(v.begin(), v.end());
            return status;
        }

        template<typename TEndian, typename TInput, typename TOutput>
        typename std::enable_if<!nil::detail::is_range<TOutput>::value
                                    || nil::detail::is_array<TOutput>::value,
                                status_type>::type
            unpack(const TInput &input, TOutput &result) {
            status_type status;
            result = unpack<TEndian>(input, status);
            return status;
        }

        template<typename TEndian, typename InputIterator, typename SinglePassRange>
        typename std::enable_if<nil::detail::is_iterator<InputIterator>::value
                                    && nil::detail::is_range<SinglePassRange>::value
                                    && !(nil::detail::is_array<SinglePassRange>::value),
                                status_type>::type
            unpack(InputIterator first, InputIterator last, SinglePassRange &result) {
            status_type status;
            std::vector<typename SinglePassRange::value_type> v = unpack<TEndian>(first, last, status);
            result = SinglePassRange(v.begin(), v.end());
            return status;
        }

        template<typename TEndian, typename InputIterator, typename TOutput>
        typename std::enable_if<nil::detail::is_iterator<InputIterator>::value && !nil::detail::is_range<TOutput>::value
                                    || nil::detail::is_array<TOutput>::value,
                                status_type>::type
            unpack(InputIterator first, InputIterator last, TOutput &result) {
            status_type status;
            result = unpack<TEndian>(first, last, status);
            return status;
        }
    }    // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_MARSHALL_UNPACK_NEW_HPP
