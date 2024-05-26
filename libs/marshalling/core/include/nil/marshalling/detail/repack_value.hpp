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

#ifndef MARSHALLING_MARSHALL_REPACK_VALUE_HPP
#define MARSHALLING_MARSHALL_REPACK_VALUE_HPP

#include <algorithm>
#include <iterator>
#include <type_traits>

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>

#include <boost/range/concepts.hpp>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/type_traits.hpp>
#include <nil/marshalling/inference.hpp>
#include <nil/marshalling/detail/unpack_value.hpp>
#include <nil/marshalling/detail/pack_value.hpp>

#include <nil/detail/type_traits.hpp>

namespace nil {
    namespace marshalling {
        namespace detail {

            template<typename TInputEndian, typename TOutputEndian, typename TInput>
            struct value_repack_impl {
                status_type *status;
                TInput input;

                value_repack_impl(const TInput &input, status_type &status) {
                    this->input = input;
                    this->status = &status;
                }

                template<typename T, typename = typename std::enable_if<
                                         std::is_same<T, T>::value && is_marshalling_type<TInput>::value
                                         && !nil::marshalling::is_supported_representation_type<T>::value>::type>
                inline operator T() {
                    status_type status_unpack, status_pack;
                    std::vector<std::uint8_t> buffer = value_unpack_impl<TInput>(input, status_unpack);

                    T result = range_pack_impl<TOutputEndian, std::vector<std::uint8_t>::const_iterator>(buffer,
                                                                                                         status_pack);
                    *status = status_pack | status_unpack;

                    return result;
                }

                template<typename T,
                         typename = typename std::enable_if<
                             std::is_same<T, T>::value && !is_marshalling_type<TInput>::value
                             && !nil::marshalling::is_supported_representation_type<T>::value>::type,
                         bool Enable = true>
                inline operator T() {
                    status_type status_unpack, status_pack;
                    using marshalling_type = typename is_compatible<TInput>::template type<TInputEndian>;

                    std::vector<std::uint8_t> buffer
                        = value_unpack_impl<marshalling_type>(marshalling_type(input), status_unpack);
                    T result = range_pack_impl<TOutputEndian, std::vector<std::uint8_t>::const_iterator>(buffer,
                                                                                                         status_pack);
                    *status = status_pack | status_unpack;

                    return result;
                }

                template<typename T,
                         typename = typename std::enable_if<
                             std::is_same<T, T>::value && !is_marshalling_type<TInput>::value
                             && nil::marshalling::is_supported_representation_type<T>::value>::type,
                         bool Enable1 = true, bool Enable2 = true>
                inline operator T() {
                    status_type status_unpack;

                    using marshalling_type = typename is_compatible<TInput>::template type<TOutputEndian>;

                    T result = value_unpack_impl<marshalling_type>(marshalling_type(input), status_unpack);
                    *status = status_unpack;

                    return result;
                }

                template<typename T,
                         typename = typename std::enable_if<
                             std::is_same<T, T>::value && is_marshalling_type<TInput>::value
                             && nil::marshalling::is_supported_representation_type<T>::value>::type,
                         bool Enable1 = true, bool Enable2 = true, bool Enable3 = true>
                inline operator T() {
                    status_type status_unpack;

                    T result = value_unpack_impl<TInput>(input, status_unpack);
                    *status = status_unpack;

                    return result;
                }
            };

            template<typename TInputEndian, typename TOutputEndian, typename Iter>
            struct range_repack_impl {
                status_type *status;
                mutable Iter iterator;
                size_t count_elements;
                status_type status_pack, status_unpack;
                using input_value = typename std::iterator_traits<Iter>::value_type;

                template<typename SinglePassRange>
                range_repack_impl(const SinglePassRange &range, status_type &status) {
                    iterator = range.begin();
                    count_elements = std::distance(range.begin(), range.end());
                    this->status = &status;
                }

                template<typename InputIterator>
                range_repack_impl(InputIterator first, InputIterator last, status_type &status) {
                    iterator = first;
                    count_elements = std::distance(first, last);
                    this->status = &status;
                }

                template<typename T,
                         typename = typename std::enable_if<
                             std::is_same<T, T>::value
                             && nil::marshalling::is_supported_representation_type<input_value>::value>::type>
                inline operator T() {
                    T result = range_pack_impl<TOutputEndian, Iter>(iterator, count_elements, status_pack);

                    *status = status_pack;
                    return result;
                }

                template<typename T,
                         typename = typename std::enable_if<
                             std::is_same<T, T>::value
                             && !nil::marshalling::is_supported_representation_type<input_value>::value
                             && (nil::marshalling::is_supported_representation_type<T>::value
                                 || nil::marshalling::is_supported_representation_type<
                                     typename T::value_type>::value)>::type,
                         bool Enable = true>
                inline operator T() {
                    T result = range_unpack_impl<TOutputEndian, Iter>(iterator, count_elements, status_unpack);
                    *status = status_unpack;
                    return result;
                }

                template<typename T,
                         typename = typename std::enable_if<
                             std::is_same<T, T>::value
                             && !nil::marshalling::is_supported_representation_type<input_value>::value
                             && !nil::marshalling::is_supported_representation_type<T>::value>::type,
                         bool Enable1 = true, bool Enable2 = true>
                inline operator T() {
                    std::vector<std::uint8_t> buffer
                        = range_unpack_impl<TInputEndian, Iter>(iterator, count_elements, status_unpack);
                    T result = range_pack_impl<TOutputEndian, std::vector<std::uint8_t>::const_iterator>(buffer,
                                                                                                         status_pack);
                    *status = status_pack | status_unpack;
                    return result;
                }
            };

            template<typename TInputEndian, typename TOutputEndian, typename Iter, typename OutputIterator>
            struct itr_repack_impl {
                status_type *status;
                mutable Iter iterator;
                size_t count_elements;
                mutable OutputIterator out_iterator;
                using input_value = typename std::iterator_traits<Iter>::value_type;

                template<typename SinglePassRange>
                itr_repack_impl(const SinglePassRange &range, OutputIterator out, status_type &status) {
                    iterator = range.begin();
                    out_iterator = out;
                    count_elements = std::distance(range.begin(), range.end());
                    this->status = &status;
                }

                template<typename InputIterator>
                itr_repack_impl(InputIterator first, InputIterator last, OutputIterator out, status_type &status) {
                    iterator = first;
                    out_iterator = out;
                    count_elements = std::distance(first, last);
                    this->status = &status;
                }

                template<typename T,
                         typename
                         = typename std::enable_if<std::is_same<T, T>::value
                                                   && nil::marshalling::is_supported_representation_type<
                                                       typename std::iterator_traits<Iter>::value_type>::value>::type>
                inline operator T() {
                    status_type status_pack;

                    out_iterator = range_pack_impl<TOutputEndian, std::vector<std::uint8_t>::const_iterator>(
                        iterator, count_elements, out_iterator, status_pack);
                    *status = status_pack;

                    return out_iterator;
                }

                template<typename T,
                         typename = typename std::enable_if<
                             std::is_same<T, T>::value
                             && !nil::marshalling::is_supported_representation_type<input_value>::value
                             && nil::marshalling::is_supported_representation_type<T>::value>::type,
                         bool Enable = true>
                inline operator T() {
                    status_type status_unpack;

                    T result
                        = range_unpack_impl<TOutputEndian, Iter>(iterator, count_elements, out_iterator, status_unpack);
                    *status = status_unpack;

                    return out_iterator;
                }

                template<typename T,
                         typename
                         = typename std::enable_if<std::is_same<T, T>::value
                                                   && !nil::marshalling::is_supported_representation_type<
                                                       typename std::iterator_traits<Iter>::value_type>::value>::type,
                         bool Enable1 = true, bool Enable2 = true>
                inline operator T() {
                    status_type status_unpack, status_pack;

                    std::vector<std::uint8_t> buffer
                        = range_unpack_impl<TInputEndian, Iter>(iterator, count_elements, status_unpack);
                    out_iterator = range_pack_impl<TOutputEndian, std::vector<std::uint8_t>::const_iterator>(
                        buffer, out_iterator, status_pack);
                    *status = status_pack | status_unpack;

                    return out_iterator;
                }
            };
        }    // namespace detail
    }        // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_MARSHALL_REPACK_VALUE_HPP
