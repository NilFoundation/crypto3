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

#ifndef MARSHALLING_MARSHALL_UNPACK_VALUE_HPP
#define MARSHALLING_MARSHALL_UNPACK_VALUE_HPP

#include <algorithm>
#include <iterator>
#include <type_traits>

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>

#include <boost/array.hpp>

#include <boost/spirit/home/support/container.hpp>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/type_traits.hpp>
#include <nil/marshalling/inference.hpp>
#include <nil/detail/type_traits.hpp>

namespace nil {
    namespace marshalling {
        namespace detail {

            template<typename T, typename Input>
            typename std::enable_if<std::is_same<T, bool>::value, size_t>::type get_length(Input in) {
                return in.bit_length();
            }

            template<typename T, typename Input>
            typename std::enable_if<!std::is_same<T, bool>::value, size_t>::type get_length(Input in) {
                return in.length();
            }

            template<typename TInput>
            struct value_unpack_impl {
                status_type *status;
                TInput input;

                value_unpack_impl(const TInput &input, status_type &status) {
                    this->input = input;
                    this->status = &status;
                }

                template<typename Array,
                         typename = typename std::enable_if<!std::is_constructible<
                             Array,
                             typename std::vector<typename Array::value_type>::iterator,
                             typename std::vector<typename Array::value_type>::iterator>::value>::type>
                inline operator Array() {
                    Array result;
                    typename Array::iterator buffer_begin = result.begin();
                    *status = input.write(buffer_begin, result.size());

                    return result;
                }

                template<typename OutputRange,
                         typename = typename std::enable_if<std::is_constructible<
                             OutputRange,
                             typename std::vector<typename OutputRange::value_type>::iterator,
                             typename std::vector<typename OutputRange::value_type>::iterator>::value>::type>
                inline operator OutputRange() const {
                    using T = typename OutputRange::value_type;
                    std::vector<T> result(get_length<T>(input));
                    typename std::vector<T>::iterator buffer_begin = result.begin();
                    *status = input.write(buffer_begin, result.size());

                    return OutputRange(result.begin(), result.end());
                }
            };

            template<typename TEndian, typename Iter>
            struct range_unpack_impl {
                status_type *status;
                mutable Iter iterator;
                size_t count_elements;
                using value_type = typename std::iterator_traits<Iter>::value_type;

                template<typename SinglePassRange>
                range_unpack_impl(const SinglePassRange &range, status_type &status) {
                    iterator = range.begin();
                    count_elements = std::distance(range.begin(), range.end());
                    this->status = &status;
                }

                template<typename InputIterator>
                range_unpack_impl(InputIterator first, InputIterator last, status_type &status) {
                    iterator = first;
                    count_elements = std::distance(first, last);
                    this->status = &status;
                }

                template<typename InputIterator>
                range_unpack_impl(const InputIterator &iter, size_t len, status_type &status) {
                    iterator = iter;
                    count_elements = len;
                    this->status = &status;
                }

                template<
                    typename OutputRange,
                    typename = typename std::enable_if<
                        std::is_constructible<OutputRange,
                                              typename std::vector<typename OutputRange::value_type>::iterator,
                                              typename std::vector<typename OutputRange::value_type>::iterator>::value
                        && (std::is_same<typename OutputRange::value_type, bool>::value
                            || std::is_same<typename OutputRange::value_type, std::uint8_t>::value)>::type>
                inline operator OutputRange() {
                    using Toutput = typename OutputRange::value_type;

                    using marshalling_type = typename is_compatible<std::vector<value_type>>::template type<TEndian>;
                    using marshalling_internal_type = typename marshalling_type::element_type;

                    //                using marshalling_vector = typename
                    //                std::conditional<marshalling::is_compatible<Input>::fixed_size,
                    //                nil::marshalling::container::static_vector<marshalling_internal_type,
                    //                marshalling_type::max_length()>, std::vector<marshalling_internal_type>>::type;
                    using marshalling_vector = std::vector<marshalling_internal_type>;
                    marshalling_vector values;

                    auto k = iterator;
                    for (std::size_t i = 0; i < count_elements; ++i, ++k) {
                        values.emplace_back(*k);
                    }

                    marshalling_type m_val = marshalling_type(values);
                    std::vector<Toutput> result(get_length<Toutput>(m_val));
                    typename std::vector<Toutput>::iterator buffer_begin = result.begin();
                    *status = m_val.write(buffer_begin, result.size());

                    return OutputRange(result.begin(), result.end());
                }

                template<typename Array,
                         typename = typename std::enable_if<!std::is_constructible<
                             Array,
                             typename std::vector<typename Array::value_type>::iterator,
                             typename std::vector<typename Array::value_type>::iterator>::value>::type,
                         typename = typename std::enable_if<
                             (std::is_same<typename Array::value_type, bool>::value
                              || std::is_same<typename Array::value_type, std::uint8_t>::value)>::type>
                inline operator Array() {
                    using marshalling_type = typename is_compatible<std::vector<value_type>>::template type<TEndian>;
                    using marshalling_internal_type = typename marshalling_type::element_type;

                    //                using marshalling_vector = typename
                    //                std::conditional<marshalling::is_compatible<Input>::fixed_size,
                    //                nil::marshalling::container::static_vector<marshalling_internal_type,
                    //                marshalling_type::max_length()>, std::vector<marshalling_internal_type>>::type;
                    using marshalling_vector = std::vector<marshalling_internal_type>;
                    marshalling_vector values;
                    auto k = iterator;
                    for (std::size_t i = 0; i < count_elements; ++i, ++k) {
                        values.emplace_back(*k);
                    }
                    marshalling_type m_val = marshalling_type(values);
                    Array result;
                    typename Array::iterator buffer_begin = result.begin();
                    *status = m_val.write(buffer_begin, result.size());

                    return result;
                }
            };
        }    // namespace detail
    }        // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_MARSHALL_UNPACK_VALUE_HPP
