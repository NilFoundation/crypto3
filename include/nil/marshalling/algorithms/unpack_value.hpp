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

#include <boost/range/concepts.hpp>
#include <boost/array.hpp>

#include <boost/spirit/home/support/container.hpp>

#include <nil/marshalling/type_traits.hpp>
#include <nil/marshalling/inference.hpp>
#include <nil/detail/type_traits.hpp>

namespace nil {
    namespace marshalling {

        template <typename TInput>
        struct value_unpack_impl {
            status_type *status;
            TInput input;

            value_unpack_impl(const TInput &input, status_type &status) {
                this->input = input;
                this->status = &status;
            }

            template <typename T, typename = typename std::enable_if<std::is_same<T, bool>::value || std::is_same<T, std::uint8_t>::value>::type>
            inline operator std::vector<T>() {
                std::vector<T> result(input.length());
                typename std::vector<T>::iterator buffer_begin = result.begin();
                *status = input.write(buffer_begin, result.size());

                return result;
            }

            template <typename T, size_t ArraySize, typename = typename std::enable_if<std::is_same<T, bool>::value || std::is_same<T, std::uint8_t>::value>::type>
            inline operator std::array<T, ArraySize>() {
                BOOST_STATIC_ASSERT(ArraySize == input.length());
                std::array<T, ArraySize> result;
                typename std::array<T, ArraySize>::iterator buffer_begin = result.begin();
                *status = input.write(buffer_begin, result.size());

                return result;
            }

            template<typename OutputRange>
            inline operator OutputRange() const {
                std::vector<typename OutputRange::value_type> result(input.length());
                typename std::vector<std::uint8_t>::iterator buffer_begin = result.begin();
                *status = input.write(buffer_begin, result.size());

                return OutputRange(result.begin(), result.end());
            }
        };

        template <typename TEndian, typename Iter>
        struct range_unpack_impl {
            status_type *status;
            mutable Iter iterator;
            size_t count_elements;

            template <typename SinglePassRange>
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

            template <typename SinglePassIterator>
            range_unpack_impl(const SinglePassIterator &iter, size_t len, status_type &status) {
                iterator = iter;
                count_elements = len;
                this->status = &status;
            }

            template <typename T, typename = typename std::enable_if<std::is_same<T, bool>::value || std::is_same<T, std::uint8_t>::value>::type>
            inline operator std::vector<T>() {
                using marshalling_type = typename is_compatible<std::vector<typename Iter::value_type>>::template type<TEndian>;
                using marshalling_internal_type = typename marshalling_type::element_type;

                std::vector<marshalling_internal_type> values;

                auto k = iterator;
                for (int i = 0; i < count_elements; ++i, ++k) {
                    values.emplace_back(*k);
                }

                marshalling_type m_val = marshalling_type(values);
                std::vector<T> result(m_val.length());
                typename std::vector<T>::iterator buffer_begin = result.begin();
                *status = m_val.write(buffer_begin, result.size());

                return result;
            }

            template <typename T, size_t ArraySize, typename = typename std::enable_if<std::is_same<T, bool>::value || std::is_same<T, std::uint8_t>::value>::type>
            inline operator std::array<T, ArraySize>() {
                using marshalling_type = typename is_compatible<std::array<T, ArraySize>>::template type<TEndian>;
                using marshalling_internal_type = typename marshalling_type::element_type;

                nil::marshalling::container::static_vector<marshalling_internal_type, marshalling_type::max_length()>
                    values;
                auto k = iterator;
                for (int i = 0; i < count_elements; ++i, ++k) {
                    values.emplace_back(*k);
                }
                marshalling_type m_val = marshalling_type(values);
                std::array<T, ArraySize> result(m_val.length());
                typename std::array<T, ArraySize>::iterator buffer_begin = result.begin();
                *status = m_val.write(buffer_begin, result.size());

                return result;
            }
        };
    }    // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_MARSHALL_UNPACK_VALUE_HPP
