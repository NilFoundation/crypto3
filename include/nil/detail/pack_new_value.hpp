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

#ifndef MARSHALLING_MARSHALL_PACK_NEW_VALUE_HPP
#define MARSHALLING_MARSHALL_PACK_NEW_VALUE_HPP

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
    namespace detail {

        template<typename TEndian, typename Iter, typename OutputIterator>
        struct itr_unpack_impl {
            marshalling::status_type *status;
            mutable Iter iterator;
            size_t count_elements;
            mutable OutputIterator out_iterator;
            using value_type = typename std::iterator_traits<Iter>::value_type;
            using output_value_type = typename std::iterator_traits<OutputIterator>::value_type;

            template<typename SinglePassRange>
            itr_unpack_impl(const SinglePassRange &range, OutputIterator out, marshalling::status_type &status) {
                out_iterator = out;
                iterator = range.begin();
                count_elements = std::distance(range.begin(), range.end());
                this->status = &status;
            }

            template<typename InputIterator>
            itr_unpack_impl(InputIterator first, InputIterator last, OutputIterator out,
                            marshalling::status_type &status) {
                iterator = first;
                out_iterator = out;
                count_elements = std::distance(first, last);
                this->status = &status;
            }

            template<typename SinglePassIterator>
            itr_unpack_impl(const SinglePassIterator &iter, size_t len, OutputIterator out,
                            marshalling::status_type &status) {
                iterator = iter;
                out_iterator = out;
                count_elements = len;
                this->status = &status;
            }

            template <typename = typename std::enable_if<nil::marshalling::is_supported_representation_type<output_value_type>::value>::type>
            inline operator OutputIterator() const {

                using marshalling_type = typename marshalling::is_compatible<std::vector<value_type>>::template type<TEndian>;
                using marshalling_internal_type = typename marshalling_type::element_type;

                std::vector<marshalling_internal_type> values;
                auto k = iterator;
                for (int i = 0; i < count_elements; ++i, ++k) {
                    values.emplace_back(*k);
                }
                marshalling_type m_val = marshalling_type(values);
                std::vector<output_value_type> result(get_length<output_value_type>(m_val));
                typename std::vector<output_value_type>::iterator buffer_begin = result.begin();

                *status = m_val.write(buffer_begin, result.size());
                return std::move(result.cbegin(), result.cend(), out_iterator);
            }

            template <typename = typename std::enable_if<!nil::marshalling::is_supported_representation_type<output_value_type>::value>::type,
                     typename = typename std::enable_if<nil::marshalling::is_supported_representation_type<value_type>::value>::type,
                bool Enable = true>
            inline operator OutputIterator() const {
                using marshalling_type = typename marshalling::is_compatible<std::vector<output_value_type>>::template type<TEndian>;
                marshalling_type m_val;

                *status = m_val.read(iterator, count_elements);
                std::vector<output_value_type> result;
                for (const auto &val_i : m_val.value()) {
                    result.push_back(val_i.value());
                }

                return std::move(result.cbegin(), result.cend(), out_iterator);
            }

            template <typename = typename std::enable_if<!nil::marshalling::is_supported_representation_type<output_value_type>::value>::type,
                     typename = typename std::enable_if<!nil::marshalling::is_supported_representation_type<value_type>::value>::type,
                     bool Enable1 = true, bool Enable2 = true>
            inline operator OutputIterator() const {
                using marshalling_type = typename marshalling::is_compatible<std::vector<output_value_type>>::template type<TEndian>;
                marshalling_type m_val;

                *status = m_val.read(iterator, count_elements);
                std::vector<output_value_type> result;
                for (const auto &val_i : m_val.value()) {
                    result.push_back(val_i.value());
                }

                return std::move(result.cbegin(), result.cend(), out_iterator);
            }
        };


    }    // namespace detail
}    // namespace nil

#endif    // MARSHALLING_MARSHALL_PACK_NEW_VALUE_HPP
