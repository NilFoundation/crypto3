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

        template <typename TEndian, typename TInput>
        struct value_unpack_impl {
            status_type *status;
            TInput input;
            size_t count_elements;

            value_unpack_impl(const TInput &input, status_type &status) {
                this->input = input;
                this->status = &status;
            }

            inline operator std::vector<std::uint8_t>() {
                using marshalling_type = typename is_compatible<TInput>::template type<TEndian>;

                marshalling_type m_val = marshalling_type(input);
                std::vector<std::uint8_t> result(m_val.length());
                typename std::vector<std::uint8_t>::iterator buffer_begin = result.begin();
                status = m_val.write(buffer_begin, result.size());

                return result;
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

            inline operator std::vector<std::uint8_t>() {
                using marshalling_type = typename is_compatible<std::vector<std::uint16_t>>::template type<TEndian>;
                using marshalling_internal_type = typename marshalling_type::element_type;

                std::vector<marshalling_internal_type> values;

                auto k = iterator;
                for (int i = 0; i < count_elements; ++i, ++k) {
                    values.emplace_back(*k);
                }

                marshalling_type m_val = marshalling_type(values);
                std::vector<std::uint8_t> result(m_val.length());
                typename std::vector<std::uint8_t>::iterator buffer_begin = result.begin();
                *status = m_val.write(buffer_begin, result.size());

                return result;
            }
        };

//        template <typename TEndian, typename Iter, typename OutputIterator>
//        struct itr_unpack_impl {
//            mutable Iter iterator;
//            size_t count_elements;
//            OutputIterator out_iterator;
//            using value_type = typename std::iterator_traits<Iter>::value_type;
//
//            template<typename SinglePassRange>
//            itr_unpack_impl(const SinglePassRange &range, OutputIterator out, status_type &status) {
//                out_iterator = out;
//                iterator = range.begin();
//                count_elements = std::distance(range.begin(), range.end());
//            }
//
//            template<typename InputIterator>
//            itr_unpack_impl(InputIterator first, InputIterator last, OutputIterator out, status_type &status) {
//                InputIterator first_save = first;
//                iterator = first_save;
//                count_elements = std::distance(first, last);
//            }
//
//            inline operator OutputIterator() const {
//                using marshalling_type = typename is_compatible<OutputIterator>::template type<TEndian>;
//
//                marshalling_type m_val;
//
//                m_val.read(iterator, count_elements);
//                auto values = m_val.value();
//
//                return std::move(values.cbegin(), values.cend(), out_iterator);
//            }
//        };

    }    // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_MARSHALL_UNPACK_VALUE_HPP
