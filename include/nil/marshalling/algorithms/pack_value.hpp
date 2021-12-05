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

#ifndef MARSHALLING_MARSHALL_PACK_VALUE_HPP
#define MARSHALLING_MARSHALL_PACK_VALUE_HPP

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

        template<typename TEndian, typename Iter>
        struct range_pack_impl {
            status_type *status;
            mutable Iter iterator;
            size_t count_elements;

            template<typename SinglePassRange>
            range_pack_impl(const SinglePassRange &range, status_type &status) {
                iterator = range.begin();
                count_elements = std::distance(range.begin(), range.end());
                this->status = &status;
            }

            template<typename InputIterator>
            range_pack_impl(InputIterator first, InputIterator last, status_type &status) {
                iterator = first;
                count_elements = std::distance(first, last);
                this->status = &status;
            }

            template<typename T, typename = typename std::enable_if<!nil::marshalling::is_container<
                                     typename is_compatible<T>::template type<>>::value>::type>
            inline operator std::vector<T>() {
                using marshalling_type = typename is_compatible<std::vector<T>>::template type<TEndian>;

                marshalling_type m_val;

                *status = m_val.read(iterator, count_elements);

                std::vector<T> result;
                for (const auto &val_i : m_val.value()) {
                    result.push_back(val_i.value());
                }
                return result;
            }

            template<typename T, size_t SizeArray,
                     typename = typename std::enable_if<
                         !nil::marshalling::is_container<typename is_compatible<T>::template type<>>::value>::type>
            inline operator std::array<T, SizeArray>() {

                using marshalling_type = typename is_compatible<std::array<T, SizeArray>>::template type<TEndian>;

                marshalling_type m_val;

                *status = m_val.read(iterator, count_elements);
                auto values = m_val.value();

                std::array<T, SizeArray> result;
                for (std::size_t i = 0; i < values.size(); i++) {
                    result[i] = values[i].value();
                }
                return result;
            }

            template<typename TMarshallingOutnput,
                     typename
                     = typename std::enable_if<marshalling::is_marshalling_type<TMarshallingOutnput>::value>::type>
            inline operator TMarshallingOutnput() const {

                TMarshallingOutnput result;
                *status = result.read(iterator, count_elements);

                return result;
            }

            template<typename TOutput, typename = typename std::enable_if<is_compatible<TOutput>::value>::type,
                     typename = typename std::enable_if<!nil::marshalling::is_container<
                         typename is_compatible<TOutput>::template type<>>::value>::type>
            inline operator TOutput() const {
                using marshalling_type = typename is_compatible<TOutput>::template type<TEndian>;

                TOutput x;

                marshalling_type m_val;

                *status = m_val.read(iterator, count_elements);

                return TOutput(m_val.value());
            }

            template<typename OutputRange, typename = typename std::enable_if<is_compatible<OutputRange>::value>::value,
                     typename = typename std::enable_if<is_compatible<OutputRange>::value>::type,
                     typename = typename std::enable_if<!nil::marshalling::is_container<
                         typename is_compatible<OutputRange>::template type<>>::value>::type>
            inline operator OutputRange() const {
                using marshalling_type = typename is_compatible<OutputRange>::template type<TEndian>;

                marshalling_type m_val;

                *status = m_val.read(iterator, count_elements);

                return OutputRange(m_val.value().begin(), m_val.value().end());
            }
        };

        template<typename TEndian, typename Iter, typename OutputIterator>
        struct itr_pack_impl {
            mutable Iter iterator;
            size_t count_elements;
            OutputIterator out_iterator;
            using value_type = typename std::iterator_traits<Iter>::value_type;

            template<typename SinglePassRange>
            itr_pack_impl(const SinglePassRange &range, OutputIterator out, status_type &status) {
                out_iterator = out;
                iterator = range.begin();
                count_elements = std::distance(range.begin(), range.end());
            }

            template<typename InputIterator>
            itr_pack_impl(InputIterator first, InputIterator last, OutputIterator out, status_type &status) {
                InputIterator first_save = first;
                iterator = first_save;
                count_elements = std::distance(first, last);
            }

            inline operator OutputIterator() const {
                using marshalling_type = typename is_compatible<OutputIterator>::template type<TEndian>;

                marshalling_type m_val;

                m_val.read(iterator, count_elements);
                auto values = m_val.value();

                return std::move(values.cbegin(), values.cend(), out_iterator);
            }
        };

    }    // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_MARSHALL_PACK_VALUE_HPP
