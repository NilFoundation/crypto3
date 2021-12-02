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
#include <boost/array.hpp>

#include <boost/spirit/home/support/container.hpp>

#include <nil/marshalling/type_traits.hpp>
#include <nil/marshalling/inference.hpp>
#include <nil/detail/type_traits.hpp>

namespace nil {
    namespace marshalling {

        template <typename TInputEndian, typename TOutputEndian, typename Iter>
        struct range_repack_impl {
            status_type *status;
            mutable Iter iterator;
            size_t count_elements;

            template <typename SinglePassRange>
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

            template<typename T>
            inline operator T() {
                status_type result_status_unpack, result_status_pack;

                std::vector<std::uint8_t> buffer = unpack<TInputEndian>(iterator, count_elements, result_status_unpack);
                T result = pack<TOutputEndian>(buffer, result_status_pack);
                *status = result_status_pack | result_status_unpack;

                return result;
            }
        };

    }    // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_MARSHALL_REPACK_VALUE_HPP
