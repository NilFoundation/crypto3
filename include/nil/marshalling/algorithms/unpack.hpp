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
#include <nil/marshalling/algorithms/unpack_value.hpp>
#include <nil/detail/type_traits.hpp>

namespace nil {
    namespace marshalling {
        template<typename TInput, typename = typename std::enable_if<marshalling::is_marshalling_type<TInput>::value>::type>
        value_unpack_impl<TInput> unpack(const TInput &input, status_type &status) {

            return value_unpack_impl<TInput>(input, status);
        }

        template<typename TEndian, typename TInput, typename = typename std::enable_if<is_compatible<TInput>::value>::type,
            typename = typename std::enable_if<!nil::marshalling::is_container<typename is_compatible<TInput>::template type<>>::value>::type>
        value_unpack_impl<TInput> unpack(const TInput &input, status_type &status) {

            return value_unpack_impl<TInput>(typename is_compatible<TInput>::template type<TEndian>(input), status);
        }

        template<typename TEndian, typename SinglePassRange>
        range_unpack_impl<TEndian, typename SinglePassRange::const_iterator> unpack(const SinglePassRange &r, status_type &status) {

            return range_unpack_impl<TEndian, typename SinglePassRange::const_iterator>(r, status);
        }

        template<typename TEndian, typename SinglePassIterator>
        range_unpack_impl<TEndian, SinglePassIterator> unpack(const SinglePassIterator &r, size_t len, status_type &status) {

            return range_unpack_impl<TEndian, SinglePassIterator>(r, len, status);
        }

        template<typename TEndian, typename InputIterator>
        range_unpack_impl<TEndian, InputIterator> unpack(InputIterator first, InputIterator last, status_type &status) {

            return range_unpack_impl<TEndian, InputIterator>(first, last, status);
        }

    }    // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_MARSHALL_UNPACK_NEW_HPP
