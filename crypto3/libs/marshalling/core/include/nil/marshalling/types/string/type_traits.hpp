//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef MARSHALLING_BASIC_STRING_TYPE_TRAITS_HPP
#define MARSHALLING_BASIC_STRING_TYPE_TRAITS_HPP

#include <type_traits>
#include <algorithm>
#include <limits>
#include <numeric>

#include <nil/marshalling/type_traits.hpp>
#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/processing/access.hpp>
#include <nil/marshalling/container/static_string.hpp>

#include <nil/marshalling/types/detail/common_funcs.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace detail {

                template<typename TStorage>
                struct string_max_length_retrieve_helper {
                    static const std::size_t value = common_funcs::max_supported_length();
                };

                template<std::size_t TSize>
                struct string_max_length_retrieve_helper<nil::marshalling::container::static_string<TSize>> {
                    static const std::size_t value = TSize - 1;
                };

                template<typename T>
                class string_has_assign {
                protected:
                    typedef char Yes;
                    typedef unsigned No;

                    template<typename U, U>
                    struct ReallyHas;

                    template<typename C>
                    static Yes
                        test(ReallyHas<C &(C::*)(typename C::const_pointer, typename C::size_type), &C::assign> *);

                    template<typename C>
                    static Yes test(
                        ReallyHas<void (C::*)(typename C::const_pointer, typename C::size_type), &C::assign> *);

                    template<typename>
                    static No test(...);

                public:
                    static const bool value = (sizeof(test<T>(0)) == sizeof(Yes));
                };

                template<typename T>
                class string_has_push_back {
                protected:
                    typedef char Yes;
                    typedef unsigned No;

                    template<typename U, U>
                    struct ReallyHas;

                    template<typename C>
                    static Yes test(ReallyHas<void (C::*)(char), &C::push_back> *);

                    template<typename>
                    static No test(...);

                public:
                    static const bool value = (sizeof(test<T>(0)) == sizeof(Yes));
                };

            }    // namespace detail
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_BASIC_STRING_TYPE_TRAITS_HPP
